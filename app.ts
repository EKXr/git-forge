// git-forge: a GitHub-compatible git forge in one process, Node standard library only.
//
// Surfaces:
//   - git smart HTTP at /{owner}/{repo}.git (upload-pack protocol v2 + v0, receive-pack v0),
//     with the git object model (blob/tree/commit/tag), packfiles and shallow support
//     implemented here on node:crypto (SHA-1) and node:zlib — no git binary.
//   - REST v3 under /api/v3: repositories, branches, commits, contents, labels, issues,
//     comments, pull requests, files and squash/merge.
//   - GraphQL v4 at /api/graphql: the documents gh and github-mcp-server send, with
//     introspection for the types they probe and Relay global ids.
//   - MCP at /mcp: streamable-HTTP JSON-RPC, revision 2026-07-28 (server/discover) plus the
//     legacy initialize handshake, with tools acting on the same store as REST.
//
// Everything lives in memory in this process; a repository created on one surface is the
// same object on every other surface.

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { createHash } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';

// ---------------------------------------------------------------------------
// small utilities

const JSON_TYPE = 'application/json; charset=utf-8';
const ZERO_OID = '0'.repeat(40);
const TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';
let requestCounter = 0;

function sha1Hex(data: Buffer): string {
  return createHash('sha1').update(data).digest('hex');
}

function nowIso(): string {
  return new Date().toISOString();
}

function nowSec(): number {
  return Math.floor(Date.now() / 1000);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function str(value: unknown, fallback = ''): string {
  return typeof value === 'string' ? value : fallback;
}

function num(value: unknown, fallback = 0): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback;
}

// ---------------------------------------------------------------------------
// the store

type GitObjectType = 'blob' | 'tree' | 'commit' | 'tag';

interface GitObject {
  type: GitObjectType;
  data: Buffer;
}

interface Label {
  id: number;
  name: string;
  color: string;
  description: string;
}

interface IssueComment {
  id: number;
  body: string;
  seq: number;
}

interface Issue {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: string[];
  comments: IssueComment[];
  seq: number;
}

interface Pull {
  id: number;
  number: number;
  title: string;
  body: string;
  head: string;
  base: string;
  state: 'open' | 'closed';
  merged: boolean;
  mergedAt: string | null;
  mergeCommitSha: string | null;
  seq: number;
}

interface Repo {
  id: number;
  name: string;
  owner: string | null;
  isPrivate: boolean;
  description: string;
  defaultBranch: string;
  objects: Map<string, GitObject>;
  refs: Map<string, string>;
  labels: Map<string, Label>;
  issues: Map<number, Issue>;
  pulls: Map<number, Pull>;
  nextNumber: number;
  seq: number;
}

const reposByName = new Map<string, Repo>();
const reposById = new Map<number, Repo>();
let nextRepoId = 100001;
let nextIssueId = 200001;
let nextCommentId = 300001;
let nextLabelId = 400001;
let globalSeq = 0;
/** The login the bearer token owns, learned from the first owner-bearing request. */
let viewerLogin: string | null = null;

function learnViewer(owner: string | null | undefined): void {
  if (owner && viewerLogin === null) viewerLogin = owner;
}

function viewer(): string {
  return viewerLogin ?? 'forge-user';
}

function createRepoRecord(name: string, isPrivate: boolean, description: string, defaultBranch: string): Repo {
  const repo: Repo = {
    id: nextRepoId++,
    name,
    owner: viewerLogin,
    isPrivate,
    description,
    defaultBranch: defaultBranch || 'main',
    objects: new Map(),
    refs: new Map(),
    labels: new Map(),
    issues: new Map(),
    pulls: new Map(),
    nextNumber: 1,
    seq: globalSeq++,
  };
  reposByName.set(name.toLowerCase(), repo);
  reposById.set(repo.id, repo);
  return repo;
}

/** Find a repo by name for `owner`, claiming it for that owner when unclaimed. */
function findRepo(owner: string, name: string): Repo | null {
  learnViewer(owner);
  const repo = reposByName.get(name.toLowerCase());
  if (!repo) return null;
  if (repo.owner === null) repo.owner = owner;
  if (repo.owner !== owner) return null;
  return repo;
}

function findRepoByNameOnly(name: string): Repo | null {
  return reposByName.get(name.toLowerCase()) ?? null;
}

// ---------------------------------------------------------------------------
// git object model

const TYPE_CODE: Record<GitObjectType, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const CODE_TYPE: Record<number, GitObjectType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

function hashObject(type: GitObjectType, data: Buffer): string {
  const header = Buffer.from(`${type} ${data.length}\0`, 'utf8');
  return sha1Hex(Buffer.concat([header, data]));
}

function storeObject(repo: Repo, type: GitObjectType, data: Buffer): string {
  const oid = hashObject(type, data);
  if (!repo.objects.has(oid)) repo.objects.set(oid, { type, data });
  return oid;
}

interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}

function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let offset = 0;
  while (offset < data.length) {
    const space = data.indexOf(0x20, offset);
    const nul = data.indexOf(0x00, space);
    const mode = data.subarray(offset, space).toString('utf8');
    const name = data.subarray(space + 1, nul).toString('utf8');
    const oid = data.subarray(nul + 1, nul + 21).toString('hex');
    entries.push({ mode, name, oid });
    offset = nul + 21;
  }
  return entries;
}

function treeSortKey(entry: TreeEntry): string {
  return entry.mode === '40000' || entry.mode === '040000' ? `${entry.name}/` : entry.name;
}

function buildTreeData(entries: TreeEntry[]): Buffer {
  const sorted = [...entries].sort((a, b) => (treeSortKey(a) < treeSortKey(b) ? -1 : treeSortKey(a) > treeSortKey(b) ? 1 : 0));
  const parts: Buffer[] = [];
  for (const entry of sorted) {
    parts.push(Buffer.from(`${entry.mode} ${entry.name}\0`, 'utf8'));
    parts.push(Buffer.from(entry.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

interface CommitView {
  tree: string;
  parents: string[];
  message: string;
  authorLine: string;
  committerLine: string;
}

function parseCommit(data: Buffer): CommitView {
  const text = data.toString('utf8');
  const split = text.indexOf('\n\n');
  const head = split === -1 ? text : text.slice(0, split);
  const message = split === -1 ? '' : text.slice(split + 2);
  let tree = '';
  const parents: string[] = [];
  let authorLine = '';
  let committerLine = '';
  for (const line of head.split('\n')) {
    if (line.startsWith('tree ')) tree = line.slice(5).trim();
    else if (line.startsWith('parent ')) parents.push(line.slice(7).trim());
    else if (line.startsWith('author ')) authorLine = line.slice(7);
    else if (line.startsWith('committer ')) committerLine = line.slice(10);
  }
  return { tree, parents, message, authorLine, committerLine };
}

function parseIdent(line: string): { name: string; email: string; date: string } {
  const match = /^(.*?) <(.*?)> (\d+) ([+-]\d{4})$/.exec(line);
  if (!match) return { name: line || 'Forge', email: 'forge@example.invalid', date: new Date(0).toISOString() };
  return { name: match[1], email: match[2], date: new Date(Number(match[3]) * 1000).toISOString() };
}

function buildCommitData(tree: string, parents: string[], message: string, ident: string, timestamp: number): Buffer {
  const lines = [`tree ${tree}`];
  for (const parent of parents) lines.push(`parent ${parent}`);
  lines.push(`author ${ident} ${timestamp} +0000`);
  lines.push(`committer ${ident} ${timestamp} +0000`);
  return Buffer.from(`${lines.join('\n')}\n\n${message}`, 'utf8');
}

function parseTag(data: Buffer): { object: string; type: string; tag: string } {
  const text = data.toString('utf8');
  let object = '';
  let type = '';
  let tag = '';
  for (const line of text.split('\n')) {
    if (line.startsWith('object ')) object = line.slice(7).trim();
    else if (line.startsWith('type ')) type = line.slice(5).trim();
    else if (line.startsWith('tag ')) tag = line.slice(4).trim();
    else if (line === '') break;
  }
  return { object, type, tag };
}

/** Peel a tag chain to the commit it names (or return the oid itself). */
function peelToCommit(repo: Repo, oid: string): string {
  let current = oid;
  for (let guard = 0; guard < 32; guard += 1) {
    const object = repo.objects.get(current);
    if (!object || object.type !== 'tag') return current;
    current = parseTag(object.data).object;
  }
  return current;
}

/** Flatten a tree (recursively) into path -> {oid, mode}. */
function flattenTree(repo: Repo, treeOid: string, prefix = '', out = new Map<string, { oid: string; mode: string }>()): Map<string, { oid: string; mode: string }> {
  const object = repo.objects.get(treeOid);
  if (!object || object.type !== 'tree') return out;
  for (const entry of parseTree(object.data)) {
    const path = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.mode === '40000' || entry.mode === '040000') flattenTree(repo, entry.oid, path, out);
    else out.set(path, { oid: entry.oid, mode: entry.mode });
  }
  return out;
}

/** Build (and store) a tree from a flat path -> {oid, mode} map; returns its oid. */
function buildTreeFromFlat(repo: Repo, flat: Map<string, { oid: string; mode: string }>): string {
  interface Node {
    files: Map<string, { oid: string; mode: string }>;
    dirs: Map<string, Node>;
  }
  const make = (): Node => ({ files: new Map(), dirs: new Map() });
  const root = make();
  for (const [path, value] of flat) {
    const segments = path.split('/');
    let node = root;
    for (let i = 0; i < segments.length - 1; i += 1) {
      if (!node.dirs.has(segments[i])) node.dirs.set(segments[i], make());
      node = node.dirs.get(segments[i])!;
    }
    node.files.set(segments[segments.length - 1], value);
  }
  const build = (node: Node): string => {
    const entries: TreeEntry[] = [];
    for (const [name, value] of node.files) entries.push({ mode: value.mode, name, oid: value.oid });
    for (const [name, child] of node.dirs) entries.push({ mode: '40000', name, oid: build(child) });
    return storeObject(repo, 'tree', buildTreeData(entries));
  };
  return build(root);
}

/** All ancestors of a commit (including itself) with shortest distance, via parent links. */
function commitAncestors(repo: Repo, tip: string): Map<string, number> {
  const distance = new Map<string, number>();
  const queue: Array<{ oid: string; depth: number }> = [{ oid: peelToCommit(repo, tip), depth: 0 }];
  while (queue.length > 0) {
    const { oid, depth } = queue.shift()!;
    if (distance.has(oid)) continue;
    const object = repo.objects.get(oid);
    if (!object || object.type !== 'commit') continue;
    distance.set(oid, depth);
    for (const parent of parseCommit(object.data).parents) queue.push({ oid: parent, depth: depth + 1 });
  }
  return distance;
}

function isAncestor(repo: Repo, ancestor: string, descendant: string): boolean {
  return commitAncestors(repo, descendant).has(ancestor);
}

function mergeBase(repo: Repo, a: string, b: string): string | null {
  const fromA = commitAncestors(repo, a);
  const fromB = commitAncestors(repo, b);
  let best: string | null = null;
  let bestScore = Number.POSITIVE_INFINITY;
  for (const [oid, depthA] of fromA) {
    const depthB = fromB.get(oid);
    if (depthB !== undefined && depthA + depthB < bestScore) {
      bestScore = depthA + depthB;
      best = oid;
    }
  }
  return best;
}

function commitTreeOid(repo: Repo, commitOid: string): string | null {
  const object = repo.objects.get(peelToCommit(repo, commitOid));
  if (!object || object.type !== 'commit') return null;
  return parseCommit(object.data).tree;
}

/**
 * Three-way merge of two tips against their merge base, at whole-file granularity.
 * Returns the merged tree oid, or null when both sides changed a path differently.
 */
function threeWayMerge(repo: Repo, baseTip: string, headTip: string): string | null {
  const base = mergeBase(repo, baseTip, headTip);
  const baseTree = base ? commitTreeOid(repo, base) : null;
  const oursTree = commitTreeOid(repo, baseTip);
  const theirsTree = commitTreeOid(repo, headTip);
  if (!oursTree || !theirsTree) return null;
  const empty = new Map<string, { oid: string; mode: string }>();
  const baseFlat = baseTree ? flattenTree(repo, baseTree) : empty;
  const oursFlat = flattenTree(repo, oursTree);
  const theirsFlat = flattenTree(repo, theirsTree);
  const merged = new Map<string, { oid: string; mode: string }>();
  const paths = new Set<string>([...baseFlat.keys(), ...oursFlat.keys(), ...theirsFlat.keys()]);
  for (const path of paths) {
    const b = baseFlat.get(path);
    const o = oursFlat.get(path);
    const t = theirsFlat.get(path);
    if (o?.oid === t?.oid && o?.mode === t?.mode) {
      if (o) merged.set(path, o);
    } else if (b?.oid === o?.oid && b?.mode === o?.mode) {
      if (t) merged.set(path, t);
    } else if (b?.oid === t?.oid && b?.mode === t?.mode) {
      if (o) merged.set(path, o);
    } else {
      return null;
    }
  }
  return buildTreeFromFlat(repo, merged);
}

function mergeWouldConflict(repo: Repo, baseTip: string, headTip: string): boolean {
  if (isAncestor(repo, headTip, baseTip)) return false;
  return threeWayMerge(repo, baseTip, headTip) === null;
}

/** Create a commit on a branch ref (used by the contents API and merges). */
function commitOnRef(repo: Repo, ref: string, treeOid: string, message: string): string {
  const parent = repo.refs.get(ref);
  const ident = `${viewer()} <${viewer()}@example.invalid>`;
  const data = buildCommitData(treeOid, parent ? [parent] : [], message, ident, nowSec());
  const oid = storeObject(repo, 'commit', data);
  repo.refs.set(ref, oid);
  return oid;
}

/** Resolve a ref name (branch, tag, HEAD or raw oid) to a commit oid. */
function resolveRef(repo: Repo, ref: string): string | null {
  if (/^[0-9a-f]{40}$/i.test(ref) && repo.objects.has(ref)) return peelToCommit(repo, ref);
  const candidates: string[] = [];
  if (ref === 'HEAD') candidates.push(`refs/heads/${repo.defaultBranch}`);
  candidates.push(ref, `refs/heads/${ref}`, `refs/tags/${ref}`, `refs/${ref}`);
  for (const candidate of candidates) {
    const oid = repo.refs.get(candidate);
    if (oid) return peelToCommit(repo, oid);
  }
  return null;
}

function defaultTip(repo: Repo): string | null {
  return repo.refs.get(`refs/heads/${repo.defaultBranch}`) ?? null;
}

// ---------------------------------------------------------------------------
// packfiles and pkt-lines

function pktLine(payload: string | Buffer): Buffer {
  const body = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const size = body.length + 4;
  const header = Buffer.from(size.toString(16).padStart(4, '0'), 'ascii');
  return Buffer.concat([header, body]);
}
const PKT_FLUSH = Buffer.from('0000', 'ascii');
const PKT_DELIM = Buffer.from('0001', 'ascii');

interface PktPacket {
  kind: 'data' | 'flush' | 'delim' | 'response-end';
  payload: Buffer;
}

/** Split a pkt-line stream; returns the packets and the offset just past the final flush. */
function decodePktLines(buffer: Buffer, start = 0): { packets: PktPacket[]; next: number } {
  const packets: PktPacket[] = [];
  let offset = start;
  while (offset + 4 <= buffer.length) {
    const header = buffer.subarray(offset, offset + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(header)) break;
    const size = parseInt(header, 16);
    if (size === 0) {
      packets.push({ kind: 'flush', payload: Buffer.alloc(0) });
      offset += 4;
      break;
    }
    if (size === 1) {
      packets.push({ kind: 'delim', payload: Buffer.alloc(0) });
      offset += 4;
      continue;
    }
    if (size === 2) {
      packets.push({ kind: 'response-end', payload: Buffer.alloc(0) });
      offset += 4;
      continue;
    }
    if (size < 4 || offset + size > buffer.length) break;
    packets.push({ kind: 'data', payload: buffer.subarray(offset + 4, offset + size) });
    offset += size;
  }
  return { packets, next: offset };
}

function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let offset = 0;
  const readSize = (): number => {
    let value = 0;
    let shift = 0;
    for (;;) {
      const byte = delta[offset++];
      value += (byte & 0x7f) * 2 ** shift;
      shift += 7;
      if (!(byte & 0x80)) break;
    }
    return value;
  };
  const sourceSize = readSize();
  const targetSize = readSize();
  if (sourceSize !== base.length) throw new Error('delta base size mismatch');
  const out = Buffer.alloc(targetSize);
  let written = 0;
  while (offset < delta.length) {
    const op = delta[offset++];
    if (op & 0x80) {
      let copyOffset = 0;
      let copySize = 0;
      let shift = 0;
      for (let bit = 0; bit < 4; bit += 1) {
        if (op & (1 << bit)) copyOffset += delta[offset++] * 2 ** shift;
        shift += 8;
      }
      shift = 0;
      for (let bit = 4; bit < 7; bit += 1) {
        if (op & (1 << bit)) copySize += delta[offset++] * 2 ** shift;
        shift += 8;
      }
      if (copySize === 0) copySize = 0x10000;
      base.copy(out, written, copyOffset, copyOffset + copySize);
      written += copySize;
    } else if (op !== 0) {
      delta.copy(out, written, offset, offset + op);
      offset += op;
      written += op;
    } else {
      throw new Error('delta opcode 0');
    }
  }
  if (written !== targetSize) throw new Error('delta size mismatch');
  return out;
}

function inflateAt(buffer: Buffer, offset: number): { data: Buffer; next: number } {
  const result = inflateSync(buffer.subarray(offset), { info: true }) as unknown as { buffer: Buffer; engine: { bytesWritten: number } };
  return { data: result.buffer, next: offset + result.engine.bytesWritten };
}

/** Parse a packfile's entries into resolved objects. Bases may come from `external` (thin packs). */
function readPackEntries(pack: Buffer, external?: (oid: string) => GitObject | undefined): GitObject[] {
  if (pack.length < 32 || pack.subarray(0, 4).toString('ascii') !== 'PACK') throw new Error('not a packfile');
  const count = pack.readUInt32BE(8);
  const trailerStart = pack.length - 20;
  interface Raw {
    offset: number;
    typeCode: number;
    data: Buffer;
    baseOffset?: number;
    baseOid?: string;
  }
  const raw: Raw[] = [];
  const byOffset = new Map<number, Raw>();
  let offset = 12;
  for (let i = 0; i < count; i += 1) {
    const entryOffset = offset;
    let byte = pack[offset++];
    const typeCode = (byte >> 4) & 0x07;
    let size = byte & 0x0f;
    let shift = 4;
    while (byte & 0x80) {
      byte = pack[offset++];
      size += (byte & 0x7f) * 2 ** shift;
      shift += 7;
    }
    const entry: Raw = { offset: entryOffset, typeCode, data: Buffer.alloc(0) };
    if (typeCode === 6) {
      let b = pack[offset++];
      let value = b & 0x7f;
      while (b & 0x80) {
        b = pack[offset++];
        value = (value + 1) * 128 + (b & 0x7f);
      }
      entry.baseOffset = entryOffset - value;
    } else if (typeCode === 7) {
      entry.baseOid = pack.subarray(offset, offset + 20).toString('hex');
      offset += 20;
    }
    const inflated = inflateAt(pack.subarray(0, trailerStart), offset);
    if (inflated.data.length !== size) throw new Error('pack entry size mismatch');
    entry.data = inflated.data;
    offset = inflated.next;
    raw.push(entry);
    byOffset.set(entryOffset, entry);
  }
  const resolvedByOid = new Map<string, GitObject>();
  const resolve = (entry: Raw): GitObject => {
    if (entry.typeCode === 6 || entry.typeCode === 7) {
      let base: GitObject | undefined;
      if (entry.typeCode === 6) {
        const baseEntry = byOffset.get(entry.baseOffset!);
        if (!baseEntry) throw new Error('ofs-delta base missing');
        base = resolve(baseEntry);
      } else {
        base = resolvedByOid.get(entry.baseOid!) ?? external?.(entry.baseOid!);
        if (!base) throw new Error('ref-delta base missing');
      }
      const object: GitObject = { type: base.type, data: applyDelta(base.data, entry.data) };
      resolvedByOid.set(hashObject(object.type, object.data), object);
      return object;
    }
    const type = CODE_TYPE[entry.typeCode];
    if (!type) throw new Error(`unknown pack type ${entry.typeCode}`);
    const object: GitObject = { type, data: entry.data };
    resolvedByOid.set(hashObject(type, entry.data), object);
    return object;
  };
  return raw.map((entry) => resolve(entry));
}

function packObjectHeader(type: GitObjectType, size: number): Buffer {
  const code = TYPE_CODE[type];
  const bytes: number[] = [];
  let remaining = size;
  let first = (code << 4) | (remaining & 0x0f);
  remaining = Math.floor(remaining / 16);
  while (remaining > 0) {
    bytes.push(first | 0x80);
    first = remaining & 0x7f;
    remaining = Math.floor(remaining / 128);
  }
  bytes.push(first);
  return Buffer.from(bytes);
}

function writePack(objects: Array<{ oid: string; type: GitObjectType; data: Buffer }>): Buffer {
  const parts: Buffer[] = [];
  const header = Buffer.alloc(12);
  header.write('PACK', 0, 4, 'ascii');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(objects.length, 8);
  parts.push(header);
  for (const object of objects) {
    parts.push(packObjectHeader(object.type, object.data.length));
    parts.push(deflateSync(object.data));
  }
  const body = Buffer.concat(parts);
  return Buffer.concat([body, createHash('sha1').update(body).digest()]);
}

/**
 * The objects a fetch must send: reachable from `wants`, minus everything reachable
 * from `haves`, honouring a shallow depth (in commit generations from the wants) and
 * the client's existing shallow boundary.
 */
function computeFetch(repo: Repo, wants: string[], haves: string[], depth: number | null, shallowReq: string[]): { send: GitObject[] & Array<{ oid: string }>; shallow: string[]; unshallow: string[] } {
  const haveClosure = new Set<string>();
  const shallowSet = new Set(shallowReq);
  const markHave = (oid: string): void => {
    const stack = [oid];
    while (stack.length > 0) {
      const current = stack.pop()!;
      if (haveClosure.has(current)) continue;
      const object = repo.objects.get(current);
      if (!object) continue;
      haveClosure.add(current);
      if (object.type === 'commit') {
        const view = parseCommit(object.data);
        // A commit the client lists as its shallow boundary is held, but its parents
        // are not: do not mark them as haves, or a deepen could never reach them.
        if (shallowSet.has(current)) stack.push(view.tree);
        else stack.push(view.tree, ...view.parents);
      } else if (object.type === 'tree') {
        for (const entry of parseTree(object.data)) stack.push(entry.oid);
      } else if (object.type === 'tag') {
        stack.push(parseTag(object.data).object);
      }
    }
  };
  for (const have of haves) markHave(have);

  // BFS from the wants, tracking commit distance (tag->commit keeps the distance).
  const commitDistance = new Map<string, number>();
  const included = new Set<string>();
  const queue: Array<{ oid: string; distance: number }> = [];
  for (const want of wants) queue.push({ oid: want, distance: 0 });
  const seen = new Set<string>();
  while (queue.length > 0) {
    const { oid, distance } = queue.shift()!;
    const object = repo.objects.get(oid);
    if (!object) continue;
    const key = `${oid}@${object.type === 'commit' ? distance : -1}`;
    if (seen.has(key)) continue;
    seen.add(key);
    if (object.type === 'commit') {
      const known = commitDistance.get(oid);
      if (known !== undefined && known <= distance) {
        // already traversed at a shorter distance; still need its tree once
      } else {
        commitDistance.set(oid, distance);
      }
      if (depth !== null && distance >= depth) {
        // beyond the shallow horizon: neither sent nor traversed
        if (distance > (commitDistance.get(oid) ?? distance)) continue;
        if (depth === 0) continue;
        // distance == depth means this commit itself is past the boundary when depth counts
        // generations to include: include commits with distance < depth only.
        continue;
      }
      if (!haveClosure.has(oid)) included.add(oid);
      const view = parseCommit(object.data);
      if (!haveClosure.has(view.tree)) included.add(view.tree);
      queue.push({ oid: view.tree, distance });
      const atBoundary = shallowReq.includes(oid) && depth === null;
      if (!atBoundary) {
        for (const parent of view.parents) queue.push({ oid: parent, distance: distance + 1 });
      }
    } else if (object.type === 'tree') {
      if (!haveClosure.has(oid)) included.add(oid);
      for (const entry of parseTree(object.data)) queue.push({ oid: entry.oid, distance });
    } else if (object.type === 'tag') {
      if (!haveClosure.has(oid)) included.add(oid);
      queue.push({ oid: parseTag(object.data).object, distance });
    } else {
      if (!haveClosure.has(oid)) included.add(oid);
    }
  }
  // Trees/blobs of included commits are queued through their commit; blobs reached via
  // included trees are handled by the tree case above. But a tree in `included` whose
  // entries were queued with a commit distance that later got cut by depth could leak a
  // parent commit: prune any commit whose distance is >= depth.
  if (depth !== null) {
    for (const oid of [...included]) {
      const object = repo.objects.get(oid);
      if (object?.type === 'commit') {
        const d = commitDistance.get(oid);
        if (d === undefined || d >= depth) included.delete(oid);
      }
    }
  }
  const send: Array<{ oid: string; type: GitObjectType; data: Buffer }> = [];
  for (const oid of included) {
    const object = repo.objects.get(oid);
    if (object) send.push({ oid, type: object.type, data: object.data });
  }
  const shallow: string[] = [];
  const shallowMode = depth !== null || shallowReq.length > 0;
  if (shallowMode) {
    for (const item of send) {
      if (item.type !== 'commit') continue;
      const view = parseCommit(item.data);
      if (view.parents.some((parent) => !included.has(parent) && repo.objects.has(parent))) shallow.push(item.oid);
    }
  }
  const unshallow = shallowReq.filter((oid) => !shallow.includes(oid) && (included.has(oid) || haveClosure.has(oid)));
  return { send: send as GitObject[] & Array<{ oid: string }>, shallow, unshallow };
}

// ---------------------------------------------------------------------------
// HTTP plumbing

function sendJson(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  const text = body === undefined ? '' : `${JSON.stringify(body)}\n`;
  res.writeHead(status, {
    'content-type': JSON_TYPE,
    'content-length': Buffer.byteLength(text),
    'x-github-request-id': `req-${++requestCounter}`,
    ...headers,
  });
  res.end(text);
}

function sendRaw(res: ServerResponse, status: number, body: Buffer, contentType: string): void {
  res.writeHead(status, {
    'content-type': contentType,
    'content-length': body.length,
    'x-github-request-id': `req-${++requestCounter}`,
    'cache-control': 'no-cache',
  });
  res.end(body);
}

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function authed(req: IncomingMessage): boolean {
  if (TOKEN === '') return typeof req.headers.authorization === 'string' && req.headers.authorization.length > 0;
  return req.headers.authorization === `Bearer ${TOKEN}`;
}

function baseUrlOf(req: IncomingMessage): string {
  const host = req.headers.host ?? '127.0.0.1';
  return `http://${host}`;
}

// ---------------------------------------------------------------------------
// git smart HTTP

function sortedRefs(repo: Repo): Array<[string, string]> {
  return [...repo.refs.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
}

function peeledOf(repo: Repo, oid: string): string | null {
  const object = repo.objects.get(oid);
  if (!object || object.type !== 'tag') return null;
  return peelToCommit(repo, oid);
}

function v0Advertisement(repo: Repo, service: string): Buffer {
  const parts: Buffer[] = [pktLine(`# service=${service}\n`), PKT_FLUSH];
  const caps =
    service === 'git-receive-pack'
      ? 'report-status delete-refs side-band-64k quiet ofs-delta object-format=sha1 agent=git-forge/1.0'
      : `multi_ack_detailed side-band-64k thin-pack ofs-delta shallow deepen-since deepen-not agent=git-forge/1.0 symref=HEAD:refs/heads/${repo.defaultBranch}`;
  const refs = sortedRefs(repo);
  if (refs.length === 0) {
    parts.push(pktLine(`${ZERO_OID} capabilities^{}\0${caps}\n`));
  } else {
    let first = true;
    const headOid = defaultTip(repo);
    if (headOid) {
      parts.push(pktLine(`${headOid} HEAD\0${caps}\n`));
      first = false;
    }
    for (const [name, oid] of refs) {
      parts.push(pktLine(first ? `${oid} ${name}\0${caps}\n` : `${oid} ${name}\n`));
      first = false;
      const peeled = peeledOf(repo, oid);
      if (peeled) parts.push(pktLine(`${peeled} ${name}^{}\n`));
    }
  }
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}

function v2Advertisement(): Buffer {
  const parts: Buffer[] = [
    pktLine('version 2\n'),
    pktLine('agent=git-forge/1.0\n'),
    pktLine('ls-refs=unborn\n'),
    pktLine('fetch=shallow wait-for-done\n'),
    pktLine('object-format=sha1\n'),
    PKT_FLUSH,
  ];
  return Buffer.concat(parts);
}

function handleInfoRefs(req: IncomingMessage, res: ServerResponse, repo: Repo, url: URL): void {
  const service = url.searchParams.get('service') ?? '';
  if (service !== 'git-upload-pack' && service !== 'git-receive-pack') {
    sendJson(res, 403, { message: 'Forbidden' });
    return;
  }
  const wantsV2 = service === 'git-upload-pack' && (req.headers['git-protocol'] ?? '').includes('version=2');
  if (wantsV2) {
    sendRaw(res, 200, v2Advertisement(), 'application/x-git-upload-pack-advertisement');
    return;
  }
  sendRaw(res, 200, v0Advertisement(repo, service), `application/x-${service}-advertisement`);
}

/** Sideband-frame a pack into pkt-lines of at most 65520 bytes. */
function sidebandPackets(pack: Buffer): Buffer[] {
  const packets: Buffer[] = [];
  // A pkt-line is at most 65520 bytes including its 4-byte header, and the sideband
  // band byte rides inside the payload: at most 65515 pack bytes per packet.
  const CHUNK = 65515;
  for (let offset = 0; offset < pack.length; offset += CHUNK) {
    const slice = pack.subarray(offset, Math.min(pack.length, offset + CHUNK));
    packets.push(pktLine(Buffer.concat([Buffer.from([1]), slice])));
  }
  if (pack.length === 0) packets.push(pktLine(Buffer.concat([Buffer.from([1]), Buffer.alloc(0)])));
  return packets;
}

function lsRefsLines(repo: Repo, args: string[]): Buffer {
  let peel = false;
  let symrefs = false;
  let unborn = false;
  const prefixes: string[] = [];
  for (const arg of args) {
    if (arg === 'peel') peel = true;
    else if (arg === 'symrefs') symrefs = true;
    else if (arg === 'unborn') unborn = true;
    else if (arg.startsWith('ref-prefix ')) prefixes.push(arg.slice('ref-prefix '.length));
  }
  const keep = (name: string): boolean => prefixes.length === 0 || prefixes.some((prefix) => name.startsWith(prefix));
  const lines: Buffer[] = [];
  const headTarget = `refs/heads/${repo.defaultBranch}`;
  const headOid = repo.refs.get(headTarget);
  if (keep('HEAD')) {
    if (headOid) {
      lines.push(pktLine(`${headOid} HEAD${symrefs ? ` symref-target:${headTarget}` : ''}\n`));
    } else if (unborn) {
      lines.push(pktLine(`unborn HEAD${symrefs ? ` symref-target:${headTarget}` : ''}\n`));
    }
  }
  for (const [name, oid] of sortedRefs(repo)) {
    if (!keep(name)) continue;
    let line = `${oid} ${name}`;
    if (peel) {
      const peeled = peeledOf(repo, oid);
      if (peeled) line += ` peeled:${peeled}`;
    }
    lines.push(pktLine(`${line}\n`));
  }
  lines.push(PKT_FLUSH);
  return Buffer.concat(lines);
}

interface FetchArgs {
  wants: string[];
  haves: string[];
  shallow: string[];
  depth: number | null;
}

function fetchPack(repo: Repo, args: FetchArgs): { pack: Buffer; shallow: string[]; unshallow: string[] } {
  const { send, shallow, unshallow } = computeFetch(repo, args.wants, args.haves, args.depth, args.shallow);
  return { pack: writePack(send), shallow, unshallow };
}

function handleUploadPackV2(res: ServerResponse, repo: Repo, body: Buffer): void {
  const { packets } = decodePktLines(body);
  const lines = packets.filter((p) => p.kind === 'data').map((p) => p.payload.toString('utf8').replace(/\n$/, ''));
  const command = lines.find((line) => line.startsWith('command='));
  if (command === 'command=ls-refs') {
    sendRaw(res, 200, lsRefsLines(repo, lines.slice(1)), 'application/x-git-upload-pack-result');
    return;
  }
  if (command === 'command=fetch') {
    const args: FetchArgs = { wants: [], haves: [], shallow: [], depth: null };
    for (const line of lines.slice(1)) {
      if (line.startsWith('want ')) args.wants.push(line.slice(5).trim());
      else if (line.startsWith('have ')) args.haves.push(line.slice(5).trim());
      else if (line.startsWith('shallow ')) args.shallow.push(line.slice(8).trim());
      else if (line.startsWith('deepen ')) args.depth = Number(line.slice(7).trim());
    }
    const { pack, shallow, unshallow } = fetchPack(repo, args);
    const parts: Buffer[] = [pktLine('acknowledgments\n'), pktLine('NAK\n'), PKT_FLUSH];
    if (shallow.length > 0 || unshallow.length > 0) {
      parts.push(pktLine('shallow-info\n'));
      for (const oid of shallow) parts.push(pktLine(`shallow ${oid}\n`));
      for (const oid of unshallow) parts.push(pktLine(`unshallow ${oid}\n`));
      parts.push(PKT_FLUSH);
    }
    parts.push(pktLine('packfile\n'));
    parts.push(...sidebandPackets(pack));
    parts.push(PKT_FLUSH);
    sendRaw(res, 200, Buffer.concat(parts), 'application/x-git-upload-pack-result');
    return;
  }
  sendRaw(res, 400, Buffer.from('unknown command\n'), 'application/x-git-upload-pack-result');
}

function handleUploadPackV0(res: ServerResponse, repo: Repo, body: Buffer): void {
  // Two pkt-line sections: wants (with shallow/deepen) flushed, then haves/done flushed.
  const lines: string[] = [];
  let offset = 0;
  for (let section = 0; section < 2; section += 1) {
    const { packets, next } = decodePktLines(body, offset);
    for (const packet of packets) {
      if (packet.kind === 'data') lines.push(packet.payload.toString('utf8').replace(/\n$/, ''));
    }
    offset = next;
    if (offset >= body.length) break;
  }
  const args: FetchArgs = { wants: [], haves: [], shallow: [], depth: null };
  for (const line of lines) {
    if (line.startsWith('want ')) args.wants.push(line.slice(5).trim().split(' ')[0]);
    else if (line.startsWith('have ')) args.haves.push(line.slice(5).trim());
    else if (line.startsWith('shallow ')) args.shallow.push(line.slice(8).trim());
    else if (line.startsWith('deepen ')) args.depth = Number(line.slice(7).trim());
  }
  const { pack, shallow, unshallow } = fetchPack(repo, args);
  const parts: Buffer[] = [];
  for (const oid of shallow) parts.push(pktLine(`shallow ${oid}\n`));
  for (const oid of unshallow) parts.push(pktLine(`unshallow ${oid}\n`));
  parts.push(pktLine('NAK\n'));
  parts.push(...sidebandPackets(pack));
  parts.push(PKT_FLUSH);
  sendRaw(res, 200, Buffer.concat(parts), 'application/x-git-upload-pack-result');
}

function handleReceivePack(res: ServerResponse, repo: Repo, body: Buffer): void {
  const { packets, next } = decodePktLines(body);
  const commandLines = packets.filter((p) => p.kind === 'data').map((p) => p.payload.toString('utf8').replace(/\n$/, ''));
  if (commandLines.length === 0) {
    sendRaw(res, 400, Buffer.from('no commands\n'), 'application/x-git-receive-pack-result');
    return;
  }
  let capabilities = '';
  const commands: Array<{ oldOid: string; newOid: string; ref: string }> = [];
  commandLines.forEach((line, index) => {
    let text = line;
    if (index === 0) {
      const nul = text.indexOf('\0');
      if (nul >= 0) {
        capabilities = text.slice(nul + 1);
        text = text.slice(0, nul);
      }
    }
    const parts = text.trim().split(/\s+/);
    if (parts.length >= 3) commands.push({ oldOid: parts[0], newOid: parts[1], ref: parts[2] });
  });
  const wantsSideband = capabilities.split(' ').includes('side-band-64k');
  const wantsReport = capabilities.split(' ').includes('report-status') || capabilities.split(' ').includes('report-status-v2');

  // The pack (if any) follows the command list.
  let unpackOk = true;
  let unpackDetail = 'ok';
  const packBytes = body.subarray(next);
  if (packBytes.length > 0) {
    try {
      const objects = readPackEntries(packBytes, (oid) => repo.objects.get(oid));
      for (const object of objects) storeObject(repo, object.type, object.data);
    } catch {
      unpackOk = false;
      unpackDetail = 'error: could not read the packfile';
    }
  }

  const wasEmpty = repo.refs.size === 0;
  const reportLines: string[] = [`unpack ${unpackDetail}`];
  for (const command of commands) {
    const fail = (reason: string): void => {
      reportLines.push(`ng ${command.ref} ${reason}`);
    };
    if (!unpackOk) {
      fail('unpacker error');
      continue;
    }
    const current = repo.refs.get(command.ref) ?? ZERO_OID;
    if (command.newOid === ZERO_OID) {
      // delete
      if (!repo.refs.has(command.ref)) {
        fail('reference does not exist');
        continue;
      }
      repo.refs.delete(command.ref);
      reportLines.push(`ok ${command.ref}`);
      continue;
    }
    if (!repo.objects.has(command.newOid)) {
      fail('unknown object');
      continue;
    }
    if (current === ZERO_OID) {
      if (command.oldOid !== ZERO_OID && command.oldOid !== current) {
        fail('reference already exists');
        continue;
      }
      repo.refs.set(command.ref, command.newOid);
      if (wasEmpty && command.ref.startsWith('refs/heads/')) {
        repo.defaultBranch = command.ref.slice('refs/heads/'.length);
      }
      reportLines.push(`ok ${command.ref}`);
      continue;
    }
    if (command.oldOid !== current) {
      fail('stale info');
      continue;
    }
    if (command.ref.startsWith('refs/heads/')) {
      const newObject = repo.objects.get(command.newOid);
      const currentObject = repo.objects.get(current);
      if (newObject?.type === 'commit' && currentObject?.type === 'commit' && command.newOid !== current && !isAncestor(repo, current, command.newOid)) {
        fail('non-fast-forward');
        continue;
      }
    }
    repo.refs.set(command.ref, command.newOid);
    reportLines.push(`ok ${command.ref}`);
  }

  if (!wantsReport) {
    sendRaw(res, 200, Buffer.alloc(0), 'application/x-git-receive-pack-result');
    return;
  }
  const report = Buffer.concat([...reportLines.map((line) => pktLine(`${line}\n`)), PKT_FLUSH]);
  if (wantsSideband) {
    const chunks: Buffer[] = [];
    const CHUNK = 65515;
    for (let offset = 0; offset < report.length; offset += CHUNK) {
      chunks.push(pktLine(Buffer.concat([Buffer.from([1]), report.subarray(offset, Math.min(report.length, offset + CHUNK))])));
    }
    chunks.push(PKT_FLUSH);
    sendRaw(res, 200, Buffer.concat(chunks), 'application/x-git-receive-pack-result');
    return;
  }
  sendRaw(res, 200, report, 'application/x-git-receive-pack-result');
}

async function handleGit(req: IncomingMessage, res: ServerResponse, owner: string, repoName: string, rest: string, url: URL): Promise<void> {
  if (!authed(req)) {
    sendJson(res, 401, { message: 'Requires authentication' });
    return;
  }
  const repo = findRepo(owner, repoName);
  if (!repo) {
    sendJson(res, 404, { message: 'Not Found' });
    return;
  }
  const method = req.method ?? 'GET';
  if (method === 'GET' && rest === '/info/refs') {
    handleInfoRefs(req, res, repo, url);
    return;
  }
  if (method === 'POST' && rest === '/git-upload-pack') {
    const body = await readBody(req);
    // A malformed body is a 400; the server stays up either way.
    if (body.length === 0 || !/^[0-9a-fA-F]{4}/.test(body.subarray(0, 4).toString('ascii'))) {
      sendRaw(res, 400, Buffer.from('malformed pkt-line\n'), 'application/x-git-upload-pack-result');
      return;
    }
    try {
      if ((req.headers['git-protocol'] ?? '').includes('version=2')) handleUploadPackV2(res, repo, body);
      else handleUploadPackV0(res, repo, body);
    } catch {
      sendRaw(res, 400, Buffer.from('bad request\n'), 'application/x-git-upload-pack-result');
    }
    return;
  }
  if (method === 'POST' && rest === '/git-receive-pack') {
    const body = await readBody(req);
    try {
      handleReceivePack(res, repo, body);
    } catch {
      sendRaw(res, 400, Buffer.from('bad request\n'), 'application/x-git-receive-pack-result');
    }
    return;
  }
  sendJson(res, 404, { message: 'Not Found' });
}

// ---------------------------------------------------------------------------
// REST v3 serializers

function userJson(login: string): Record<string, unknown> {
  return { login, id: 1000, node_id: 'U_1000', type: 'User', site_admin: false };
}

function repoJson(repo: Repo, req: IncomingMessage): Record<string, unknown> {
  const owner = repo.owner ?? viewer();
  const base = baseUrlOf(req);
  return {
    id: repo.id,
    node_id: `R_${repo.id}`,
    name: repo.name,
    full_name: `${owner}/${repo.name}`,
    private: repo.isPrivate,
    owner: userJson(owner),
    html_url: `${base}/${owner}/${repo.name}`,
    description: repo.description,
    fork: false,
    url: `${base}/api/v3/repos/${owner}/${repo.name}`,
    clone_url: `${base}/${owner}/${repo.name}.git`,
    git_url: `git://${base}/${owner}/${repo.name}.git`,
    ssh_url: `git@${base}:${owner}/${repo.name}.git`,
    created_at: '2025-01-01T00:00:00Z',
    updated_at: nowIso(),
    pushed_at: nowIso(),
    size: repo.objects.size,
    stargazers_count: 0,
    watchers_count: 0,
    language: null,
    has_issues: true,
    has_projects: true,
    has_downloads: true,
    has_wiki: true,
    has_pages: false,
    forks_count: 0,
    archived: false,
    disabled: false,
    open_issues_count: [...repo.issues.values()].filter((issue) => issue.state === 'open').length,
    license: null,
    allow_forking: true,
    visibility: repo.isPrivate ? 'private' : 'public',
    default_branch: repo.defaultBranch,
  };
}

function labelJson(label: Label): Record<string, unknown> {
  return { id: label.id, node_id: `LA_${label.id}`, name: label.name, color: label.color, default: false, description: label.description };
}

function issueJson(repo: Repo, issue: Issue, req: IncomingMessage): Record<string, unknown> {
  const base = baseUrlOf(req);
  const owner = repo.owner ?? viewer();
  return {
    id: issue.id,
    node_id: `I_${issue.id}`,
    url: `${base}/api/v3/repos/${owner}/${repo.name}/issues/${issue.number}`,
    repository_url: `${base}/api/v3/repos/${owner}/${repo.name}`,
    labels_url: `${base}/api/v3/repos/${owner}/${repo.name}/issues/${issue.number}/labels{/name}`,
    comments_url: `${base}/api/v3/repos/${owner}/${repo.name}/issues/${issue.number}/comments`,
    html_url: `${base}/${owner}/${repo.name}/issues/${issue.number}`,
    number: issue.number,
    title: issue.title,
    user: userJson(viewer()),
    labels: issue.labels.map((name) => {
      const label = repo.labels.get(name);
      return label ? labelJson(label) : { id: 0, name, color: 'ededed', default: false, description: null };
    }),
    state: issue.state,
    locked: false,
    assignees: [],
    assignee: null,
    milestone: null,
    comments: issue.comments.length,
    created_at: '2025-01-01T00:00:00Z',
    updated_at: nowIso(),
    closed_at: issue.state === 'closed' ? nowIso() : null,
    body: issue.body,
    pull_request: undefined,
  };
}

function commentJson(repo: Repo, issue: Issue, comment: IssueComment, req: IncomingMessage): Record<string, unknown> {
  const base = baseUrlOf(req);
  const owner = repo.owner ?? viewer();
  return {
    id: comment.id,
    node_id: `IC_${comment.id}`,
    url: `${base}/api/v3/repos/${owner}/${repo.name}/issues/comments/${comment.id}`,
    html_url: `${base}/${owner}/${repo.name}/issues/${issue.number}#issuecomment-${comment.id}`,
    body: comment.body,
    user: userJson(viewer()),
    created_at: '2025-01-01T00:00:00Z',
    updated_at: nowIso(),
    issue_url: `${base}/api/v3/repos/${owner}/${repo.name}/issues/${issue.number}`,
  };
}

function commitJson(repo: Repo, oid: string, req: IncomingMessage): Record<string, unknown> {
  const object = repo.objects.get(oid);
  const view = object && object.type === 'commit' ? parseCommit(object.data) : { tree: '', parents: [], message: '', authorLine: '', committerLine: '' };
  const author = parseIdent(view.authorLine);
  const committer = parseIdent(view.committerLine);
  const base = baseUrlOf(req);
  const owner = repo.owner ?? viewer();
  return {
    sha: oid,
    node_id: `C_${oid}`,
    commit: {
      author: { name: author.name, email: author.email, date: author.date },
      committer: { name: committer.name, email: committer.email, date: committer.date },
      message: view.message,
      tree: { sha: view.tree, url: `${base}/api/v3/repos/${owner}/${repo.name}/git/trees/${view.tree}` },
      url: `${base}/api/v3/repos/${owner}/${repo.name}/git/commits/${oid}`,
      comment_count: 0,
    },
    url: `${base}/api/v3/repos/${owner}/${repo.name}/commits/${oid}`,
    html_url: `${base}/${owner}/${repo.name}/commit/${oid}`,
    author: { login: author.name, id: 1000, type: 'User' },
    committer: { login: committer.name, id: 1000, type: 'User' },
    parents: view.parents.map((parent) => ({ sha: parent, url: `${base}/api/v3/repos/${owner}/${repo.name}/commits/${parent}` })),
  };
}

function pullJson(repo: Repo, pull: Pull, req: IncomingMessage): Record<string, unknown> {
  const base = baseUrlOf(req);
  const owner = repo.owner ?? viewer();
  const headSha = repo.refs.get(`refs/heads/${pull.head}`) ?? '';
  const baseSha = repo.refs.get(`refs/heads/${pull.base}`) ?? '';
  let mergeable: boolean | null = null;
  if (pull.state === 'open' && headSha && baseSha) mergeable = !mergeWouldConflict(repo, baseSha, headSha);
  return {
    id: pull.id,
    node_id: `PR_${pull.id}`,
    url: `${base}/api/v3/repos/${owner}/${repo.name}/pulls/${pull.number}`,
    html_url: `${base}/${owner}/${repo.name}/pull/${pull.number}`,
    diff_url: `${base}/${owner}/${repo.name}/pull/${pull.number}.diff`,
    patch_url: `${base}/${owner}/${repo.name}/pull/${pull.number}.patch`,
    number: pull.number,
    state: pull.state,
    locked: false,
    title: pull.title,
    user: userJson(viewer()),
    body: pull.body,
    created_at: '2025-01-01T00:00:00Z',
    updated_at: nowIso(),
    closed_at: pull.state === 'closed' ? nowIso() : null,
    merged_at: pull.mergedAt,
    merge_commit_sha: pull.mergeCommitSha,
    merged: pull.merged,
    mergeable,
    mergeable_state: mergeable === null ? 'unknown' : mergeable ? 'clean' : 'dirty',
    head: {
      label: `${owner}:${pull.head}`,
      ref: pull.head,
      sha: headSha,
      user: userJson(owner),
      repo: repoJson(repo, req),
    },
    base: {
      label: `${owner}:${pull.base}`,
      ref: pull.base,
      sha: baseSha,
      user: userJson(owner),
      repo: repoJson(repo, req),
    },
    author_association: 'OWNER',
    draft: false,
  };
}

/** Files changed between a pull's merge base and its head, with line counts. */
function pullFiles(repo: Repo, pull: Pull): Array<Record<string, unknown>> {
  const headSha = repo.refs.get(`refs/heads/${pull.head}`);
  const baseSha = repo.refs.get(`refs/heads/${pull.base}`);
  if (!headSha || !baseSha) return [];
  const base = mergeBase(repo, baseSha, headSha) ?? baseSha;
  const baseTree = commitTreeOid(repo, base);
  const headTree = commitTreeOid(repo, headSha);
  if (!headTree) return [];
  const empty = new Map<string, { oid: string; mode: string }>();
  const baseFlat = baseTree ? flattenTree(repo, baseTree) : empty;
  const headFlat = flattenTree(repo, headTree);
  const files: Array<Record<string, unknown>> = [];
  const paths = new Set<string>([...baseFlat.keys(), ...headFlat.keys()]);
  const linesOf = (oid: string | undefined): string[] => {
    if (!oid) return [];
    const object = repo.objects.get(oid);
    if (!object || object.type !== 'blob') return [];
    const text = object.data.toString('utf8');
    return text === '' ? [] : text.split('\n');
  };
  const lcsLength = (a: string[], b: string[]): number => {
    const dp = new Array<number>(b.length + 1).fill(0);
    for (let i = 1; i <= a.length; i += 1) {
      let prev = 0;
      for (let j = 1; j <= b.length; j += 1) {
        const saved = dp[j];
        dp[j] = a[i - 1] === b[j - 1] ? prev + 1 : Math.max(dp[j], dp[j - 1]);
        prev = saved;
      }
    }
    return dp[b.length];
  };
  for (const path of [...paths].sort()) {
    const before = baseFlat.get(path);
    const after = headFlat.get(path);
    if (before?.oid === after?.oid) continue;
    const oldLines = linesOf(before?.oid);
    const newLines = linesOf(after?.oid);
    const common = lcsLength(oldLines, newLines);
    const additions = newLines.length - common;
    const deletions = oldLines.length - common;
    files.push({
      sha: after?.oid ?? before?.oid ?? '',
      filename: path,
      status: !before ? 'added' : !after ? 'removed' : 'modified',
      additions,
      deletions,
      changes: additions + deletions,
      blob_url: '',
      raw_url: '',
      contents_url: '',
    });
  }
  return files;
}

/** Perform the merge of a pull into its base branch. Returns {sha} or 'conflict'. */
function mergePull(repo: Repo, pull: Pull, method: string): { sha: string } | 'conflict' | 'gone' {
  const baseRef = `refs/heads/${pull.base}`;
  const headRef = `refs/heads/${pull.head}`;
  const baseTip = repo.refs.get(baseRef);
  const headTip = repo.refs.get(headRef);
  if (!baseTip || !headTip) return 'gone';
  if (mergeWouldConflict(repo, baseTip, headTip)) return 'conflict';
  let sha: string;
  if (method === 'merge') {
    const base = mergeBase(repo, baseTip, headTip);
    const tree = base === headTip || isAncestor(repo, headTip, baseTip) ? commitTreeOid(repo, baseTip)! : threeWayMerge(repo, baseTip, headTip)!;
    const ident = `${viewer()} <${viewer()}@example.invalid>`;
    const data = buildCommitData(tree, [baseTip, headTip], `Merge pull request #${pull.number} from ${pull.head}\n\n${pull.title}\n`, ident, nowSec());
    sha = storeObject(repo, 'commit', data);
    repo.refs.set(baseRef, sha);
  } else {
    // squash (and rebase, approximated as squash): one commit on the base with the merged tree.
    const tree = isAncestor(repo, headTip, baseTip) ? commitTreeOid(repo, baseTip)! : threeWayMerge(repo, baseTip, headTip)!;
    sha = commitOnRef(repo, baseRef, tree, `${pull.title} (#${pull.number})\n\n${pull.body ?? ''}\n`);
  }
  pull.state = 'closed';
  pull.merged = true;
  pull.mergedAt = nowIso();
  pull.mergeCommitSha = sha;
  return { sha };
}

function createIssueRecord(repo: Repo, title: string, body: string, labels: string[]): Issue {
  const issue: Issue = {
    id: nextIssueId++,
    number: repo.nextNumber++,
    title,
    body,
    state: 'open',
    labels: [...labels],
    comments: [],
    seq: globalSeq++,
  };
  repo.issues.set(issue.number, issue);
  return issue;
}

function createPullRecord(repo: Repo, title: string, body: string, head: string, base: string): Pull {
  const pull: Pull = {
    id: nextIssueId++,
    number: repo.nextNumber++,
    title,
    body,
    head,
    base,
    state: 'open',
    merged: false,
    mergedAt: null,
    mergeCommitSha: null,
    seq: globalSeq++,
  };
  repo.pulls.set(pull.number, pull);
  return pull;
}

// ---------------------------------------------------------------------------
// REST v3 routing

interface RestContext {
  req: IncomingMessage;
  res: ServerResponse;
  url: URL;
  body: Record<string, unknown> | null;
  bodyError: boolean;
}

function paginate<T>(req: IncomingMessage, res: ServerResponse, url: URL, items: T[], path: string): T[] {
  const perPage = Math.max(1, Math.min(100, Number(url.searchParams.get('per_page') ?? '30') || 30));
  const page = Math.max(1, Number(url.searchParams.get('page') ?? '1') || 1);
  const start = (page - 1) * perPage;
  const slice = items.slice(start, start + perPage);
  const headers: Record<string, string> = {};
  if (start + perPage < items.length) {
    const next = new URL(path, baseUrlOf(req));
    next.searchParams.set('per_page', String(perPage));
    next.searchParams.set('page', String(page + 1));
    const last = new URL(path, baseUrlOf(req));
    last.searchParams.set('per_page', String(perPage));
    last.searchParams.set('page', String(Math.ceil(items.length / perPage)));
    headers.link = `<${next.toString()}>; rel="next", <${last.toString()}>; rel="last"`;
  }
  if (Object.keys(headers).length > 0) {
    // sendJson merges headers; stash for the caller via a header set here.
    res.setHeader('link', headers.link);
  }
  return slice;
}

function notFound(res: ServerResponse): void {
  sendJson(res, 404, { message: 'Not Found' });
}

async function handleRest(ctx: RestContext): Promise<void> {
  const { req, res, url } = ctx;
  const method = req.method ?? 'GET';
  const segments = url.pathname.replace(/^\/api\/v3\/?/, '').split('/').filter((s) => s !== '').map((s) => decodeURIComponent(s));

  if (!authed(req)) {
    sendJson(res, 401, { message: 'Requires authentication' });
    return;
  }
  if (ctx.bodyError) {
    sendJson(res, 400, { message: 'Malformed JSON body' });
    return;
  }
  const body: Record<string, unknown> = ctx.body ?? {};

  // Root and meta.
  if (segments.length === 0) {
    if (method !== 'GET') return notFound(res);
    sendJson(
      res,
      200,
      {
        current_user_url: '/api/v3/user',
        current_user_repositories_url: '/api/v3/user/repos',
        repository_url: '/api/v3/repos/{owner}/{repo}',
        rate_limit_url: '/api/v3/rate_limit',
      },
      { 'x-oauth-scopes': 'repo, read:org' },
    );
    return;
  }
  if (segments.length === 1 && segments[0] === 'meta') {
    if (method !== 'GET') return notFound(res);
    sendJson(res, 200, { verifiable_password_authentication: false, installed_version: '1.0.0-forge', github_developer_version: 'v3' });
    return;
  }
  if (segments.length === 1 && segments[0] === 'user') {
    if (method !== 'GET') return notFound(res);
    sendJson(res, 200, { ...userJson(viewer()), name: viewer(), email: `${viewer()}@example.invalid` });
    return;
  }
  if (segments.length === 1 && segments[0] === 'rate_limit') {
    sendJson(res, 200, { resources: { core: { limit: 5000, remaining: 4999, reset: 1893456000, used: 1 } }, rate: { limit: 5000, remaining: 4999, reset: 1893456000, used: 1 } });
    return;
  }

  // /user/repos
  if (segments[0] === 'user' && segments[1] === 'repos' && segments.length === 2) {
    if (method === 'GET') {
      const mine = [...reposByName.values()]
        .filter((repo) => repo.owner === null || repo.owner === viewerLogin || viewerLogin === null)
        .sort((a, b) => a.seq - b.seq);
      const page = paginate(req, res, url, mine, '/api/v3/user/repos');
      sendJson(res, 200, page.map((repo) => repoJson(repo, req)), res.getHeader('link') ? { link: String(res.getHeader('link')) } : {});
      return;
    }
    if (method === 'POST') {
      const name = str(body.name);
      if (!name) {
        sendJson(res, 422, { message: 'Repository creation failed: name is required' });
        return;
      }
      if (findRepoByNameOnly(name)) {
        sendJson(res, 422, { message: 'Repository creation failed: name already exists on this account' });
        return;
      }
      const repo = createRepoRecord(name, body.private === undefined ? false : Boolean(body.private), str(body.description), str(body.default_branch, 'main'));
      sendJson(res, 201, repoJson(repo, req));
      return;
    }
    return notFound(res);
  }

  // /repos/{owner}/{repo}/...
  if (segments[0] === 'repos' && segments.length >= 3) {
    const owner = segments[1];
    const repo = findRepo(owner, segments[2]);
    if (!repo) return notFound(res);
    const rest = segments.slice(3);
    const repoPath = `/api/v3/repos/${owner}/${repo.name}`;

    if (rest.length === 0) {
      if (method === 'GET') {
        sendJson(res, 200, repoJson(repo, req));
        return;
      }
      if (method === 'PATCH') {
        if (typeof body.description === 'string') repo.description = body.description;
        if (typeof body.name === 'string' && body.name) repo.name = body.name;
        if (typeof body.private === 'boolean') repo.isPrivate = body.private;
        if (typeof body.default_branch === 'string' && body.default_branch) repo.defaultBranch = body.default_branch;
        sendJson(res, 200, repoJson(repo, req));
        return;
      }
      if (method === 'DELETE') {
        reposByName.delete(repo.name.toLowerCase());
        reposById.delete(repo.id);
        res.writeHead(204, { 'x-github-request-id': `req-${++requestCounter}` });
        res.end();
        return;
      }
      return notFound(res);
    }

    // branches
    if (rest[0] === 'branches' && rest.length === 1 && method === 'GET') {
      const branches = [...repo.refs.entries()]
        .filter(([ref]) => ref.startsWith('refs/heads/'))
        .map(([ref, oid]) => ({ name: ref.slice('refs/heads/'.length), commit: { sha: oid, url: `${baseUrlOf(req)}${repoPath}/commits/${oid}` }, protected: false }))
        .sort((a, b) => (a.name < b.name ? -1 : 1));
      sendJson(res, 200, paginate(req, res, url, branches, `${repoPath}/branches`));
      return;
    }

    // commits
    if (rest[0] === 'commits' && rest.length === 1 && method === 'GET') {
      const shaParam = url.searchParams.get('sha');
      const tip = shaParam ? resolveRef(repo, shaParam) : defaultTip(repo);
      if (!tip) {
        sendJson(res, 200, []);
        return;
      }
      const ancestors = commitAncestors(repo, tip);
      const ordered = [...ancestors.entries()].sort((a, b) => a[1] - b[1]).map(([oid]) => oid);
      // Present newest first: BFS distance ascending is newest-first for linear history;
      // stable and complete either way.
      sendJson(res, 200, paginate(req, res, url, ordered, `${repoPath}/commits`).map((oid) => commitJson(repo, oid, req)));
      return;
    }
    if (rest[0] === 'commits' && rest.length === 2 && method === 'GET') {
      const oid = resolveRef(repo, rest[1]);
      if (!oid) return notFound(res);
      sendJson(res, 200, commitJson(repo, oid, req));
      return;
    }

    // git/refs
    if (rest[0] === 'git' && rest[1] === 'refs') {
      if (method === 'POST' && rest.length === 2) {
        const ref = str(body.ref);
        const sha = str(body.sha);
        const target = repo.objects.get(sha);
        if (!ref.startsWith('refs/') || !target) {
          sendJson(res, 422, { message: 'Invalid ref or sha' });
          return;
        }
        repo.refs.set(ref, sha);
        sendJson(res, 201, { ref, node_id: `REF_${ref}`, url: `${baseUrlOf(req)}${repoPath}/git/refs/${ref.slice(5)}`, object: { type: target.type, sha, url: `${baseUrlOf(req)}${repoPath}/git/${target.type}s/${sha}` } });
        return;
      }
      if (method === 'GET') {
        const ref = `refs/${rest.slice(2).join('/')}`;
        const oid = repo.refs.get(ref);
        if (!oid) return notFound(res);
        const target = repo.objects.get(oid);
        sendJson(res, 200, { ref, object: { type: target?.type ?? 'commit', sha: oid } });
        return;
      }
      if (method === 'DELETE') {
        const ref = `refs/${rest.slice(2).join('/')}`;
        if (!repo.refs.has(ref)) return notFound(res);
        repo.refs.delete(ref);
        res.writeHead(204, { 'x-github-request-id': `req-${++requestCounter}` });
        res.end();
        return;
      }
      return notFound(res);
    }

    // contents
    if (rest[0] === 'contents') {
      const contentPath = rest.slice(1).join('/');
      return handleContents(ctx, repo, repoPath, contentPath);
    }

    // labels
    if (rest[0] === 'labels' && rest.length === 1) {
      if (method === 'GET') {
        sendJson(res, 200, [...repo.labels.values()].map((label) => labelJson(label)));
        return;
      }
      if (method === 'POST') {
        const name = str(body.name);
        if (!name) {
          sendJson(res, 422, { message: 'Label name is required' });
          return;
        }
        if (repo.labels.has(name)) {
          sendJson(res, 422, { message: 'Label already exists' });
          return;
        }
        const label: Label = { id: nextLabelId++, name, color: str(body.color, 'ededed').replace(/^#/, ''), description: str(body.description) };
        repo.labels.set(name, label);
        sendJson(res, 201, labelJson(label));
        return;
      }
      return notFound(res);
    }

    // issues
    if (rest[0] === 'issues') {
      return handleIssues(ctx, repo, repoPath, rest.slice(1));
    }

    // pulls
    if (rest[0] === 'pulls') {
      return handlePulls(ctx, repo, repoPath, rest.slice(1));
    }

    return notFound(res);
  }

  return notFound(res);
}

function handleContents(ctx: RestContext, repo: Repo, repoPath: string, contentPath: string): void {
  const { req, res, url } = ctx;
  const method = req.method ?? 'GET';
  const body: Record<string, unknown> = ctx.body ?? {};
  const base = baseUrlOf(req);

  if (method === 'GET') {
    const refParam = url.searchParams.get('ref');
    const tip = refParam ? resolveRef(repo, refParam) : defaultTip(repo);
    if (!tip) return notFound(res);
    const treeOid = commitTreeOid(repo, tip);
    if (!treeOid) return notFound(res);
    if (contentPath === '') {
      const entries = parseTree(repo.objects.get(treeOid)!.data).map((entry) => ({
        name: entry.name,
        path: entry.name,
        sha: entry.oid,
        size: entry.mode === '40000' || entry.mode === '040000' ? 0 : (repo.objects.get(entry.oid)?.data.length ?? 0),
        type: entry.mode === '40000' || entry.mode === '040000' ? 'dir' : 'file',
        url: `${base}${repoPath}/contents/${entry.name}`,
        download_url: null,
      }));
      sendJson(res, 200, entries);
      return;
    }
    // Walk the tree.
    const segments = contentPath.split('/');
    let currentTree = treeOid;
    for (let i = 0; i < segments.length; i += 1) {
      const treeObject = repo.objects.get(currentTree);
      if (!treeObject || treeObject.type !== 'tree') return notFound(res);
      const entry = parseTree(treeObject.data).find((candidate) => candidate.name === segments[i]);
      if (!entry) return notFound(res);
      const isDir = entry.mode === '40000' || entry.mode === '040000';
      if (i === segments.length - 1) {
        if (isDir) {
          const dirObject = repo.objects.get(entry.oid)!;
          const entries = parseTree(dirObject.data).map((child) => ({
            name: child.name,
            path: `${contentPath}/${child.name}`,
            sha: child.oid,
            size: child.mode === '40000' || child.mode === '040000' ? 0 : (repo.objects.get(child.oid)?.data.length ?? 0),
            type: child.mode === '40000' || child.mode === '040000' ? 'dir' : 'file',
            url: `${base}${repoPath}/contents/${contentPath}/${child.name}`,
            download_url: null,
          }));
          sendJson(res, 200, entries);
          return;
        }
        const blob = repo.objects.get(entry.oid);
        if (!blob) return notFound(res);
        sendJson(res, 200, {
          name: segments[i],
          path: contentPath,
          sha: entry.oid,
          size: blob.data.length,
          url: `${base}${repoPath}/contents/${contentPath}`,
          html_url: `${base}/${repo.owner ?? viewer()}/${repo.name}/blob/${repo.defaultBranch}/${contentPath}`,
          git_url: `${base}${repoPath}/git/blobs/${entry.oid}`,
          download_url: null,
          type: 'file',
          encoding: 'base64',
          content: blob.data.toString('base64'),
        });
        return;
      }
      if (!isDir) return notFound(res);
      currentTree = entry.oid;
    }
    return notFound(res);
  }

  if (method === 'PUT') {
    const branch = str(body.branch, repo.defaultBranch);
    const ref = `refs/heads/${branch}`;
    const exists = repo.refs.has(ref);
    if (body.branch !== undefined && !exists) return notFound(res);
    const tip = repo.refs.get(ref);
    const flat = new Map<string, { oid: string; mode: string }>();
    if (tip) {
      const treeOid = commitTreeOid(repo, tip);
      if (treeOid) for (const [path, value] of flattenTree(repo, treeOid)) flat.set(path, value);
    }
    const current = flat.get(contentPath);
    const providedSha = typeof body.sha === 'string' ? body.sha : undefined;
    if (current && providedSha !== undefined && providedSha !== current.oid) {
      sendJson(res, 409, { message: 'Conflict: the file has changed; the supplied sha is stale' });
      return;
    }
    if (current && providedSha === undefined) {
      sendJson(res, 422, { message: 'Invalid request: "sha" wasn\'t supplied' });
      return;
    }
    const content = Buffer.from(str(body.content), 'base64');
    const blobOid = storeObject(repo, 'blob', content);
    flat.set(contentPath, { oid: blobOid, mode: '100644' });
    const treeOid = buildTreeFromFlat(repo, flat);
    const commitSha = commitOnRef(repo, ref, treeOid, str(body.message, 'Update file'));
    sendJson(res, current ? 200 : 201, {
      content: {
        name: contentPath.split('/').pop() ?? contentPath,
        path: contentPath,
        sha: blobOid,
        size: content.length,
        url: `${base}${repoPath}/contents/${contentPath}`,
        html_url: `${base}/${repo.owner ?? viewer()}/${repo.name}/blob/${branch}/${contentPath}`,
        git_url: `${base}${repoPath}/git/blobs/${blobOid}`,
        download_url: null,
        type: 'file',
        encoding: 'base64',
      },
      commit: commitJson(repo, commitSha, req).commit ? { sha: commitSha, url: `${base}${repoPath}/git/commits/${commitSha}` } : { sha: commitSha },
    });
    return;
  }

  if (method === 'DELETE') {
    const branch = str(body.branch, repo.defaultBranch);
    const ref = `refs/heads/${branch}`;
    const tip = repo.refs.get(ref);
    if (!tip) return notFound(res);
    const treeOid = commitTreeOid(repo, tip);
    if (!treeOid) return notFound(res);
    const flat = flattenTree(repo, treeOid);
    if (!flat.has(contentPath)) return notFound(res);
    flat.delete(contentPath);
    const newTree = buildTreeFromFlat(repo, flat);
    const commitSha = commitOnRef(repo, ref, newTree, str(body.message, 'Delete file'));
    sendJson(res, 200, { content: null, commit: { sha: commitSha, url: `${base}${repoPath}/git/commits/${commitSha}` } });
    return;
  }

  return notFound(res);
}

function handleIssues(ctx: RestContext, repo: Repo, repoPath: string, rest: string[]): void {
  const { req, res, url } = ctx;
  const method = req.method ?? 'GET';
  const body: Record<string, unknown> = ctx.body ?? {};

  if (rest.length === 0) {
    if (method === 'POST') {
      const labelNames: string[] = [];
      const rawLabels = body.labels;
      if (Array.isArray(rawLabels)) {
        for (const entry of rawLabels) {
          const name = typeof entry === 'string' ? entry : isRecord(entry) ? str(entry.name) : '';
          if (name) labelNames.push(name);
        }
      }
      for (const name of labelNames) {
        if (!repo.labels.has(name)) {
          sendJson(res, 422, { message: `Validation Failed: label "${name}" does not exist` });
          return;
        }
      }
      const issue = createIssueRecord(repo, str(body.title), str(body.body), labelNames);
      sendJson(res, 201, issueJson(repo, issue, req));
      return;
    }
    if (method === 'GET') {
      const state = url.searchParams.get('state') ?? 'open';
      let list = [...repo.issues.values()];
      if (state === 'open' || state === 'closed') list = list.filter((issue) => issue.state === state);
      const direction = url.searchParams.get('direction') ?? 'desc';
      list.sort((a, b) => (direction === 'asc' ? a.seq - b.seq : b.seq - a.seq));
      const page = paginate(req, res, url, list, `${repoPath}/issues`);
      sendJson(res, 200, page.map((issue) => issueJson(repo, issue, req)));
      return;
    }
    return notFound(res);
  }

  const number = Number(rest[0]);
  const issue = Number.isInteger(number) ? repo.issues.get(number) : undefined;

  if (rest.length === 1) {
    if (!issue) return notFound(res);
    if (method === 'GET') {
      sendJson(res, 200, issueJson(repo, issue, req));
      return;
    }
    if (method === 'PATCH') {
      if (body.state === 'open' || body.state === 'closed') issue.state = body.state;
      if (typeof body.title === 'string') issue.title = body.title;
      if (typeof body.body === 'string') issue.body = body.body;
      if (Array.isArray(body.labels)) {
        const names: string[] = [];
        for (const entry of body.labels) {
          const name = typeof entry === 'string' ? entry : isRecord(entry) ? str(entry.name) : '';
          if (name) {
            if (!repo.labels.has(name)) {
              sendJson(res, 422, { message: `Validation Failed: label "${name}" does not exist` });
              return;
            }
            names.push(name);
          }
        }
        issue.labels = names;
      }
      sendJson(res, 200, issueJson(repo, issue, req));
      return;
    }
    return notFound(res);
  }

  if (rest.length === 2 && rest[1] === 'comments') {
    if (!issue) return notFound(res);
    if (method === 'POST') {
      const comment: IssueComment = { id: nextCommentId++, body: str(body.body), seq: globalSeq++ };
      issue.comments.push(comment);
      sendJson(res, 201, commentJson(repo, issue, comment, req));
      return;
    }
    if (method === 'GET') {
      const page = paginate(req, res, url, issue.comments, `${repoPath}/issues/${issue.number}/comments`);
      sendJson(res, 200, page.map((comment) => commentJson(repo, issue, comment, req)));
      return;
    }
    return notFound(res);
  }

  if (rest.length === 2 && rest[1] === 'labels') {
    if (!issue) return notFound(res);
    if (method === 'GET') {
      sendJson(res, 200, issue.labels.map((name) => {
        const label = repo.labels.get(name);
        return label ? labelJson(label) : { id: 0, name, color: 'ededed', default: false, description: null };
      }));
      return;
    }
    return notFound(res);
  }

  return notFound(res);
}

function handlePulls(ctx: RestContext, repo: Repo, repoPath: string, rest: string[]): void {
  const { req, res, url } = ctx;
  const method = req.method ?? 'GET';
  const body: Record<string, unknown> = ctx.body ?? {};

  if (rest.length === 0) {
    if (method === 'POST') {
      const head = str(body.head);
      const base = str(body.base, repo.defaultBranch);
      const headRef = head.includes(':') ? head.split(':').pop()! : head;
      if (!repo.refs.has(`refs/heads/${headRef}`)) {
        sendJson(res, 422, { message: `Validation Failed: head branch "${headRef}" does not exist` });
        return;
      }
      if (!repo.refs.has(`refs/heads/${base}`)) {
        sendJson(res, 422, { message: `Validation Failed: base branch "${base}" does not exist` });
        return;
      }
      const pull = createPullRecord(repo, str(body.title), str(body.body), headRef, base);
      sendJson(res, 201, pullJson(repo, pull, req));
      return;
    }
    if (method === 'GET') {
      const state = url.searchParams.get('state') ?? 'open';
      let list = [...repo.pulls.values()];
      if (state === 'open') list = list.filter((pull) => pull.state === 'open');
      else if (state === 'closed') list = list.filter((pull) => pull.state === 'closed');
      list.sort((a, b) => b.seq - a.seq);
      const page = paginate(req, res, url, list, `${repoPath}/pulls`);
      sendJson(res, 200, page.map((pull) => pullJson(repo, pull, req)));
      return;
    }
    return notFound(res);
  }

  const number = Number(rest[0]);
  const pull = Number.isInteger(number) ? repo.pulls.get(number) : undefined;

  if (rest.length === 1) {
    if (!pull) return notFound(res);
    if (method === 'GET') {
      sendJson(res, 200, pullJson(repo, pull, req));
      return;
    }
    if (method === 'PATCH') {
      if (body.state === 'open' || body.state === 'closed') pull.state = body.state;
      if (typeof body.title === 'string') pull.title = body.title;
      if (typeof body.body === 'string') pull.body = body.body;
      sendJson(res, 200, pullJson(repo, pull, req));
      return;
    }
    return notFound(res);
  }

  if (rest.length === 2 && rest[1] === 'files' && method === 'GET') {
    if (!pull) return notFound(res);
    sendJson(res, 200, paginate(req, res, url, pullFiles(repo, pull), `${repoPath}/pulls/${pull.number}/files`));
    return;
  }

  if (rest.length === 2 && rest[1] === 'merge' && method === 'PUT') {
    if (!pull) return notFound(res);
    if (pull.merged) {
      sendJson(res, 405, { message: 'Pull Request is not mergeable: it has already been merged' });
      return;
    }
    const method2 = str(body.merge_method, 'merge').toLowerCase();
    const result = mergePull(repo, pull, method2 === 'merge' ? 'merge' : 'squash');
    if (result === 'conflict') {
      sendJson(res, 405, { message: 'Pull Request is not mergeable: it has conflicts that must be resolved' });
      return;
    }
    if (result === 'gone') {
      sendJson(res, 405, { message: 'Pull Request is not mergeable: a branch is missing' });
      return;
    }
    sendJson(res, 200, { sha: result.sha, merged: true, message: 'Pull Request successfully merged' });
    return;
  }

  return notFound(res);
}

// ---------------------------------------------------------------------------
// GraphQL v4: a small parser and executor for the documents gh sends.

type GqlValue =
  | { kind: 'var'; name: string }
  | { kind: 'string'; value: string }
  | { kind: 'int'; value: number }
  | { kind: 'float'; value: number }
  | { kind: 'bool'; value: boolean }
  | { kind: 'null' }
  | { kind: 'enum'; value: string }
  | { kind: 'list'; values: GqlValue[] }
  | { kind: 'object'; fields: Array<{ name: string; value: GqlValue }> };

interface GqlField {
  name: string;
  alias: string | null;
  args: Array<{ name: string; value: GqlValue }>;
  selections: GqlSelection[];
}

type GqlSelection =
  | { kind: 'field'; field: GqlField }
  | { kind: 'fragment'; name: string }
  | { kind: 'inline'; typeCondition: string | null; selections: GqlSelection[] };

interface GqlOperation {
  type: 'query' | 'mutation';
  name: string | null;
  selections: GqlSelection[];
}

interface GqlDocument {
  operations: GqlOperation[];
  fragments: Map<string, { typeCondition: string; selections: GqlSelection[] }>;
}

function tokenizeGql(source: string): string[] {
  const tokens: string[] = [];
  let i = 0;
  while (i < source.length) {
    const ch = source[i];
    if (ch === '#') {
      while (i < source.length && source[i] !== '\n') i += 1;
      continue;
    }
    if (/\s|,/.test(ch)) {
      i += 1;
      continue;
    }
    if (source.startsWith('...', i)) {
      tokens.push('...');
      i += 3;
      continue;
    }
    if ('{}()[]:=@$!'.includes(ch)) {
      tokens.push(ch);
      i += 1;
      continue;
    }
    if (ch === '"') {
      if (source.startsWith('"""', i)) {
        const end = source.indexOf('"""', i + 3);
        tokens.push(`"${source.slice(i + 3, end === -1 ? source.length : end)}"`);
        i = end === -1 ? source.length : end + 3;
        continue;
      }
      let j = i + 1;
      let value = '';
      while (j < source.length && source[j] !== '"') {
        if (source[j] === '\\' && j + 1 < source.length) {
          value += source[j + 1];
          j += 2;
        } else {
          value += source[j];
          j += 1;
        }
      }
      tokens.push(`"${value}"`);
      i = j + 1;
      continue;
    }
    const match = /^-?[0-9][0-9.eE+-]*|[_A-Za-z][_0-9A-Za-z]*/.exec(source.slice(i));
    if (match) {
      tokens.push(match[0]);
      i += match[0].length;
      continue;
    }
    i += 1;
  }
  return tokens;
}

class GqlParser {
  private tokens: string[];
  private pos = 0;

  constructor(source: string) {
    this.tokens = tokenizeGql(source);
  }

  private peek(): string | undefined {
    return this.tokens[this.pos];
  }

  private next(): string {
    const token = this.tokens[this.pos++];
    if (token === undefined) throw new Error('unexpected end of document');
    return token;
  }

  private expect(token: string): void {
    const got = this.next();
    if (got !== token) throw new Error(`expected ${token}, got ${got}`);
  }

  parseDocument(): GqlDocument {
    const operations: GqlOperation[] = [];
    const fragments = new Map<string, { typeCondition: string; selections: GqlSelection[] }>();
    while (this.pos < this.tokens.length) {
      const token = this.peek();
      if (token === '{') {
        operations.push({ type: 'query', name: null, selections: this.parseSelections() });
      } else if (token === 'query' || token === 'mutation' || token === 'subscription') {
        this.next();
        let name: string | null = null;
        if (this.peek() !== '(' && this.peek() !== '{') name = this.next();
        if (this.peek() === '(') this.skipParens();
        // directives before the selection set
        while (this.peek() === '@') {
          this.next();
          this.next();
          if (this.peek() === '(') this.skipParens();
        }
        operations.push({ type: token === 'mutation' ? 'mutation' : 'query', name, selections: this.parseSelections() });
      } else if (token === 'fragment') {
        this.next();
        const fragName = this.next();
        this.expect('on');
        const typeCondition = this.next();
        fragments.set(fragName, { typeCondition, selections: this.parseSelections() });
      } else {
        this.next();
      }
    }
    return { operations, fragments };
  }

  private skipParens(): void {
    this.expect('(');
    let depth = 1;
    while (depth > 0 && this.pos < this.tokens.length) {
      const token = this.next();
      if (token === '(') depth += 1;
      else if (token === ')') depth -= 1;
    }
  }

  private parseSelections(): GqlSelection[] {
    this.expect('{');
    const selections: GqlSelection[] = [];
    while (this.peek() !== '}') {
      if (this.peek() === '...') {
        this.next();
        if (this.peek() === 'on') {
          this.next();
          const typeCondition = this.next();
          selections.push({ kind: 'inline', typeCondition, selections: this.parseSelections() });
        } else {
          selections.push({ kind: 'fragment', name: this.next() });
        }
        continue;
      }
      let name = this.next();
      let alias: string | null = null;
      if (this.peek() === ':') {
        this.next();
        alias = name;
        name = this.next();
      }
      const args: Array<{ name: string; value: GqlValue }> = [];
      if (this.peek() === '(') {
        this.next();
        while (this.peek() !== ')') {
          const argName = this.next();
          this.expect(':');
          args.push({ name: argName, value: this.parseValue() });
        }
        this.next();
      }
      while (this.peek() === '@') {
        this.next();
        this.next();
        if (this.peek() === '(') this.skipParens();
      }
      const sub = this.peek() === '{' ? this.parseSelections() : [];
      selections.push({ kind: 'field', field: { name, alias, args, selections: sub } });
    }
    this.next();
    return selections;
  }

  private parseValue(): GqlValue {
    const token = this.next();
    if (token === '$') return { kind: 'var', name: this.next() };
    if (token.startsWith('"')) return { kind: 'string', value: token.slice(1, -1) };
    if (token === '[') {
      const values: GqlValue[] = [];
      while (this.peek() !== ']') values.push(this.parseValue());
      this.next();
      return { kind: 'list', values };
    }
    if (token === '{') {
      const fields: Array<{ name: string; value: GqlValue }> = [];
      while (this.peek() !== '}') {
        const name = this.next();
        this.expect(':');
        fields.push({ name, value: this.parseValue() });
      }
      this.next();
      return { kind: 'object', fields };
    }
    if (token === 'true' || token === 'false') return { kind: 'bool', value: token === 'true' };
    if (token === 'null') return { kind: 'null' };
    if (/^-?\d+$/.test(token)) return { kind: 'int', value: Number(token) };
    if (/^-?\d*\.\d/.test(token)) return { kind: 'float', value: Number(token) };
    return { kind: 'enum', value: token };
  }
}

function gqlValue(value: GqlValue, variables: Record<string, unknown>): unknown {
  switch (value.kind) {
    case 'var':
      return variables[value.name];
    case 'string':
    case 'int':
    case 'float':
    case 'bool':
      return value.value;
    case 'null':
      return null;
    case 'enum':
      return value.value;
    case 'list':
      return value.values.map((entry) => gqlValue(entry, variables));
    case 'object': {
      const out: Record<string, unknown> = {};
      for (const field of value.fields) out[field.name] = gqlValue(field.value, variables);
      return out;
    }
  }
}

// Global (Relay) ids: base64 of "Type:key", opaque and stable.
function globalId(type: string, key: string): string {
  return Buffer.from(`${type}:${key}`, 'utf8').toString('base64');
}

function decodeGlobalId(id: string): { type: string; key: string } | null {
  try {
    const text = Buffer.from(id, 'base64').toString('utf8');
    const colon = text.indexOf(':');
    if (colon < 0) return null;
    return { type: text.slice(0, colon), key: text.slice(colon + 1) };
  } catch {
    return null;
  }
}

interface GqlObject {
  __type: string;
  repo?: Repo;
  issue?: Issue;
  pull?: Pull;
  comment?: IssueComment;
  login?: string;
  payload?: Record<string, unknown>;
  connection?: { nodes: GqlObject[]; total: number; startIndex: number };
  typeName?: string;
}

const TYPE_FIELDS: Record<string, string[]> = {
  Query: ['viewer', 'repository', 'node', 'search', 'rateLimit', '__type', '__schema', '__typename'],
  Mutation: ['createIssue', 'closeIssue', 'createPullRequest', 'mergePullRequest', 'addComment', '__typename'],
  User: ['login', 'id', 'databaseId', 'name', 'email', 'url', 'avatarUrl', '__typename'],
  Organization: ['login', 'id', 'name', 'url', '__typename'],
  Repository: [
    'id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission',
    'hasIssuesEnabled', 'hasPullRequestsEnabled', 'isPrivate', 'description', 'url', 'createdAt', 'updatedAt',
    'issue', 'issues', 'pullRequest', 'pullRequests', 'stargazerCount', 'forkCount', 'isFork', 'isArchived',
    'primaryLanguage', 'licenseInfo', '__typename',
  ],
  Ref: ['name', 'prefix', 'target', '__typename'],
  Commit: ['id', 'oid', 'message', 'committedDate', '__typename'],
  Issue: [
    'id', 'databaseId', 'number', 'title', 'state', 'body', 'url', 'createdAt', 'updatedAt', 'author',
    'labels', 'comments', 'repository', 'closed', '__typename',
  ],
  PullRequest: [
    'id', 'databaseId', 'number', 'title', 'body', 'state', 'merged', 'mergedAt', 'mergeable',
    'headRefName', 'baseRefName', 'headRefOid', 'baseRefOid', 'url', 'createdAt', 'updatedAt', 'author',
    'files', 'repository', 'mergedBy', 'isDraft', 'additions', 'deletions', 'changedFiles', '__typename',
  ],
  IssueComment: ['id', 'databaseId', 'body', 'url', 'createdAt', 'updatedAt', 'author', '__typename'],
  Label: ['id', 'name', 'color', 'description', '__typename'],
  IssueConnection: ['nodes', 'edges', 'pageInfo', 'totalCount', '__typename'],
  PullRequestConnection: ['nodes', 'edges', 'pageInfo', 'totalCount', '__typename'],
  PullRequestChangedFileConnection: ['nodes', 'edges', 'pageInfo', 'totalCount', '__typename'],
  PullRequestChangedFile: ['path', 'additions', 'deletions', 'changeType', '__typename'],
  PageInfo: ['hasNextPage', 'hasPreviousPage', 'startCursor', 'endCursor', '__typename'],
  CreateIssuePayload: ['issue', 'clientMutationId', '__typename'],
  CloseIssuePayload: ['issue', 'clientMutationId', '__typename'],
  CreatePullRequestPayload: ['pullRequest', 'clientMutationId', '__typename'],
  MergePullRequestPayload: ['pullRequest', 'clientMutationId', '__typename'],
  AddCommentPayload: ['commentEdge', 'subject', 'clientMutationId', '__typename'],
  IssueEdge: ['node', 'cursor', '__typename'],
  PullRequestEdge: ['node', 'cursor', '__typename'],
  CommentEdge: ['node', 'cursor', '__typename'],
  __Type: ['name', 'kind', 'description', 'fields', 'enumValues', 'possibleTypes', 'inputFields', 'ofType', 'specifiedByURL', '__typename'],
  __Field: ['name', 'description', 'args', 'type', 'isDeprecated', 'deprecationReason', '__typename'],
  __EnumValue: ['name', 'description', 'isDeprecated', 'deprecationReason', '__typename'],
  __InputValue: ['name', 'description', 'type', 'defaultValue', '__typename'],
  __Schema: ['types', 'queryType', 'mutationType', 'subscriptionType', 'directives', '__typename'],
  __Directive: ['name', 'description', 'locations', 'args', '__typename'],
  SearchResultItemConnection: ['nodes', 'edges', 'pageInfo', 'issueCount', '__typename'],
};

const ENUM_TYPES: Record<string, string[]> = {
  IssueState: ['OPEN', 'CLOSED'],
  PullRequestState: ['OPEN', 'CLOSED', 'MERGED'],
  MergeableState: ['MERGEABLE', 'CONFLICTING', 'UNKNOWN'],
  PullRequestMergeMethod: ['MERGE', 'SQUASH', 'REBASE'],
  RepositoryPermission: ['ADMIN', 'MAINTAIN', 'WRITE', 'TRIAGE', 'READ'],
  SearchType: ['ISSUE', 'REPOSITORY', 'USER', 'DISCUSSION'],
  IssueOrderField: ['CREATED_AT', 'UPDATED_AT', 'COMMENTS'],
  OrderDirection: ['ASC', 'DESC'],
  FileStatus: ['ADDED', 'MODIFIED', 'DELETED', 'RENAMED', 'COPIED', 'CHANGED'],
};

function cursorFor(index: number): string {
  return Buffer.from(`cursor:${index}`, 'utf8').toString('base64');
}

function indexFromCursor(cursor: unknown): number {
  if (typeof cursor !== 'string' || cursor === '') return 0;
  try {
    const text = Buffer.from(cursor, 'base64').toString('utf8');
    const match = /^cursor:(\d+)$/.exec(text);
    if (match) return Number(match[1]);
    const asNumber = Number(cursor);
    return Number.isInteger(asNumber) && asNumber >= 0 ? asNumber : 0;
  } catch {
    return 0;
  }
}

interface GqlExec {
  variables: Record<string, unknown>;
  errors: Array<{ message: string }>;
  doc: GqlDocument;
}

function repoGql(repo: Repo): GqlObject {
  return { __type: 'Repository', repo };
}

function issueGql(repo: Repo, issue: Issue): GqlObject {
  return { __type: 'Issue', repo, issue };
}

function pullGql(repo: Repo, pull: Pull): GqlObject {
  return { __type: 'PullRequest', repo, pull };
}

function pageConnection(nodes: GqlObject[], total: number, startIndex: number): GqlObject {
  return { __type: 'Connection', connection: { nodes, total, startIndex } };
}

function resolveField(obj: GqlObject, field: GqlField, exec: GqlExec): unknown {
  const args = new Map<string, unknown>();
  for (const arg of field.args) args.set(arg.name, gqlValue(arg.value, exec.variables));
  const repo = obj.repo;
  switch (obj.__type) {
    case 'Query': {
      if (field.name === 'viewer') return { __type: 'User', login: viewer() };
      if (field.name === 'repository') {
        const owner = str(args.get('owner'));
        const name = str(args.get('name'));
        const found = owner && name ? findRepo(owner, name) : null;
        return found ? repoGql(found) : null;
      }
      if (field.name === 'node') {
        const decoded = decodeGlobalId(str(args.get('id')));
        if (!decoded) return null;
        if (decoded.type === 'Repository') {
          const found = reposById.get(Number(decoded.key));
          return found ? repoGql(found) : null;
        }
        if (decoded.type === 'Issue' || decoded.type === 'PullRequest') {
          const [repoId, numberText] = decoded.key.split(':');
          const found = reposById.get(Number(repoId));
          if (!found) return null;
          const number = Number(numberText);
          const issue = decoded.type === 'Issue' ? found.issues.get(number) : undefined;
          const pull = decoded.type === 'PullRequest' ? found.pulls.get(number) : undefined;
          if (issue) return issueGql(found, issue);
          if (pull) return pullGql(found, pull);
          return null;
        }
        if (decoded.type === 'User') return { __type: 'User', login: decoded.key };
        return null;
      }
      if (field.name === '__type') return { __type: '__Type', typeName: str(args.get('name')) };
      if (field.name === '__schema') return { __type: '__Schema' };
      if (field.name === 'search') return pageConnection([], 0, 0);
      if (field.name === 'rateLimit') return { __type: 'Payload', payload: { limit: 5000, remaining: 4999, used: 1, resetAt: '2030-01-01T00:00:00Z', cost: 1, nodeCount: 0 } };
      break;
    }
    case 'Mutation': {
      if (field.name === 'createIssue') {
        const input = isRecord(args.get('input')) ? (args.get('input') as Record<string, unknown>) : {};
        const decoded = decodeGlobalId(str(input.repositoryId));
        const target = decoded ? reposById.get(Number(decoded.key)) : null;
        if (!target) throw new Error('repository not found for createIssue');
        const issue = createIssueRecord(target, str(input.title), str(input.body), []);
        return { __type: 'CreateIssuePayload', repo: target, issue, payload: { clientMutationId: input.clientMutationId ?? null } };
      }
      if (field.name === 'closeIssue') {
        const input = isRecord(args.get('input')) ? (args.get('input') as Record<string, unknown>) : {};
        const decoded = decodeGlobalId(str(input.issueId));
        if (!decoded) throw new Error('bad issue id');
        const [repoId, numberText] = decoded.key.split(':');
        const target = reposById.get(Number(repoId));
        const issue = target?.issues.get(Number(numberText));
        if (!target || !issue) throw new Error('issue not found');
        issue.state = 'closed';
        return { __type: 'CloseIssuePayload', repo: target, issue, payload: { clientMutationId: input.clientMutationId ?? null } };
      }
      if (field.name === 'createPullRequest') {
        const input = isRecord(args.get('input')) ? (args.get('input') as Record<string, unknown>) : {};
        const decoded = decodeGlobalId(str(input.repositoryId));
        const target = decoded ? reposById.get(Number(decoded.key)) : null;
        if (!target) throw new Error('repository not found for createPullRequest');
        const pull = createPullRecord(target, str(input.title), str(input.body), str(input.headRefName), str(input.baseRefName, target.defaultBranch));
        return { __type: 'CreatePullRequestPayload', repo: target, pull, payload: { clientMutationId: input.clientMutationId ?? null } };
      }
      if (field.name === 'mergePullRequest') {
        const input = isRecord(args.get('input')) ? (args.get('input') as Record<string, unknown>) : {};
        const decoded = decodeGlobalId(str(input.pullRequestId));
        if (!decoded) throw new Error('bad pull request id');
        const [repoId, numberText] = decoded.key.split(':');
        const target = reposById.get(Number(repoId));
        const pull = target?.pulls.get(Number(numberText));
        if (!target || !pull) throw new Error('pull request not found');
        if (!pull.merged) {
          const method = str(input.mergeMethod, 'SQUASH').toLowerCase();
          mergePull(target, pull, method === 'merge' ? 'merge' : 'squash');
        }
        return { __type: 'MergePullRequestPayload', repo: target, pull, payload: { clientMutationId: input.clientMutationId ?? null } };
      }
      if (field.name === 'addComment') {
        const input = isRecord(args.get('input')) ? (args.get('input') as Record<string, unknown>) : {};
        const decoded = decodeGlobalId(str(input.subjectId));
        if (!decoded) throw new Error('bad subject id');
        const [repoId, numberText] = decoded.key.split(':');
        const target = reposById.get(Number(repoId));
        const issue = target?.issues.get(Number(numberText));
        if (!target || !issue) throw new Error('subject not found');
        const comment: IssueComment = { id: nextCommentId++, body: str(input.body), seq: globalSeq++ };
        issue.comments.push(comment);
        return { __type: 'AddCommentPayload', repo: target, issue, comment, payload: { clientMutationId: input.clientMutationId ?? null } };
      }
      break;
    }
    case 'User':
    case 'Organization': {
      const login = obj.login ?? viewer();
      if (field.name === 'login') return login;
      if (field.name === 'id') return globalId('User', login);
      if (field.name === 'databaseId') return 1000;
      if (field.name === 'name') return login;
      if (field.name === 'email') return `${login}@example.invalid`;
      if (field.name === 'url') return `/${login}`;
      if (field.name === 'avatarUrl') return '';
      break;
    }
    case 'Repository': {
      if (!repo) break;
      const owner = repo.owner ?? viewer();
      switch (field.name) {
        case 'id': return globalId('Repository', String(repo.id));
        case 'databaseId': return repo.id;
        case 'name': return repo.name;
        case 'nameWithOwner': return `${owner}/${repo.name}`;
        case 'owner': return { __type: 'User', login: owner };
        case 'defaultBranchRef': {
          const tip = defaultTip(repo);
          return tip ? { __type: 'Ref', payload: { name: repo.defaultBranch, oid: tip }, repo } : null;
        }
        case 'viewerPermission': return 'ADMIN';
        case 'hasIssuesEnabled': return true;
        case 'hasPullRequestsEnabled': return true;
        case 'isPrivate': return repo.isPrivate;
        case 'description': return repo.description;
        case 'url': return `/${owner}/${repo.name}`;
        case 'createdAt': return '2025-01-01T00:00:00Z';
        case 'updatedAt': return nowIso();
        case 'stargazerCount': return 0;
        case 'forkCount': return 0;
        case 'isFork': return false;
        case 'isArchived': return false;
        case 'primaryLanguage': return null;
        case 'licenseInfo': return null;
        case 'issue': {
          const issue = repo.issues.get(num(args.get('number')));
          return issue ? issueGql(repo, issue) : null;
        }
        case 'issues': {
          let list = [...repo.issues.values()];
          const states = args.get('states');
          if (Array.isArray(states) && states.length > 0) {
            const wanted = states.map((s) => String(s).toLowerCase());
            list = list.filter((issue) => wanted.includes(issue.state));
          }
          const orderBy = isRecord(args.get('orderBy')) ? (args.get('orderBy') as Record<string, unknown>) : null;
          const direction = orderBy ? str(orderBy.direction, 'DESC') : 'DESC';
          list.sort((a, b) => (direction === 'ASC' ? a.seq - b.seq || a.number - b.number : b.seq - a.seq || b.number - a.number));
          const total = list.length;
          const start = args.get('after') != null ? indexFromCursor(args.get('after')) + 1 : 0;
          const first = args.get('first') != null ? num(args.get('first'), total) : total;
          const slice = list.slice(start, start + Math.max(0, first));
          const connection = pageConnection(slice.map((issue) => issueGql(repo, issue)), total, start);
          connection.__type = 'IssueConnection';
          return connection;
        }
        case 'pullRequest': {
          const pull = repo.pulls.get(num(args.get('number')));
          return pull ? pullGql(repo, pull) : null;
        }
        case 'pullRequests': {
          let list = [...repo.pulls.values()];
          const states = args.get('states');
          if (Array.isArray(states) && states.length > 0) {
            const wanted = states.map((s) => String(s).toLowerCase());
            list = list.filter((pull) => wanted.includes(pull.merged ? 'merged' : pull.state));
          } else {
            list = list.filter((pull) => pull.state === 'open' || pull.merged);
          }
          list.sort((a, b) => b.seq - a.seq);
          const total = list.length;
          const start = args.get('after') != null ? indexFromCursor(args.get('after')) + 1 : 0;
          const first = args.get('first') != null ? num(args.get('first'), total) : total;
          const slice = list.slice(start, start + Math.max(0, first));
          const connection = pageConnection(slice.map((pull) => pullGql(repo, pull)), total, start);
          connection.__type = 'PullRequestConnection';
          return connection;
        }
      }
      break;
    }
    case 'Ref': {
      if (field.name === 'name') return obj.payload?.name ?? repo?.defaultBranch ?? 'main';
      if (field.name === 'prefix') return 'refs/heads/';
      if (field.name === 'target') return { __type: 'Commit', payload: { oid: obj.payload?.oid ?? '' }, repo };
      break;
    }
    case 'Commit': {
      if (field.name === 'oid') return obj.payload?.oid ?? '';
      if (field.name === 'id') return globalId('Commit', String(obj.payload?.oid ?? ''));
      if (field.name === 'message') {
        const object = repo?.objects.get(String(obj.payload?.oid ?? ''));
        return object ? parseCommit(object.data).message : '';
      }
      if (field.name === 'committedDate') return '2025-01-01T00:00:00Z';
      break;
    }
    case 'Issue': {
      const issue = obj.issue;
      if (!issue || !repo) break;
      switch (field.name) {
        case 'id': return globalId('Issue', `${repo.id}:${issue.number}`);
        case 'databaseId': return issue.id;
        case 'number': return issue.number;
        case 'title': return issue.title;
        case 'state': return issue.state.toUpperCase();
        case 'body': return issue.body;
        case 'url': return `/${repo.owner ?? viewer()}/${repo.name}/issues/${issue.number}`;
        case 'createdAt': return '2025-01-01T00:00:00Z';
        case 'updatedAt': return nowIso();
        case 'closed': return issue.state === 'closed';
        case 'author': return { __type: 'User', login: viewer() };
        case 'repository': return repoGql(repo);
        case 'labels': {
          const nodes = issue.labels.map((name) => ({ __type: 'Label', payload: { name, color: repo.labels.get(name)?.color ?? 'ededed', description: repo.labels.get(name)?.description ?? '' } }) as GqlObject);
          const connection = pageConnection(nodes, nodes.length, 0);
          connection.__type = 'Connection';
          return connection;
        }
        case 'comments': {
          const nodes = issue.comments.map((comment) => ({ __type: 'IssueComment', repo, issue, comment }) as GqlObject);
          const connection = pageConnection(nodes, nodes.length, 0);
          connection.__type = 'Connection';
          return connection;
        }
      }
      break;
    }
    case 'PullRequest': {
      const pull = obj.pull;
      if (!pull || !repo) break;
      const headSha = repo.refs.get(`refs/heads/${pull.head}`) ?? '';
      const baseSha = repo.refs.get(`refs/heads/${pull.base}`) ?? '';
      switch (field.name) {
        case 'id': return globalId('PullRequest', `${repo.id}:${pull.number}`);
        case 'databaseId': return pull.id;
        case 'number': return pull.number;
        case 'title': return pull.title;
        case 'body': return pull.body;
        case 'state': return pull.merged ? 'MERGED' : pull.state.toUpperCase();
        case 'merged': return pull.merged;
        case 'mergedAt': return pull.mergedAt;
        case 'mergeable': {
          if (pull.merged || pull.state === 'closed') return 'UNKNOWN';
          if (!headSha || !baseSha) return 'UNKNOWN';
          return mergeWouldConflict(repo, baseSha, headSha) ? 'CONFLICTING' : 'MERGEABLE';
        }
        case 'headRefName': return pull.head;
        case 'baseRefName': return pull.base;
        case 'headRefOid': return headSha;
        case 'baseRefOid': return baseSha;
        case 'url': return `/${repo.owner ?? viewer()}/${repo.name}/pull/${pull.number}`;
        case 'createdAt': return '2025-01-01T00:00:00Z';
        case 'updatedAt': return nowIso();
        case 'author': return { __type: 'User', login: viewer() };
        case 'repository': return repoGql(repo);
        case 'mergedBy': return pull.merged ? { __type: 'User', login: viewer() } : null;
        case 'isDraft': return false;
        case 'files': {
          const files = pullFiles(repo, pull);
          const first = args.get('first') != null ? num(args.get('first'), files.length) : files.length;
          const nodes = files.slice(0, first).map((file) => ({
            __type: 'PullRequestChangedFile',
            payload: {
              path: file.filename,
              additions: file.additions,
              deletions: file.deletions,
              changeType: file.status === 'added' ? 'ADDED' : file.status === 'removed' ? 'DELETED' : 'MODIFIED',
            },
          }) as GqlObject);
          const connection = pageConnection(nodes, files.length, 0);
          connection.__type = 'PullRequestChangedFileConnection';
          return connection;
        }
        case 'additions': return pullFiles(repo, pull).reduce((sum, file) => sum + num(file.additions), 0);
        case 'deletions': return pullFiles(repo, pull).reduce((sum, file) => sum + num(file.deletions), 0);
        case 'changedFiles': return pullFiles(repo, pull).length;
      }
      break;
    }
    case 'IssueComment': {
      const comment = obj.comment;
      if (!comment) break;
      if (field.name === 'id') return globalId('IssueComment', String(comment.id));
      if (field.name === 'databaseId') return comment.id;
      if (field.name === 'body') return comment.body;
      if (field.name === 'createdAt') return '2025-01-01T00:00:00Z';
      if (field.name === 'updatedAt') return nowIso();
      if (field.name === 'author') return { __type: 'User', login: viewer() };
      if (field.name === 'url') return '';
      break;
    }
    case 'Label': {
      if (field.name === 'id') return globalId('Label', String(obj.payload?.name ?? ''));
      if (field.name === 'name') return obj.payload?.name ?? '';
      if (field.name === 'color') return obj.payload?.color ?? 'ededed';
      if (field.name === 'description') return obj.payload?.description ?? '';
      break;
    }
    case 'PullRequestChangedFile': {
      if (field.name === 'path') return obj.payload?.path ?? '';
      if (field.name === 'additions') return obj.payload?.additions ?? 0;
      if (field.name === 'deletions') return obj.payload?.deletions ?? 0;
      if (field.name === 'changeType') return obj.payload?.changeType ?? 'MODIFIED';
      break;
    }
    case 'CreateIssuePayload':
    case 'CloseIssuePayload': {
      if (field.name === 'issue') return obj.issue && repo ? issueGql(repo, obj.issue) : null;
      if (field.name === 'clientMutationId') return obj.payload?.clientMutationId ?? null;
      break;
    }
    case 'CreatePullRequestPayload':
    case 'MergePullRequestPayload': {
      if (field.name === 'pullRequest') return obj.pull && repo ? pullGql(repo, obj.pull) : null;
      if (field.name === 'clientMutationId') return obj.payload?.clientMutationId ?? null;
      break;
    }
    case 'AddCommentPayload': {
      if (field.name === 'commentEdge') {
        return { __type: 'CommentEdge', repo, issue: obj.issue, comment: obj.comment };
      }
      if (field.name === 'subject') return obj.issue && repo ? issueGql(repo, obj.issue) : null;
      if (field.name === 'clientMutationId') return obj.payload?.clientMutationId ?? null;
      break;
    }
    case 'CommentEdge':
    case 'IssueEdge':
    case 'PullRequestEdge': {
      if (field.name === 'node') {
        if (obj.comment) return { __type: 'IssueComment', repo: obj.repo, issue: obj.issue, comment: obj.comment };
        if (obj.issue && obj.repo) return issueGql(obj.repo, obj.issue);
        if (obj.pull && obj.repo) return pullGql(obj.repo, obj.pull);
        return null;
      }
      if (field.name === 'cursor') return cursorFor(0);
      break;
    }
    case '__Type': {
      const typeName = obj.typeName ?? '';
      if (field.name === 'name') return typeName || null;
      if (field.name === 'kind') {
        if (ENUM_TYPES[typeName]) return 'ENUM';
        if (typeName.endsWith('Input')) return 'INPUT_OBJECT';
        return 'OBJECT';
      }
      if (field.name === 'description') return null;
      if (field.name === 'fields') {
        const names = TYPE_FIELDS[typeName];
        if (!names) return null;
        return names.filter((name) => name !== '__typename').map((name) => ({ __type: '__Field', payload: { name } }));
      }
      if (field.name === 'enumValues') {
        const values = ENUM_TYPES[typeName];
        if (!values) return null;
        return values.map((name) => ({ __type: '__EnumValue', payload: { name } }));
      }
      if (field.name === 'possibleTypes') return [];
      if (field.name === 'inputFields') return [];
      if (field.name === 'ofType') return null;
      if (field.name === 'specifiedByURL') return null;
      break;
    }
    case '__Field': {
      if (field.name === 'name') return obj.payload?.name ?? '';
      if (field.name === 'description') return null;
      if (field.name === 'args') return [];
      if (field.name === 'type') return { __type: '__Type', typeName: 'String' };
      if (field.name === 'isDeprecated') return false;
      if (field.name === 'deprecationReason') return null;
      break;
    }
    case '__EnumValue': {
      if (field.name === 'name') return obj.payload?.name ?? '';
      if (field.name === 'description') return null;
      if (field.name === 'isDeprecated') return false;
      if (field.name === 'deprecationReason') return null;
      break;
    }
    case '__Schema': {
      if (field.name === 'queryType') return { __type: '__Type', typeName: 'Query' };
      if (field.name === 'mutationType') return { __type: '__Type', typeName: 'Mutation' };
      if (field.name === 'subscriptionType') return null;
      if (field.name === 'types') return Object.keys(TYPE_FIELDS).map((name) => ({ __type: '__Type', typeName: name }));
      if (field.name === 'directives') return [];
      break;
    }
    case 'Payload': {
      const value = obj.payload?.[field.name];
      return value === undefined ? null : value;
    }
  }
  if (field.name === '__typename') return obj.__type;
  // Connections share one implementation.
  if (obj.connection) {
    const { nodes, total, startIndex } = obj.connection;
    if (field.name === 'nodes') return nodes;
    if (field.name === 'totalCount') return total;
    if (field.name === 'pageInfo') {
      return {
        __type: 'PageInfo',
        payload: {
          hasNextPage: startIndex + nodes.length < total,
          hasPreviousPage: startIndex > 0,
          startCursor: nodes.length > 0 ? cursorFor(startIndex) : null,
          endCursor: nodes.length > 0 ? cursorFor(startIndex + nodes.length - 1) : null,
        },
      };
    }
    if (field.name === 'edges') {
      return nodes.map((node, index) => ({ __type: 'Edge', payload: { cursor: cursorFor(startIndex + index) }, issue: node.issue, pull: node.pull, comment: node.comment, repo: node.repo, nodeRef: node }));
    }
  }
  if (obj.__type === 'PageInfo' && obj.payload) {
    const value = obj.payload[field.name];
    return value === undefined ? null : value;
  }
  if (obj.__type === 'Edge') {
    if (field.name === 'cursor') return obj.payload?.cursor ?? '';
    if (field.name === 'node') return (obj as unknown as { nodeRef?: GqlObject }).nodeRef ?? null;
  }
  exec.errors.push({ message: `Field '${field.name}' doesn't exist on type '${obj.__type}'` });
  return null;
}

function executeSelections(obj: GqlObject, selections: GqlSelection[], exec: GqlExec): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const selection of selections) {
    if (selection.kind === 'fragment') {
      const fragment = exec.doc.fragments.get(selection.name);
      if (fragment && fragment.typeCondition === obj.__type) Object.assign(out, executeSelections(obj, fragment.selections, exec));
      continue;
    }
    if (selection.kind === 'inline') {
      if (selection.typeCondition === null || selection.typeCondition === obj.__type) {
        Object.assign(out, executeSelections(obj, selection.selections, exec));
      }
      continue;
    }
    const field = selection.field;
    const key = field.alias ?? field.name;
    let value: unknown;
    try {
      value = resolveField(obj, field, exec);
    } catch (err) {
      exec.errors.push({ message: err instanceof Error ? err.message : String(err) });
      value = null;
    }
    if (value !== null && typeof value === 'object' && !Array.isArray(value) && field.selections.length > 0) {
      value = executeSelections(value as GqlObject, field.selections, exec);
    } else if (Array.isArray(value) && field.selections.length > 0) {
      value = value.map((entry) => (entry !== null && typeof entry === 'object' ? executeSelections(entry as GqlObject, field.selections, exec) : entry));
    }
    out[key] = value === undefined ? null : value;
  }
  return out;
}

function executeOperation(operation: GqlOperation, doc: GqlDocument, variables: Record<string, unknown>): { data: Record<string, unknown>; errors?: Array<{ message: string }> } {
  const exec: GqlExec = { variables, errors: [], doc };
  const root: GqlObject = { __type: operation.type === 'mutation' ? 'Mutation' : 'Query' };
  const data = executeSelections(root, operation.selections, exec);
  return exec.errors.length > 0 ? { data, errors: exec.errors } : { data };
}

async function handleGraphQL(req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (!authed(req)) {
    sendJson(res, 401, { message: 'Requires authentication' });
    return;
  }
  const raw = await readBody(req);
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.toString('utf8'));
  } catch {
    sendJson(res, 400, { errors: [{ message: 'Malformed JSON body' }] });
    return;
  }
  const runOne = (entry: unknown): unknown => {
    if (!isRecord(entry) || typeof entry.query !== 'string') return { errors: [{ message: 'A query document is required' }] };
    const variables = isRecord(entry.variables) ? entry.variables : {};
    let doc: GqlDocument;
    try {
      doc = new GqlParser(entry.query).parseDocument();
    } catch (err) {
      return { errors: [{ message: err instanceof Error ? err.message : 'parse error' }] };
    }
    if (doc.operations.length === 0) return { errors: [{ message: 'No operation found' }] };
    const operationName = typeof entry.operationName === 'string' ? entry.operationName : null;
    const chosen = operationName ? doc.operations.filter((op) => op.name === operationName) : doc.operations;
    if (chosen.length === 1) return executeOperation(chosen[0], doc, variables);
    return chosen.map((op) => executeOperation(op, doc, variables));
  };
  if (Array.isArray(parsed)) {
    sendJson(res, 200, parsed.map((entry) => runOne(entry)));
    return;
  }
  const result = runOne(parsed);
  if (Array.isArray(result)) {
    sendJson(res, 200, result);
    return;
  }
  sendJson(res, 200, result);
}

// ---------------------------------------------------------------------------
// MCP: JSON-RPC 2.0 over streamable HTTP.

const MCP_REVISIONS = ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];
const MCP_SERVER_INFO = { name: 'git-forge', version: '1.0.0' };

interface McpTool {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  required: string[];
  run: (args: Record<string, unknown>) => Record<string, unknown>;
}

function toolSchema(properties: Record<string, unknown>, required: string[]): Record<string, unknown> {
  return { type: 'object', properties, required, additionalProperties: true };
}

function repoForTool(args: Record<string, unknown>): Repo {
  const owner = str(args.owner, viewer());
  const name = str(args.repo, str(args.name));
  const repo = name ? findRepo(owner, name) : null;
  if (!repo) throw new Error(`repository ${owner}/${name} not found`);
  return repo;
}

function restShapeRepo(repo: Repo): Record<string, unknown> {
  return {
    id: repo.id,
    name: repo.name,
    full_name: `${repo.owner ?? viewer()}/${repo.name}`,
    private: repo.isPrivate,
    description: repo.description,
    default_branch: repo.defaultBranch,
    owner: { login: repo.owner ?? viewer(), id: 1000, type: 'User' },
  };
}

function restShapeIssue(repo: Repo, issue: Issue): Record<string, unknown> {
  return {
    id: issue.id,
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    labels: issue.labels.map((name) => ({ name, color: repo.labels.get(name)?.color ?? 'ededed' })),
    user: { login: viewer() },
    comments: issue.comments.length,
  };
}

function restShapePull(repo: Repo, pull: Pull): Record<string, unknown> {
  return {
    id: pull.id,
    number: pull.number,
    state: pull.state,
    title: pull.title,
    body: pull.body,
    merged: pull.merged,
    merged_at: pull.mergedAt,
    merge_commit_sha: pull.mergeCommitSha,
    head: { ref: pull.head, sha: repo.refs.get(`refs/heads/${pull.head}`) ?? '' },
    base: { ref: pull.base, sha: repo.refs.get(`refs/heads/${pull.base}`) ?? '' },
    user: { login: viewer() },
  };
}

const MCP_TOOLS: McpTool[] = [
  {
    name: 'create_repo',
    description: 'Create a new repository for the authenticated user.',
    inputSchema: toolSchema({ name: { type: 'string', description: 'The repository name' }, description: { type: 'string' }, private: { type: 'boolean' } }, ['name']),
    required: ['name'],
    run: (args) => {
      const name = str(args.name);
      const existing = findRepoByNameOnly(name);
      if (existing) return restShapeRepo(existing);
      const repo = createRepoRecord(name, Boolean(args.private), str(args.description), 'main');
      return restShapeRepo(repo);
    },
  },
  {
    name: 'get_repo',
    description: 'Get a repository by owner and name.',
    inputSchema: toolSchema({ owner: { type: 'string' }, repo: { type: 'string' } }, ['owner', 'repo']),
    required: ['owner', 'repo'],
    run: (args) => restShapeRepo(repoForTool(args)),
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    inputSchema: toolSchema({ owner: { type: 'string' }, repo: { type: 'string' }, title: { type: 'string' }, body: { type: 'string' } }, ['owner', 'repo', 'title']),
    required: ['owner', 'repo', 'title'],
    run: (args) => {
      const repo = repoForTool(args);
      const labels = Array.isArray(args.labels) ? args.labels.map((entry) => (typeof entry === 'string' ? entry : isRecord(entry) ? str(entry.name) : '')).filter(Boolean) : [];
      for (const name of labels) if (!repo.labels.has(name)) throw new Error(`label "${name}" does not exist`);
      const issue = createIssueRecord(repo, str(args.title), str(args.body), labels);
      return restShapeIssue(repo, issue);
    },
  },
  {
    name: 'list_issues',
    description: 'List issues in a repository, optionally filtered by state.',
    inputSchema: toolSchema({ owner: { type: 'string' }, repo: { type: 'string' }, state: { type: 'string', enum: ['open', 'closed', 'all'] } }, ['owner', 'repo']),
    required: ['owner', 'repo'],
    run: (args) => {
      const repo = repoForTool(args);
      const state = str(args.state, 'open');
      let list = [...repo.issues.values()];
      if (state === 'open' || state === 'closed') list = list.filter((issue) => issue.state === state);
      list.sort((a, b) => b.seq - a.seq);
      return { issues: list.map((issue) => restShapeIssue(repo, issue)), total_count: list.length };
    },
  },
  {
    name: 'create_pull_request',
    description: 'Create a pull request from a head branch to a base branch.',
    inputSchema: toolSchema(
      { owner: { type: 'string' }, repo: { type: 'string' }, title: { type: 'string' }, head: { type: 'string' }, base: { type: 'string' }, body: { type: 'string' } },
      ['owner', 'repo', 'title', 'head', 'base'],
    ),
    required: ['owner', 'repo', 'title', 'head', 'base'],
    run: (args) => {
      const repo = repoForTool(args);
      const head = str(args.head).includes(':') ? str(args.head).split(':').pop()! : str(args.head);
      const base = str(args.base, repo.defaultBranch);
      if (!repo.refs.has(`refs/heads/${head}`)) throw new Error(`head branch "${head}" does not exist`);
      if (!repo.refs.has(`refs/heads/${base}`)) throw new Error(`base branch "${base}" does not exist`);
      const pull = createPullRecord(repo, str(args.title), str(args.body), head, base);
      return restShapePull(repo, pull);
    },
  },
  {
    name: 'merge_pull_request',
    description: 'Merge a pull request (squash by default).',
    inputSchema: toolSchema(
      { owner: { type: 'string' }, repo: { type: 'string' }, pull_number: { type: 'number' }, merge_method: { type: 'string', enum: ['merge', 'squash', 'rebase'] } },
      ['owner', 'repo', 'pull_number'],
    ),
    required: ['owner', 'repo', 'pull_number'],
    run: (args) => {
      const repo = repoForTool(args);
      const pull = repo.pulls.get(num(args.pull_number));
      if (!pull) throw new Error(`pull request ${num(args.pull_number)} not found`);
      if (!pull.merged) {
        const result = mergePull(repo, pull, str(args.merge_method, 'squash').toLowerCase() === 'merge' ? 'merge' : 'squash');
        if (result === 'conflict') throw new Error('pull request has conflicts that must be resolved');
        if (result === 'gone') throw new Error('a branch is missing');
      }
      return { ...restShapePull(repo, pull), sha: pull.mergeCommitSha, merged: true, message: 'Pull Request successfully merged' };
    },
  },
];

const MCP_TOOL_LIST_JSON = JSON.stringify({
  tools: MCP_TOOLS.map((tool) => ({ name: tool.name, description: tool.description, inputSchema: tool.inputSchema })),
});

function findTool(name: string): McpTool | null {
  const wanted = name.toLowerCase();
  for (const tool of MCP_TOOLS) {
    if (tool.name.toLowerCase() === wanted || wanted.endsWith(`__${tool.name.toLowerCase()}`) || wanted.endsWith(`_${tool.name.toLowerCase()}`)) return tool;
  }
  return null;
}

interface RpcOutcome {
  status: number;
  body: Record<string, unknown> | null;
}

function rpcError(id: unknown, code: number, message: string): Record<string, unknown> {
  return { jsonrpc: '2.0', id: id === undefined ? null : id, error: { code, message } };
}

function handleRpc(request: Record<string, unknown>): RpcOutcome {
  const id = request.id;
  const method = str(request.method);
  const params = isRecord(request.params) ? request.params : {};
  const isNotification = id === undefined || id === null;

  if (method === 'server/discover') {
    return {
      status: 200,
      body: {
        jsonrpc: '2.0',
        id,
        result: {
          resultType: 'complete',
          supportedVersions: MCP_REVISIONS,
          capabilities: { tools: { listChanged: false } },
          serverInfo: MCP_SERVER_INFO,
          instructions: 'A GitHub-compatible git forge: repositories, issues and pull requests.',
        },
      },
    };
  }
  if (method === 'initialize') {
    const requested = str(params.protocolVersion, '2025-11-25');
    const protocolVersion = MCP_REVISIONS.includes(requested) ? requested : '2025-11-25';
    return {
      status: 200,
      body: {
        jsonrpc: '2.0',
        id,
        result: { protocolVersion, capabilities: { tools: { listChanged: false } }, serverInfo: MCP_SERVER_INFO },
      },
    };
  }
  if (method.startsWith('notifications/')) {
    return { status: 202, body: null };
  }
  if (method === 'ping') {
    return { status: 200, body: { jsonrpc: '2.0', id, result: {} } };
  }
  if (method === 'tools/list') {
    // Byte-for-byte stable: the list is a pre-serialized constant.
    return { status: 200, body: { jsonrpc: '2.0', id, result: JSON.parse(MCP_TOOL_LIST_JSON) as Record<string, unknown> } };
  }
  if (method === 'tools/call') {
    const name = str(params.name);
    const tool = name ? findTool(name) : null;
    if (!tool) {
      return { status: 200, body: rpcError(id, -32602, `Unknown tool: ${name || '(missing)'}`) };
    }
    const args = isRecord(params.arguments) ? params.arguments : {};
    // The suite maps canonical arguments onto the schema's property names and may fill
    // full_name; accept owner/repo split out of full_name too.
    const effective: Record<string, unknown> = { ...args };
    if (typeof effective.full_name === 'string' && (!effective.owner || !effective.repo)) {
      const [ownerPart, repoPart] = (effective.full_name as string).split('/');
      if (ownerPart && repoPart) {
        effective.owner = effective.owner ?? ownerPart;
        effective.repo = effective.repo ?? repoPart;
      }
    }
    const missing = tool.required.filter((key) => effective[key] === undefined || effective[key] === null || effective[key] === '');
    if (missing.length > 0) {
      return { status: 200, body: rpcError(id, -32602, `Missing required argument(s): ${missing.join(', ')}`) };
    }
    try {
      const result = tool.run(effective);
      return {
        status: 200,
        body: {
          jsonrpc: '2.0',
          id,
          result: {
            content: [{ type: 'text', text: JSON.stringify(result) }],
            structuredContent: result,
            isError: false,
          },
        },
      };
    } catch (err) {
      return {
        status: 200,
        body: {
          jsonrpc: '2.0',
          id,
          result: {
            content: [{ type: 'text', text: err instanceof Error ? err.message : String(err) }],
            isError: true,
          },
        },
      };
    }
  }
  if (isNotification) return { status: 202, body: null };
  return { status: 200, body: rpcError(id, -32601, `Method not found: ${method}`) };
}

async function handleMcp(req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (req.method === 'GET' || req.method === 'DELETE') {
    sendJson(res, 405, { message: 'Method Not Allowed' });
    return;
  }
  if (!authed(req)) {
    sendJson(res, 401, { jsonrpc: '2.0', id: null, error: { code: -32001, message: 'Unauthorized' } });
    return;
  }
  const raw = await readBody(req);
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.toString('utf8'));
  } catch {
    sendJson(res, 400, rpcError(null, -32700, 'Parse error'));
    return;
  }
  if (Array.isArray(parsed)) {
    const results: unknown[] = [];
    let status = 200;
    for (const entry of parsed) {
      if (!isRecord(entry)) {
        results.push(rpcError(null, -32600, 'Invalid request'));
        continue;
      }
      const outcome = handleRpc(entry);
      if (outcome.body) results.push(outcome.body);
      status = outcome.status === 202 ? status : outcome.status;
    }
    sendJson(res, status, results);
    return;
  }
  if (!isRecord(parsed)) {
    sendJson(res, 400, rpcError(null, -32600, 'Invalid request'));
    return;
  }
  const outcome = handleRpc(parsed);
  if (outcome.body === null) {
    res.writeHead(outcome.status, { 'x-github-request-id': `req-${++requestCounter}` });
    res.end();
    return;
  }
  const headers: Record<string, string> = {};
  if (str(parsed.method) === 'initialize') headers['mcp-session-id'] = 'forge-session-1';
  sendJson(res, outcome.status, outcome.body, headers);
}

// ---------------------------------------------------------------------------
// the app

export function createApp(): Server {
  return createServer((req: IncomingMessage, res: ServerResponse) => {
    (async (): Promise<void> => {
      const url = new URL(req.url ?? '/', 'http://entry');
      const path = url.pathname;
      const method = req.method ?? 'GET';

      if (method === 'GET' && path === '/healthz') {
        sendJson(res, 200, { ok: true });
        return;
      }

      if (path === '/mcp') {
        await handleMcp(req, res);
        return;
      }

      if (path === '/api/graphql') {
        if (method !== 'POST') {
          sendJson(res, 405, { message: 'Method Not Allowed' });
          return;
        }
        await handleGraphQL(req, res);
        return;
      }

      if (path === '/api/v3' || path.startsWith('/api/v3/')) {
        let body: Record<string, unknown> | null = null;
        let bodyError = false;
        if (method === 'POST' || method === 'PATCH' || method === 'PUT' || method === 'DELETE') {
          const raw = await readBody(req);
          if (raw.length > 0) {
            try {
              const parsedBody: unknown = JSON.parse(raw.toString('utf8'));
              body = isRecord(parsedBody) ? parsedBody : {};
            } catch {
              bodyError = true;
            }
          } else {
            body = {};
          }
        }
        await handleRest({ req, res, url, body, bodyError });
        return;
      }

      // git smart HTTP: /{owner}/{repo}.git/...
      const gitMatch = /^\/([^/]+)\/([^/]+)\.git(\/.*)?$/.exec(path);
      if (gitMatch) {
        await handleGit(req, res, decodeURIComponent(gitMatch[1]), decodeURIComponent(gitMatch[2]), gitMatch[3] ?? '', url);
        return;
      }

      sendJson(res, 404, { message: 'Not Found' });
    })().catch(() => {
      if (!res.headersSent) sendJson(res, 500, { message: 'Internal Server Error' });
      else res.end();
    });
  });
}
