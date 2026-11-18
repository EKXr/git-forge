// Entry point for the forge clone.
//
// My job here is small but strict: boot the app on a kernel-chosen
// port, tell the surrounding harness where that port is, then stay
// alive until the harness says the run is finished. Everything else
// (routing, storage, the actual forge behaviour) lives in app.ts.

import { createApp } from './app.ts';

// Pause helper built on the global timer — no imports needed.
function pause(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

// Normalise the harness base URL: trim surrounding whitespace first
// (env values copied from a shell often carry a stray space), then
// drop any run of trailing slashes so that `${base}/register` never
// ends up with a doubled separator. A value that is only slashes
// collapses to the empty string and is rejected by the caller.
function cleanBaseUrl(raw: string | undefined): string {
  if (raw === undefined) {
    return '';
  }
  const trimmed = raw.trim();
  let end = trimmed.length;
  while (end > 0 && trimmed.charAt(end - 1) === '/') {
    end -= 1;
  }
  return trimmed.slice(0, end);
}

const REQUEST_TIMEOUT_MS = 30000;
const FIRST_DELAY_MS = 250;
const MAX_DELAY_MS = 2000;

// Exponential backoff as a tiny stateful tracker, so each retry loop
// reads as "wait, then step" instead of juggling a bare number.
// Schedule: 250ms, 500ms, 1000ms, then pinned at the 2000ms ceiling.
// A fresh tracker per phase means the polling phase does not inherit
// a maxed-out delay from a rough registration phase.
class Backoff {
  private current: number;

  constructor() {
    this.current = FIRST_DELAY_MS;
  }

  async wait(): Promise<void> {
    const delay = this.current;
    const doubled = this.current * 2;
    this.current = doubled > MAX_DELAY_MS ? MAX_DELAY_MS : doubled;
    await pause(delay);
  }
}

async function registerWithHarness(base: string, port: number): Promise<void> {
  const backoff = new Backoff();
  for (;;) {
    let shouldRetry = false;
    try {
      const response = await fetch(`${base}/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ port }),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });

      if (response.status === 200 || response.status === 409) {
        // 200: fresh registration. 409: an earlier attempt already
        // registered this run — that is success, not a conflict.
        console.log(`registered with harness on port ${port} (status ${response.status})`);
        return;
      }

      if (response.status === 400 || response.status === 405) {
        // The harness is rejecting the shape of the request itself.
        // Retrying an identical payload cannot fix that, so bail out.
        throw new Error(`harness refused registration with status ${response.status}`);
      }

      console.log(`registration attempt got status ${response.status}; will retry`);
      shouldRetry = true;
    } catch (err) {
      // A refusal error thrown above must not be swallowed by the
      // retry path — rethrow anything that is not a fetch failure.
      if (err instanceof Error && err.message.startsWith('harness refused registration')) {
        throw err;
      }
      console.log(`registration attempt failed (${String(err)}); will retry`);
      shouldRetry = true;
    }

    if (shouldRetry) {
      await backoff.wait();
    }
  }
}

async function waitUntilHarnessIsDone(base: string): Promise<void> {
  const backoff = new Backoff();
  for (;;) {
    let finished = false;
    try {
      const response = await fetch(`${base}/done`, {
        method: 'GET',
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      if (response.ok) {
        const payload: unknown = await response.json();
        if (
          payload !== null &&
          typeof payload === 'object' &&
          (payload as { done?: unknown }).done === true
        ) {
          finished = true;
        }
      } else {
        console.log(`done-check answered status ${response.status}; will keep waiting`);
      }
    } catch (err) {
      // Any failure here — network blip, timeout, malformed JSON —
      // just means "not done yet". We must never exit early.
      console.log(`done-check failed (${String(err)}); will keep waiting`);
    }

    if (finished) {
      return;
    }
    await backoff.wait();
  }
}

async function main(): Promise<void> {
  const base = cleanBaseUrl(process.env.MAKEFUN_ENV_URL);
  if (base.length === 0) {
    console.error('error: MAKEFUN_ENV_URL is not set (or is empty); cannot register with the harness');
    process.exit(1);
  }

  const server = createApp();

  // Port 0 asks the kernel for a free ephemeral port. Binding a fixed
  // port here would collide with the harness itself.
  await new Promise<void>((resolve) => {
    server.listen(0, () => {
      resolve();
    });
  });

  const address = server.address();
  if (address === null || typeof address !== 'object' || typeof address.port !== 'number') {
    throw new Error('server did not report a usable listening port');
  }
  const port = address.port;
  if (port <= 0 || port > 65535) {
    throw new Error(`server reported an out-of-range port: ${port}`);
  }
  console.log(`forge listening on ephemeral port ${port}`);

  // Whatever happens after listen() — a refused registration, a
  // polling blow-up — the server must be closed before we propagate,
  // otherwise a failed run leaves a listening socket behind.
  try {
    await registerWithHarness(base, port);
    await waitUntilHarnessIsDone(base);
  } catch (err) {
    await new Promise<void>((resolve) => {
      server.close(() => {
        resolve();
      });
    });
    throw err;
  }

  console.log('harness signalled done; shutting down');
  await new Promise<void>((resolve) => {
    server.close(() => {
      resolve();
    });
  });
}

main().then(
  () => {
    process.exit(0);
  },
  (err: unknown) => {
    console.error(`fatal: ${err instanceof Error ? err.stack ?? err.message : String(err)}`);
    process.exit(1);
  },
);
