import { initBoundDbsc, stopBoundDbsc, type InitBoundDbscOptions, type BoundDbscOutcome } from "./index.js";
import { interceptFetch } from "./installFetchInterceptor.js";

const REGISTRATION_HEADERS = ["secure-session-registration", "sec-session-registration"];

export interface StartDbscOptions extends InitBoundDbscOptions {
  /**
   * Path prefixes whose same-origin requests carry a proof (for example
   * `["/api/"]`). Default: every same-origin request except the SDK's own
   * protocol calls. Cross-origin requests are never signed.
   */
  sign?: string[];
  /** Sign the query string too. Must match the server's `signQuery`. */
  signQuery?: boolean;
}

export interface DbscClient {
  /** Resolves with the outcome of the current registration run. */
  readonly ready: Promise<BoundDbscOutcome>;
  /** The latest outcome, or `null` while the first run is still going. */
  readonly outcome: BoundDbscOutcome | null;
  /** Called with every new outcome. Returns the unsubscribe function. */
  subscribe(listener: (outcome: BoundDbscOutcome) => void): () => void;
  /**
   * Runs registration again. The client does this by itself when a
   * same-origin response starts a binding (a login made with `fetch`), so
   * single-page apps rarely need it.
   */
  restart(): Promise<BoundDbscOutcome>;
  /** Removes the fetch interceptor and stops background refresh. */
  stop(): void;
}

let current: DbscClient | null = null;

/** The client `startDbsc()` created, if any. */
export function getDbscClient(): DbscClient | null {
  return current;
}

function protocolPaths(opts: InitBoundDbscOptions): string[] {
  return [
    opts.statePath ?? "/dbsc-bound/state",
    opts.challengePath ?? "/dbsc-bound/challenge",
    opts.registrationPath ?? "/dbsc-bound/registration",
    opts.refreshPath ?? "/dbsc-bound/refresh",
  ];
}

function validPrefix(prefix: string): boolean {
  return typeof prefix === "string" && prefix.startsWith("/") && !prefix.startsWith("//");
}

/**
 * The whole browser side in one call: registers the device key (native DBSC
 * or the Web Crypto polyfill), keeps it refreshed, and signs same-origin
 * `fetch` calls so `requireProof()` routes pass. Safe to call more than once;
 * later calls return the first client.
 *
 *   import { startDbsc } from "dbsc-toolkit/client";
 *   startDbsc();
 *
 * Without a bundler, load `/dbsc-client/auto.js` as a module script instead.
 */
export function startDbsc(opts: StartDbscOptions = {}): DbscClient {
  if (current) return current;
  const { sign, signQuery, ...init } = opts;
  const prefixes = sign?.filter(validPrefix);
  const skip = new Set(protocolPaths(init));
  const listeners = new Set<(outcome: BoundDbscOutcome) => void>();
  let outcome: BoundDbscOutcome | null = null;
  let running: Promise<BoundDbscOutcome> | null = null;

  const publish = (next: BoundDbscOutcome): void => {
    outcome = next;
    for (const fn of listeners) fn(next);
    if (typeof window !== "undefined" && typeof CustomEvent !== "undefined") {
      window.dispatchEvent(new CustomEvent("dbsc:change", { detail: next }));
    }
  };

  // Runs never overlap: a restart waits for the run in flight.
  const run = (): Promise<BoundDbscOutcome> => {
    const prior = running ?? Promise.resolve(null);
    running = prior
      .catch(() => null)
      .then(() => initBoundDbsc(init))
      .then((next) => {
        publish(next);
        return next;
      });
    return running;
  };

  let restartQueued = false;
  const uninstall = interceptFetch({
    shouldSign: (url) => {
      if (skip.has(url.pathname)) return false;
      if (!prefixes || prefixes.length === 0) return true;
      return prefixes.some((p) => url.pathname.startsWith(p));
    },
    onResponse: (res) => {
      // A login done with fetch starts a binding on its response. Register
      // right away instead of waiting for the next page load.
      if (restartQueued || !REGISTRATION_HEADERS.some((h) => res.headers.has(h))) return;
      restartQueued = true;
      queueMicrotask(() => {
        restartQueued = false;
        void client.restart();
      });
    },
    passThroughStreams: true,
    ...(signQuery !== undefined && { signQuery }),
  });

  const client: DbscClient = {
    get ready() {
      return running ?? run();
    },
    get outcome() {
      return outcome;
    },
    subscribe(listener) {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
    restart: () => run(),
    stop() {
      uninstall();
      stopBoundDbsc();
      listeners.clear();
      if (current === client) current = null;
    },
  };
  current = client;
  void run();
  return client;
}
