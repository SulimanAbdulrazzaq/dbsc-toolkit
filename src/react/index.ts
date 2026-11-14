import { useSyncExternalStore } from "react";
import { startDbsc, getDbscClient, type StartDbscOptions } from "../client/start.js";
import type { BoundDbscOutcome } from "../client/index.js";

export type DbscStatus = "starting" | "bound" | "unbound" | "error";

export interface DbscState {
  /**
   * `starting` until the first registration run ends; `bound` when the
   * device holds a key (native or polyfill); `unbound` when no one is
   * signed in; `error` when registration threw.
   */
  status: DbscStatus;
  /** `dbsc` (hardware key), `bound` (Web Crypto polyfill), or `null`. */
  tier: "dbsc" | "bound" | null;
  /** Why the browser fell back or lost its key, when it did (e.g. `local-key-missing`). */
  skipReason: string | undefined;
  /** The raw outcome from the client SDK. */
  outcome: BoundDbscOutcome | null;
}

function toState(outcome: BoundDbscOutcome | null): DbscState {
  if (!outcome) return { status: "starting", tier: null, skipReason: undefined, outcome };
  switch (outcome.phase) {
    case "native-dbsc":
    case "polyfill-bound":
      return { status: "bound", tier: outcome.tier, skipReason: outcome.skipReason, outcome };
    case "unbound":
      return { status: "unbound", tier: null, skipReason: undefined, outcome };
    default:
      return { status: "error", tier: null, skipReason: undefined, outcome };
  }
}

// One state object per outcome, so useSyncExternalStore sees a stable snapshot.
const states = new WeakMap<BoundDbscOutcome, DbscState>();
const STARTING = toState(null);

function snapshot(): DbscState {
  const outcome = getDbscClient()?.outcome ?? null;
  if (!outcome) return STARTING;
  let state = states.get(outcome);
  if (!state) {
    state = toState(outcome);
    states.set(outcome, state);
  }
  return state;
}

/**
 * Starts the client SDK (once per page) and returns its status. Requests made
 * with `fetch` are signed from then on.
 *
 *   const { status, tier } = useDbsc();
 *   if (status === "bound") ... // show "this device is protected"
 *
 * Options apply to the first call only, like `startDbsc()`. On the server it
 * renders as `starting` and does nothing.
 */
export function useDbsc(opts?: StartDbscOptions): DbscState {
  return useSyncExternalStore(
    (onChange) => startDbsc(opts).subscribe(onChange),
    snapshot,
    () => STARTING,
  );
}
