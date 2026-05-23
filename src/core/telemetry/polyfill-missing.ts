import type { AnyTelemetryEvent, Session, StorageAdapter } from "../types.js";
import { emit } from "./hooks.js";

/** Default grace window before emitting polyfill_missing. */
export const POLYFILL_MISSING_GRACE_MS = 60_000;

/**
 * Per-adapter helper. Checks whether a Chromium-bound session has gone past
 * the grace window without registering its polyfill key, and emits
 * `polyfill_missing` once. The caller passes a Set used to dedupe within
 * the process — restarts re-arm the set, which is fine.
 *
 * Caller has already loaded the session; pass it in to avoid a redundant
 * storage read.
 */
export async function maybeEmitPolyfillMissing(opts: {
  storage: StorageAdapter;
  session: Session;
  ip: string;
  emitted: Set<string>;
  graceMs?: number;
  onEvent?: (event: AnyTelemetryEvent) => void;
}): Promise<void> {
  if (!opts.onEvent) return;
  if (opts.session.tier !== "dbsc") return;
  if (opts.emitted.has(opts.session.id)) return;
  const grace = opts.graceMs ?? POLYFILL_MISSING_GRACE_MS;
  if (Date.now() - opts.session.createdAt < grace) return;

  const boundKey = await opts.storage.getBoundKey(opts.session.id, "bound");
  if (boundKey) return;

  opts.emitted.add(opts.session.id);
  emit(opts.onEvent, {
    type: "polyfill_missing",
    sessionId: opts.session.id,
    tier: "dbsc",
    timestamp: Date.now(),
    ip: opts.ip,
  });
}
