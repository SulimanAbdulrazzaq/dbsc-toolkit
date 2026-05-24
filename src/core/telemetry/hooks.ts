import type { AnyTelemetryEvent } from "../types.js";

export type EventHandler = (event: AnyTelemetryEvent) => void | Promise<void>;

export function emit(handler: EventHandler | undefined, event: AnyTelemetryEvent): void {
  if (!handler) return;
  try {
    const result = handler(event);
    // Sync handler that throws is caught below. Async handler that rejects
    // would otherwise produce an unhandled promise rejection — same
    // contract here: telemetry must never crash or destabilize the auth
    // path. The rejection is dropped silently. Ops teams that want
    // visibility into telemetry-handler failures should add their own
    // try/catch inside the handler.
    if (result && typeof (result as Promise<unknown>).catch === "function") {
      (result as Promise<unknown>).catch(() => {
        /* swallow — same reasoning as the sync catch below */
      });
    }
  } catch {
    // telemetry failures must never crash the auth path
  }
}
