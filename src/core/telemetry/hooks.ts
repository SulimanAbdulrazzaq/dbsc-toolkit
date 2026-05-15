import type { AnyTelemetryEvent } from "../types.js";

export type EventHandler = (event: AnyTelemetryEvent) => void;

export function emit(handler: EventHandler | undefined, event: AnyTelemetryEvent): void {
  if (!handler) return;
  try {
    handler(event);
  } catch {
    // telemetry failures must never crash the auth path
  }
}
