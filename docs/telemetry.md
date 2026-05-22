# Telemetry

The library emits typed events for every protocol-significant action. There is no logger dependency — you wire events into your existing observability stack via the `onEvent` callback.

## Wiring up

Pass `onEvent` in the `createDbsc` config (or directly to `dbsc()` if you mount the raw middleware):

```ts
const dbsc = createDbsc({
  storage,
  onEvent: (event) => {
    logger.info({ dbsc: event });
    metrics.increment(`dbsc.${event.type}`, { tier: event.tier });
    if (event.type === "session_stolen") {
      alerting.trigger("dbsc.session_stolen", {
        sessionId: event.sessionId,
        ip: event.ip,
      });
    }
  },
});
dbsc.install(app);
```

Every event carries the same base fields:

```ts
interface TelemetryEvent {
  sessionId: string;
  tier: ProtectionTier;
  timestamp: number;   // Date.now() at emit time
}
```

Plus event-specific fields described below.

## Event types

### `registration`

Fires after a successful registration JWS verification. Session tier is now `"dbsc"`.

```ts
interface RegistrationEvent extends TelemetryEvent {
  type: "registration";
  algorithm: string;   // "ES256" or "RS256"
  ip: string;
}
```

Useful for: counting new DBSC sessions, breaking down by algorithm, geographic distribution by IP.

### `refresh`

Fires after a successful refresh. The bound cookie has been re-issued, `lastRefreshAt` updated.

```ts
interface RefreshEvent extends TelemetryEvent {
  type: "refresh";
  ip: string;
}
```

Useful for: refresh rate, IP changes mid-session (potential session-jumping detection), refresh latency tracking.

### `verification_failure`

Fires whenever JWS verification or challenge validation fails on either registration or refresh.

```ts
interface VerificationFailureEvent extends TelemetryEvent {
  type: "verification_failure";
  reason: string;   // ErrorCode value, e.g. "SIGNATURE_INVALID", "CHALLENGE_EXPIRED"
  ip: string;
}
```

Most common reasons:

- `SIGNATURE_INVALID` — JWS signature does not match stored JWK. Either a stolen cookie attack or a hardware-key change.
- `JTI_MISMATCH` — challenge in JWS does not match what the server issued. Replay attempt or stale browser state.
- `CHALLENGE_CONSUMED` — challenge already used. Concurrent refresh race or replay.
- `CHALLENGE_EXPIRED` — challenge older than 5 minutes. Slow client or clock drift.
- `MALFORMED_JWS` — bad JWS structure. Buggy client or middleware tampering.

A spike in `SIGNATURE_INVALID` from a single IP is a strong signal of cookie theft in progress.

### `session_stolen`

Fires when refresh fails AND a bound key exists for the session. The cookie was valid but the proof was not — meaning someone has the cookie but not the device key.

```ts
interface SessionStolenEvent extends TelemetryEvent {
  type: "session_stolen";
  ip: string;
}
```

This is the single most actionable event. Wire it to:

- Force-logout the session immediately (`storage.revokeSession(sessionId)`).
- Notify the user via email/SMS/in-app alert.
- Page on-call if the rate exceeds N/minute.
- Trigger a security review of the affected user account.

### `tier_change`

Fires when a session moves between tiers — for example when the bound polyfill activates after a native DBSC attempt times out, or when a refresh failure demotes a tier to `"none"`.

```ts
interface TierChangeEvent extends TelemetryEvent {
  type: "tier_change";
  from: ProtectionTier;
  to: ProtectionTier;
  reason: string;
}
```

The library does not auto-emit this event from every internal transition; it is the canonical shape for applications that want to track promotions or demotions explicitly. Useful for: dashboards on what fraction of sessions land at each tier, identifying browsers/platforms where the polyfill carries more traffic than expected.

## OpenTelemetry mapping

The library does not depend on OpenTelemetry, but the event shapes map cleanly onto OTel attributes. Suggested span/metric attribute names:

```
dbsc.session_id    = event.sessionId
dbsc.tier          = event.tier
dbsc.event_type    = event.type
dbsc.ip            = event.ip
dbsc.algorithm     = event.algorithm    (registration only)
dbsc.failure_reason = event.reason      (verification_failure only)
dbsc.tier_from     = event.from         (tier_change only)
dbsc.tier_to       = event.to           (tier_change only)
```

Example with OTel:

```ts
import { metrics, trace } from "@opentelemetry/api";

const meter = metrics.getMeter("dbsc-toolkit");
const registrationCounter = meter.createCounter("dbsc.registration.count");
const refreshHistogram = meter.createHistogram("dbsc.refresh.duration_ms");
const failureCounter = meter.createCounter("dbsc.verification_failure.count");
const stolenCounter = meter.createCounter("dbsc.session_stolen.count");

const dbsc = createDbsc({
  storage,
  onEvent: (event) => {
    const attrs = { tier: event.tier };
    switch (event.type) {
      case "registration":
        registrationCounter.add(1, { ...attrs, algorithm: event.algorithm });
        break;
      case "refresh":
        // measure refresh duration in your route handler around handleRefresh
        break;
      case "verification_failure":
        failureCounter.add(1, { ...attrs, reason: event.reason });
        break;
      case "session_stolen":
        stolenCounter.add(1, attrs);
        // also fire a span event for trace correlation
        trace.getActiveSpan()?.addEvent("dbsc.session_stolen", { sessionId: event.sessionId });
        break;
    }
  },
});
dbsc.install(app);
```

## Suggested counters and histograms

For dashboards:

| Metric | Type | Labels |
|--------|------|--------|
| `dbsc.registration.count` | counter | tier, algorithm |
| `dbsc.refresh.count` | counter | tier |
| `dbsc.refresh.duration_ms` | histogram | tier |
| `dbsc.verification_failure.count` | counter | tier, reason |
| `dbsc.session_stolen.count` | counter | (none — should always be near zero) |
| `dbsc.tier_distribution` | gauge | tier — sample periodically from storage |
| `dbsc.tier_change.count` | counter | from, to, reason |

## Alerting thresholds (starting points)

| Condition | Severity |
|-----------|----------|
| `dbsc.session_stolen.count` > 0 in 5 min | High |
| `dbsc.verification_failure.count{reason="SIGNATURE_INVALID"}` rate > 10/min from single IP | Medium |
| `dbsc.tier_distribution{tier="dbsc"}` drops by 50% week-over-week | Medium (Chrome behavior changed?) |
| `dbsc.refresh.duration_ms{p99}` > 500ms | Low (storage latency issue) |

Tune to your traffic patterns. The first two are the ones that actually catch attacks.

## Audit logging

For applications with strict audit requirements (financial, healthcare), emit every event to a write-ahead log:

```ts
onEvent: (event) => {
  await auditLog.append({
    type: event.type,
    sessionId: event.sessionId,
    tier: event.tier,
    timestamp: event.timestamp,
    ip: event.ip,
    payload: event,
  });
}
```

The Postgres storage adapter ships with a `dbsc_audit_log` table that can serve as this WAL.
