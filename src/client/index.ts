import { clearKeyRecord, getKeyRecord, setKeyRecord } from "./keystore.js";
import { recordServerTime } from "./clockSync.js";

export { wrapFetch } from "./wrapFetch.js";
export type { WrapFetchOptions } from "./wrapFetch.js";

export interface InitBoundDbscOptions {
  statePath?: string;
  challengePath?: string;
  registrationPath?: string;
  refreshPath?: string;
  nativeProbeWindowMs?: number;
  refreshMarginMs?: number;
}

/**
 * Structured outcome of an `initBoundDbsc()` call. Every exit path resolves to
 * one of these so consumers can render a deterministic status without polling.
 *
 * - `native-dbsc`: Chromium 145+ registered natively. TPM-backed.
 * - `polyfill-bound`: the Web Crypto polyfill registered. `skipReason` is set
 *   when Chrome explicitly refused native registration (e.g. `quota_exceeded`).
 * - `unbound`: no session is present on the server. User is logged out, or the
 *   bound cookie points at a session row that no longer exists.
 * - `error`: an exception was thrown somewhere in the flow. `error` carries the
 *   message; consult the console for the underlying object.
 */
export type BoundDbscOutcome =
  | { phase: "native-dbsc"; tier: "dbsc" }
  | { phase: "polyfill-bound"; tier: "bound"; skipReason?: string | undefined }
  | { phase: "unbound" }
  | { phase: "error"; error: string };

interface StateUnbound {
  phase: "unbound";
  sessionId: null;
  nativeSkipped?: string[];
}

interface StateNeedsRegistration {
  phase: "needs-registration";
  sessionId: string;
  challenge: string;
  nativeSkipped?: string[];
}

interface StateBound {
  phase: "bound";
  sessionId: string;
  tier: "dbsc" | "bound";
  refreshIntervalMs: number;
  nativeSkipped?: string[];
}

type StateResponse = StateUnbound | StateNeedsRegistration | StateBound;

interface ResolvedOptions {
  statePath: string;
  challengePath: string;
  registrationPath: string;
  refreshPath: string;
  nativeProbeWindowMs: number;
  refreshMarginMs: number;
}

const DEFAULTS: ResolvedOptions = {
  statePath: "/dbsc-bound/state",
  challengePath: "/dbsc-bound/challenge",
  registrationPath: "/dbsc-bound/registration",
  refreshPath: "/dbsc-bound/refresh",
  nativeProbeWindowMs: 5000,
  refreshMarginMs: 5000,
};

let refreshTimer: ReturnType<typeof setTimeout> | null = null;

export async function initBoundDbsc(options: InitBoundDbscOptions = {}): Promise<BoundDbscOutcome> {
  if (typeof window === "undefined" || typeof indexedDB === "undefined") {
    return { phase: "error", error: "window or indexedDB unavailable" };
  }

  const cfg: ResolvedOptions = {
    statePath: options.statePath ?? DEFAULTS.statePath,
    challengePath: options.challengePath ?? DEFAULTS.challengePath,
    registrationPath: options.registrationPath ?? DEFAULTS.registrationPath,
    refreshPath: options.refreshPath ?? DEFAULTS.refreshPath,
    nativeProbeWindowMs: options.nativeProbeWindowMs ?? DEFAULTS.nativeProbeWindowMs,
    refreshMarginMs: options.refreshMarginMs ?? DEFAULTS.refreshMarginMs,
  };

  try {
    const state = await fetchState(cfg.statePath);

    if (state.phase === "unbound") {
      await clearKeyRecord().catch(() => {});
      return { phase: "unbound" };
    }

    if (state.phase === "bound") {
      if (state.tier === "dbsc") return { phase: "native-dbsc", tier: "dbsc" };
      const rec = await getKeyRecord().catch(() => null);
      if (!rec || rec.sessionId !== state.sessionId) {
        await clearKeyRecord().catch(() => {});
        const fresh = await fetchState(cfg.statePath);
        if (fresh.phase === "needs-registration") {
          await runRegistration(fresh.sessionId, fresh.challenge, cfg);
          scheduleRefresh(cfg, state.refreshIntervalMs);
          return outcomeFromSkip("polyfill-bound", fresh.nativeSkipped);
        }
        if (fresh.phase === "bound" && fresh.tier === "dbsc") {
          return { phase: "native-dbsc", tier: "dbsc" };
        }
        return { phase: "polyfill-bound", tier: "bound" };
      }
      scheduleRefresh(cfg, state.refreshIntervalMs);
      return { phase: "polyfill-bound", tier: "bound" };
    }

    // phase === "needs-registration"
    // If Chrome already skipped native (quota, unreachable, etc), do not burn
    // the probe window — Chrome has already told us it won't register.
    if (state.nativeSkipped && state.nativeSkipped.length > 0) {
      await runRegistration(state.sessionId, state.challenge, cfg);
      const final = await fetchState(cfg.statePath);
      if (final.phase === "bound") scheduleRefresh(cfg, final.refreshIntervalMs);
      return { phase: "polyfill-bound", tier: "bound", skipReason: state.nativeSkipped[0] };
    }

    await sleep(cfg.nativeProbeWindowMs);

    const recheck = await fetchState(cfg.statePath);
    if (recheck.phase === "bound" && recheck.tier === "dbsc") {
      return { phase: "native-dbsc", tier: "dbsc" };
    }
    if (recheck.phase === "bound" && recheck.tier === "bound") {
      // Someone else (another tab) registered during the probe window.
      scheduleRefresh(cfg, recheck.refreshIntervalMs);
      return { phase: "polyfill-bound", tier: "bound" };
    }
    if (recheck.phase !== "needs-registration") {
      return { phase: "unbound" };
    }

    await runRegistration(recheck.sessionId, recheck.challenge, cfg);
    const final = await fetchState(cfg.statePath);
    if (final.phase === "bound") scheduleRefresh(cfg, final.refreshIntervalMs);
    return outcomeFromSkip("polyfill-bound", recheck.nativeSkipped);
  } catch (err) {
    return { phase: "error", error: err instanceof Error ? err.message : String(err) };
  }
}

function outcomeFromSkip(
  phase: "polyfill-bound",
  skipped: string[] | undefined,
): BoundDbscOutcome {
  if (skipped && skipped.length > 0) {
    return { phase, tier: "bound", skipReason: skipped[0] };
  }
  return { phase, tier: "bound" };
}

export function stopBoundDbsc(): void {
  if (refreshTimer !== null) {
    clearTimeout(refreshTimer);
    refreshTimer = null;
  }
}

async function fetchState(path: string): Promise<StateResponse> {
  const r = await fetch(path, { credentials: "include" });
  await recordServerTime(r);
  return (await r.json()) as StateResponse;
}

async function runRegistration(
  sessionId: string,
  challenge: string,
  cfg: ResolvedOptions,
): Promise<void> {
  await clearKeyRecord().catch(() => {});

  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign", "verify"],
  );

  const publicKey = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  const signature = await signMessage(keyPair.privateKey, challenge);

  const res = await fetch(cfg.registrationPath, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ publicKey, signature, challenge }),
  });

  if (!res.ok) {
    throw new Error(`bound registration failed: ${res.status}`);
  }

  await setKeyRecord({ sessionId, keyPair });
  await recordServerTime(res);
}

async function runRefresh(cfg: ResolvedOptions): Promise<boolean> {
  const rec = await getKeyRecord().catch(() => null);
  if (!rec) return false;

  const cRes = await fetch(cfg.challengePath, { credentials: "include" });
  if (!cRes.ok) return false;
  const { challenge } = (await cRes.json()) as { challenge: string };

  const timestamp = Date.now();
  const message = `${challenge}.${timestamp}`;
  const signature = await signMessage(rec.keyPair.privateKey, message);

  const res = await fetch(cfg.refreshPath, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ challenge, signature, timestamp }),
  });

  await recordServerTime(res);
  return res.ok;
}

function scheduleRefresh(cfg: ResolvedOptions, intervalMs: number): void {
  if (refreshTimer !== null) clearTimeout(refreshTimer);
  const wait = Math.max(1000, intervalMs - cfg.refreshMarginMs);
  refreshTimer = setTimeout(async () => {
    const ok = await runRefresh(cfg).catch(() => false);
    if (ok) {
      scheduleRefresh(cfg, intervalMs);
    } else {
      refreshTimer = null;
    }
  }, wait);
}

async function signMessage(privateKey: CryptoKey, message: string): Promise<string> {
  const data = new TextEncoder().encode(message);
  const sig = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    privateKey,
    data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer,
  );
  return base64urlEncode(new Uint8Array(sig));
}

function base64urlEncode(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i] as number);
  return btoa(s).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}
