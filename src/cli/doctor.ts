export type CheckStatus = "ok" | "warn" | "fail";

export interface CheckResult {
  status: CheckStatus;
  title: string;
  detail?: string;
}

export interface DoctorOptions {
  /** A signed-in browser's Cookie header, to check the bound session and a guarded route. */
  cookie?: string;
  /** A route protected by requireProof(), requested with the cookie and no proof. */
  guard?: string;
  /** Path the client SDK is served from. Default "/dbsc-client". */
  clientPath?: string;
  /** Per-request timeout in ms. Default 30 s, enough for a cold-starting free-tier host. */
  timeoutMs?: number;
  fetch?: typeof fetch;
}

const SKEW_WARN_MS = 60_000;
const DEFAULT_TIMEOUT_MS = 30_000;

function isLocal(url: URL): boolean {
  return ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname) || url.hostname.endsWith(".localhost");
}

/** Turns a fetch failure into a message that says what actually went wrong. */
export function describeFetchError(err: unknown, timeoutMs: number): Error {
  if (!(err instanceof Error)) return new Error(String(err));
  if (err.name === "TimeoutError" || err.name === "AbortError") {
    return new Error(`no response within ${Math.round(timeoutMs / 1000)}s (a cold-starting host can take longer; raise --timeout)`);
  }
  const cause = (err as { cause?: { code?: string; message?: string } }).cause;
  const detail = cause?.code ?? cause?.message;
  return new Error(detail ? `${err.message} (${detail})` : err.message);
}

async function get(f: typeof fetch, timeoutMs: number, url: string, init: RequestInit = {}): Promise<Response | Error> {
  try {
    return await f(url, { redirect: "manual", signal: AbortSignal.timeout(timeoutMs), ...init });
  } catch (err) {
    return describeFetchError(err, timeoutMs);
  }
}

async function readJson(res: Response): Promise<Record<string, unknown> | null> {
  try {
    const body = (await res.json()) as unknown;
    return body && typeof body === "object" ? (body as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

/**
 * Checks a running site from the outside: HTTPS, the protocol routes, clock
 * skew, the client SDK, and (with a signed-in cookie) that a guarded route
 * turns away a request that has the cookie but no proof — what an attacker
 * holding a stolen cookie would send.
 */
export async function runDoctor(target: string, opts: DoctorOptions = {}): Promise<CheckResult[]> {
  const f = opts.fetch ?? fetch;
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const results: CheckResult[] = [];
  let base: URL;
  try {
    base = new URL(target);
  } catch {
    return [{ status: "fail", title: "URL", detail: `"${target}" is not a valid URL` }];
  }
  const at = (path: string) => new URL(path, base).toString();
  const cookieHeaders: Record<string, string> = opts.cookie ? { cookie: opts.cookie } : {};

  if (base.protocol === "https:") {
    results.push({ status: "ok", title: "HTTPS" });
  } else if (isLocal(base)) {
    results.push({
      status: "warn",
      title: "HTTPS",
      detail: "plain http on localhost works only with secure: false (the default under NODE_ENV=development)",
    });
  } else {
    results.push({
      status: "fail",
      title: "HTTPS",
      detail: "DBSC cookies are __Host- and Secure; browsers drop them over plain http. Serve the site over HTTPS.",
    });
  }

  const state = await get(f, timeoutMs, at("/dbsc-bound/state"), { headers: cookieHeaders });
  if (state instanceof Error) {
    results.push({ status: "fail", title: "Protocol routes", detail: `could not reach ${at("/dbsc-bound/state")}: ${state.message}` });
    return results;
  }
  const stateBody = state.ok ? await readJson(state) : null;
  if (!stateBody || typeof stateBody.phase !== "string") {
    results.push({
      status: "fail",
      title: "Protocol routes",
      detail: `GET /dbsc-bound/state returned ${state.status}. Mount the middleware (createDbsc().install(app)) before your routes, and keep bound: true.`,
    });
  } else {
    results.push({ status: "ok", title: "Protocol routes", detail: `/dbsc-bound/state answers (phase: ${stateBody.phase})` });
  }

  const serverTime = Number(state.headers.get("x-server-time"));
  if (Number.isFinite(serverTime) && serverTime > 0) {
    const skew = Math.abs(Date.now() - serverTime);
    results.push(
      skew > SKEW_WARN_MS
        ? { status: "warn", title: "Server clock", detail: `differs from this machine by ${Math.round(skew / 1000)}s; check NTP on the server` }
        : { status: "ok", title: "Server clock" },
    );
  }

  const clientPath = (opts.clientPath ?? "/dbsc-client").replace(/\/$/, "");
  const sdk = await get(f, timeoutMs, at(`${clientPath}/auto.js`));
  const sdkType = sdk instanceof Error ? "" : (sdk.headers.get("content-type") ?? "");
  if (!(sdk instanceof Error) && sdk.ok && /javascript/.test(sdkType)) {
    results.push({ status: "ok", title: "Client SDK", detail: `${clientPath}/auto.js is served` });
  } else {
    results.push({
      status: "warn",
      title: "Client SDK",
      detail: `${clientPath}/auto.js is not served. Fine if your bundle imports startDbsc from "dbsc-toolkit/client"; otherwise browsers never register a key.`,
    });
  }

  const refresh = await get(f, timeoutMs, at("/dbsc/refresh"), { method: "POST" });
  if (!(refresh instanceof Error) && refresh.status >= 400 && refresh.status < 500) {
    results.push({ status: "ok", title: "Refresh route", detail: `POST /dbsc/refresh without a session answers ${refresh.status}` });
  } else {
    results.push({
      status: "warn",
      title: "Refresh route",
      detail: `POST /dbsc/refresh without a session answered ${refresh instanceof Error ? refresh.message : refresh.status}; expected a 4xx`,
    });
  }

  if (opts.cookie) {
    const phase = stateBody?.phase;
    results.push(
      phase === "bound"
        ? { status: "ok", title: "Signed-in session", detail: `bound (tier: ${String(stateBody?.tier)})` }
        : {
            status: "warn",
            title: "Signed-in session",
            detail: `state is "${String(phase)}" for the given cookie; sign in and copy the Cookie header again, or check that the login starts a binding`,
          },
    );
  }

  if (opts.guard) {
    if (!opts.cookie) {
      results.push({ status: "warn", title: "Stolen-cookie replay", detail: "--guard needs --cookie from a signed-in browser" });
    } else {
      const replay = await get(f, timeoutMs, at(opts.guard), { headers: cookieHeaders });
      if (replay instanceof Error) {
        results.push({ status: "fail", title: "Stolen-cookie replay", detail: replay.message });
      } else if (replay.status === 401) {
        results.push({
          status: "warn",
          title: "Stolen-cookie replay",
          detail: `${opts.guard} answered 401: the app's own login check ran first and rejected the cookie. Pass the app's session cookie in --cookie too, so the request reaches the DBSC guard.`,
        });
      } else if (replay.status === 403) {
        const body = await readJson(replay);
        results.push({
          status: "ok",
          title: "Stolen-cookie replay",
          detail: `${opts.guard} turned away the cookie without a proof (${String(body?.code ?? 403)})`,
        });
      } else {
        results.push({
          status: "fail",
          title: "Stolen-cookie replay",
          detail: `${opts.guard} answered ${replay.status} to the cookie without a proof. Guard it with requireProof() or protect().`,
        });
      }
    }
  }

  return results;
}

export function formatResults(results: CheckResult[]): string {
  const label: Record<CheckStatus, string> = { ok: "  ok ", warn: " warn", fail: " FAIL" };
  return results
    .map((r) => `${label[r.status]}  ${r.title}${r.detail ? ` - ${r.detail}` : ""}`)
    .join("\n");
}
