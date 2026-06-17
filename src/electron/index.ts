import type { IncomingMessage, ServerResponse } from "node:http";
import { dbsc, getDbscSession, type DbscNodeHandler, type DbscNodeSession } from "../node/index.js";

// Re-export the raw-http surface verbatim. In Electron's main process you can run
// an ordinary localhost http.Server and wire `dbsc()` at the top of the listener
// exactly as on the node adapter, then read the session with `getDbscSession`.
export {
  dbsc,
  bindSession,
  getDbscSession,
  readJsonBody,
  createDbsc,
  DBSC_INTERNAL,
} from "../node/index.js";
export type {
  DbscNodeHandler,
  DbscNodeSession,
  DbscNodeOptions,
  DbscInternal,
  BindSessionOptions,
} from "../node/index.js";
export type { CreateDbscOptions, DbscKit, BindOptions } from "../node/create-dbsc.js";
export { requireProof, type ElectronProofGuard } from "./require-proof.js";
export { requireDpop, type ElectronDpopGuard } from "./require-dpop.js";
export { createElectronDbsc, type ElectronDbscKit } from "./create-dbsc.js";

/**
 * Electron's `protocol.handle(scheme, handler)` hands you a Web `Request` and
 * wants a `Response`. This adapts that shape onto the existing raw-http handler
 * (no protocol logic is duplicated): it builds a minimal request/response shim,
 * runs the node `dbsc()` handler, and converts the captured response back.
 *
 * When the request is a DBSC protocol route the returned `Response` is the answer
 * to send. Otherwise `dbsc()` did not own the route — `handled` is false, the
 * resolved `session` is provided so the caller can branch, and `respondWith`
 * lets a guard write into the same response shim.
 */
export interface DbscProtocolResult {
  handled: boolean;
  response: Response;
  session: DbscNodeSession | undefined;
}

/** Minimal IncomingMessage shim carrying just what the handler + guards read. */
function makeReq(request: Request, body: Uint8Array): IncomingMessage {
  const headers: Record<string, string> = {};
  request.headers.forEach((value, key) => {
    headers[key.toLowerCase()] = value;
  });
  const u = new URL(request.url);
  // host header drives reqUrl/reqOrigin in the node handler; honor it from the URL.
  if (!headers["host"]) headers["host"] = u.host;

  let consumed = false;
  const req = {
    method: request.method,
    url: u.pathname + u.search,
    headers,
    socket: { remoteAddress: "127.0.0.1", encrypted: u.protocol === "https:" },
    // readJsonBody does `for await (const chunk of req)`; yield the body once.
    async *[Symbol.asyncIterator]() {
      if (consumed) return;
      consumed = true;
      if (body.length) yield Buffer.from(body);
    },
  };
  return req as unknown as IncomingMessage;
}

/** Minimal ServerResponse shim that captures status, headers, and body. */
interface ResCapture {
  res: ServerResponse;
  toResponse(): Response;
}
function makeRes(): ResCapture {
  let statusCode = 200;
  const headers = new Map<string, string | string[]>();
  const chunks: Uint8Array[] = [];
  const key = (n: string) => n.toLowerCase();

  const res = {
    get statusCode() {
      return statusCode;
    },
    set statusCode(v: number) {
      statusCode = v;
    },
    setHeader(name: string, value: string | number | readonly string[]) {
      headers.set(key(name), Array.isArray(value) ? value.map(String) : String(value));
    },
    getHeader(name: string) {
      return headers.get(key(name));
    },
    end(chunk?: string | Uint8Array) {
      if (chunk !== undefined) {
        chunks.push(typeof chunk === "string" ? new TextEncoder().encode(chunk) : chunk);
      }
    },
  };

  function toResponse(): Response {
    const h = new Headers();
    for (const [name, value] of headers) {
      if (name === "set-cookie") {
        const list = Array.isArray(value) ? value : [value];
        for (const c of list) h.append("set-cookie", c);
      } else {
        h.set(name, Array.isArray(value) ? value.join(", ") : value);
      }
    }
    const total = chunks.reduce((n, c) => n + c.length, 0);
    const body = new Uint8Array(total);
    let off = 0;
    for (const c of chunks) {
      body.set(c, off);
      off += c.length;
    }
    return new Response(total ? body : null, { status: statusCode, headers: h });
  }

  return { res: res as unknown as ServerResponse, toResponse };
}

/**
 * Run a configured `dbsc()` handler against an Electron Web `Request`.
 * Use the kit's `protocolHandler()` for the common case; this is the lower-level
 * primitive if you need the resolved session or to chain a guard.
 */
export async function handleDbscProtocol(
  request: Request,
  handler: DbscNodeHandler,
): Promise<DbscProtocolResult> {
  const raw = new Uint8Array(await request.clone().arrayBuffer());
  const req = makeReq(request, raw);
  const { res, toResponse } = makeRes();
  const handled = await handler(req, res);
  return { handled, response: toResponse(), session: getDbscSession(req) };
}
