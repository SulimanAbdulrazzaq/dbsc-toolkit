import {
  createDbsc as createNodeDbsc,
  type CreateDbscOptions,
  type DbscKit,
} from "../node/create-dbsc.js";
import { handleDbscProtocol, type DbscProtocolResult } from "./index.js";

export type { CreateDbscOptions } from "../node/create-dbsc.js";

export interface ElectronDbscKit extends DbscKit {
  /**
   * A handler for Electron's `protocol.handle(scheme, handler)`. Pass a Web
   * `Request`, get the `Response` for DBSC protocol routes:
   *
   *   protocol.handle("app", (request) => kit.protocolHandler()(request));
   *
   * Non-protocol requests come back as a 404 by default; use
   * `protocolRoute(request)` if you need the resolved session to serve your own
   * routes instead.
   */
  protocolHandler(): (request: Request) => Promise<Response>;
  /** Lower-level: returns `{ handled, response, session }` so you can branch. */
  protocolRoute(request: Request): Promise<DbscProtocolResult>;
}

/**
 * Builds a DBSC kit for an Electron main process. Everything the raw-http kit
 * offers (`handler`, `bind`, `requireProof`, `requireDpop`, `getSession`) plus a
 * `protocol.handle`-shaped surface so the routes mount on an Electron scheme.
 */
export function createElectronDbsc(opts: CreateDbscOptions): ElectronDbscKit {
  const kit = createNodeDbsc(opts);
  const handler = kit.handler();

  return {
    ...kit,
    protocolRoute: (request: Request) => handleDbscProtocol(request, handler),
    protocolHandler: () => async (request: Request) => {
      const { handled, response } = await handleDbscProtocol(request, handler);
      if (handled) return response;
      return new Response(null, { status: 404 });
    },
  };
}
