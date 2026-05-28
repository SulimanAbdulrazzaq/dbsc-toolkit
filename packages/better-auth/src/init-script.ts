/**
 * Generates the browser-side init shim served at `<clientPath>/init.js`.
 *
 * The user drops one tag in their HTML:
 *
 *   <script src="/dbsc-client/init.js"></script>
 *
 * The shim imports the polyfill SDK from `<clientPath>/index.js`, calls
 * `initBoundDbsc()` with paths that match the configured Better Auth
 * basePath, and exposes `window.boundFetch` so app code can sign per-request
 * proofs by calling `boundFetch(...)` instead of `fetch(...)`.
 */
export interface InitScriptOptions {
  basePath: string;
  clientPath: string;
}

export function buildInitScript(opts: InitScriptOptions): string {
  const { basePath, clientPath } = opts;
  return `// @dbsc-toolkit/better-auth — browser init shim
import { initBoundDbsc, wrapFetch, clearBoundKey } from "${clientPath}/index.js";

const paths = {
  statePath: "${basePath}/dbsc-bound/state",
  challengePath: "${basePath}/dbsc-bound/challenge",
  registrationPath: "${basePath}/dbsc-bound/registration",
  refreshPath: "${basePath}/dbsc-bound/refresh",
};

// Polyfill kicks in on Firefox / Safari / older Chromium. On Chromium 145+
// native DBSC runs first; the polyfill co-registers a key so per-request
// proofs work everywhere.
const outcome = initBoundDbsc({ nativeProbeWindowMs: 8000, ...paths });
outcome.then((o) => console.log("[dbsc]", o)).catch((e) => console.error("[dbsc]", e));

// boundFetch signs every request body (empty bytes for GET). Replace
// \`fetch\` with \`boundFetch\` on any call to a requireProof()-guarded route.
window.boundFetch = wrapFetch({ signBody: true });
window.clearBoundKey = clearBoundKey;
window.__dbscOutcome = outcome;
`;
}
