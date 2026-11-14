import { startDbsc, type DbscClient } from "./start.js";

// Loaded as <script type="module" src="/dbsc-client/auto.js">. Options come
// from the script URL: ?sign=/api/,/account/ and &signQuery=1.
const params = new URL(import.meta.url).searchParams;
const sign = params.get("sign");

const client: DbscClient = startDbsc({
  ...(sign ? { sign: sign.split(",").map((p) => p.trim()).filter(Boolean) } : {}),
  ...(params.get("signQuery") === "1" && { signQuery: true }),
});

declare global {
  interface Window {
    /** Set by `/dbsc-client/auto.js`. */
    dbsc?: DbscClient;
  }
}

if (typeof window !== "undefined") window.dbsc = client;

export default client;
