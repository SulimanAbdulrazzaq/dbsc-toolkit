import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { join, sep } from "node:path";

const CLIENT_DIR = fileURLToPath(new URL("../client/", import.meta.url));
const SAFE_NAME = /^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*\.js(?:\.map)?$/;

export interface ClientAsset {
  body: Buffer;
  contentType: string;
}

/**
 * Reads a file of the browser SDK (`dist/client/*.js`) for a request under
 * `mount`, e.g. `/dbsc-client/auto.js`. Returns `null` for anything else,
 * including names that try to leave the directory.
 */
export async function readClientAsset(pathname: string, mount: string): Promise<ClientAsset | null> {
  const prefix = `${mount.replace(/\/$/, "")}/`;
  if (!pathname.startsWith(prefix)) return null;
  const name = pathname.slice(prefix.length);
  if (!SAFE_NAME.test(name)) return null;
  const file = join(CLIENT_DIR, name);
  if (!file.startsWith(CLIENT_DIR.endsWith(sep) ? CLIENT_DIR : CLIENT_DIR + sep)) return null;
  try {
    const body = await readFile(file);
    const contentType = name.endsWith(".map") ? "application/json; charset=utf-8" : "text/javascript; charset=utf-8";
    return { body, contentType };
  } catch {
    return null;
  }
}
