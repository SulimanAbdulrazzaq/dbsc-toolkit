/**
 * Parses a `Cookie` request header into a name→value map. Lets the adapter
 * middlewares read DBSC cookies without depending on `cookie-parser`.
 */
export function parseCookieHeader(header?: string | null): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    const name = part.slice(0, eq).trim();
    if (!name) continue;
    let value = part.slice(eq + 1).trim();
    if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) {
      value = value.slice(1, -1);
    }
    try {
      value = decodeURIComponent(value);
    } catch {
      // keep the raw value if it is not valid percent-encoding
    }
    if (!(name in out)) out[name] = value;
  }
  return out;
}
