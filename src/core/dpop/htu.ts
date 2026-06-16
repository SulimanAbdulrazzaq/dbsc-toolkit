/**
 * RFC 9449 htu normalization. This is the dangerous check: a weak normalizer
 * lets a proof minted for one URL be accepted on another. §4.3 requires the
 * htu claim to match the request URI "ignoring any query and fragment parts"
 * and SHOULD apply RFC 3986 §6.2.2 (syntax-based) + §6.2.3 (scheme-based)
 * normalization before comparing.
 *
 * Rules applied here, on both the claimed htu and the live request URL, then
 * compared as strings:
 *   - lowercase scheme and host (WHATWG URL does this for us)
 *   - drop ONLY the scheme-default port (443 for https, 80 for http); keep
 *     every non-default port exactly (:8443 stays :8443)
 *   - strip query and fragment
 *   - empty path becomes "/"
 *   - trailing slash is SIGNIFICANT: "/token/" does not equal "/token"
 *
 * Percent-encoding and path "."/".." resolution are handled by `new URL()`.
 */
import { DbscVerificationError, ErrorCodes } from "../errors.js";

const DEFAULT_PORT: Record<string, string> = { "https:": "443", "http:": "80" };

export function normalizeHtu(uri: string): string {
  let u: URL;
  try {
    u = new URL(uri);
  } catch {
    throw new DbscVerificationError(
      ErrorCodes.DPOP_HTU_MISMATCH,
      `htu is not an absolute URI: ${uri}`,
    );
  }

  const scheme = u.protocol.toLowerCase();
  const host = u.hostname.toLowerCase();
  // u.port is "" when the URL used the scheme-default port implicitly, and the
  // numeric string otherwise. Drop it only when it equals the scheme default.
  const port = u.port && u.port !== DEFAULT_PORT[scheme] ? `:${u.port}` : "";
  const path = u.pathname === "" ? "/" : u.pathname;

  // scheme://host[:port]path — query and fragment intentionally dropped.
  return `${scheme}//${host}${port}${path}`;
}

/** True when the claimed htu and the actual request URL normalize equal. */
export function htuMatches(claimed: string, requestUrl: string): boolean {
  return normalizeHtu(claimed) === normalizeHtu(requestUrl);
}
