import { jwkThumbprint } from "./thumbprint.js";

export interface DpopConfirmation {
  /** RFC 7638 thumbprint of the bound key, for the token's cnf.jkt. */
  jkt: string;
}

/**
 * Build the `cnf` confirmation to embed in an access token at issue time so
 * the token is bound to a DPoP key (RFC 9449 §6). Embed the return value as
 * `{ cnf: { jkt } }` in the token claims, then guard the resource route with
 * `requireDpop({ getBoundJkt })` returning the same jkt. Framework-neutral:
 * the caller signs the token however it already does.
 */
export async function dpopConfirmation(jwk: JsonWebKey): Promise<DpopConfirmation> {
  return { jkt: await jwkThumbprint(jwk) };
}
