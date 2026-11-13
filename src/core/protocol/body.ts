/** Protocol request bodies are a key and a signature; anything larger is refused. */
export const MAX_PROTOCOL_BODY_BYTES = 16 * 1024;

/**
 * Reads a Web `Request` body as a JSON object, stopping after `limit` bytes.
 * Returns `{}` for an empty, oversized, invalid, or non-object body, so route
 * code can read fields without guarding against `null` or arrays.
 */
export async function readJsonObject(
  request: Request,
  limit: number = MAX_PROTOCOL_BODY_BYTES,
): Promise<Record<string, unknown>> {
  const declared = Number(request.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > limit) return {};
  if (!request.body) return {};
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > limit) {
      await reader.cancel().catch(() => {});
      return {};
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size);
  let off = 0;
  for (const c of chunks) {
    bytes.set(c, off);
    off += c.byteLength;
  }
  try {
    const parsed: unknown = JSON.parse(new TextDecoder().decode(bytes));
    return parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : {};
  } catch {
    return {};
  }
}
