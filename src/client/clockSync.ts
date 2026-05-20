import { getKeyRecord, setKeyRecord } from "./keystore.js";

export async function recordServerTime(response: Response): Promise<void> {
  const hdr = response.headers.get("X-Server-Time");
  if (!hdr) return;
  const serverTime = Number(hdr);
  if (!Number.isFinite(serverTime)) return;
  const rec = await getKeyRecord().catch(() => null);
  if (!rec) return;
  const offset = serverTime - Date.now();
  if (rec.clockOffsetMs === offset) return;
  await setKeyRecord({ ...rec, clockOffsetMs: offset });
}
