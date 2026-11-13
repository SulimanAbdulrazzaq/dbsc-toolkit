import { describe, it, expect } from "vitest";
import { createServer, type Server } from "node:http";
import { connect, type AddressInfo } from "node:net";
import { dbsc } from "./index.js";
import { MemoryStorage } from "../storage/memory/index.js";

async function rawRequest(port: number, payload: string): Promise<string> {
  return new Promise((resolve) => {
    const sock = connect(port, "127.0.0.1", () => sock.write(payload));
    let data = "";
    sock.on("data", (d) => (data += d));
    sock.on("close", () => resolve(data.split("\r\n")[0] ?? ""));
    setTimeout(() => sock.destroy(), 1000);
  });
}

describe("node adapter hostile input", () => {
  it("survives a JSON null body and a malformed Host header", async () => {
    const rejections: unknown[] = [];
    const onRejection = (e: unknown) => rejections.push(e);
    process.on("unhandledRejection", onRejection);
    const handler = dbsc({ storage: new MemoryStorage(), secure: false });
    const server: Server = createServer((req, res) => {
      void handler(req, res).then((handled) => {
        if (!handled) res.end("app");
      });
    });
    await new Promise<void>((r) => server.listen(0, r));
    const port = (server.address() as AddressInfo).port;

    const nullBody = await rawRequest(
      port,
      "POST /dbsc-bound/refresh HTTP/1.1\r\nHost: x\r\nCookie: dbsc-session=x\r\nContent-Length: 4\r\nConnection: close\r\n\r\nnull",
    );
    const badHost = await rawRequest(port, "GET /anything HTTP/1.1\r\nHost: a b\r\nConnection: close\r\n\r\n");
    server.close();
    process.off("unhandledRejection", onRejection);

    expect(nullBody).toMatch(/^HTTP\/1\.1 4\d\d/);
    expect(badHost).toMatch(/^HTTP\/1\.1 200/);
    expect(rejections).toEqual([]);
  });
});
