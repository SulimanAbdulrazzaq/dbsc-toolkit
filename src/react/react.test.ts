// @vitest-environment jsdom
import { afterEach, describe, expect, it } from "vitest";
import "fake-indexeddb/auto";
import { createElement, act } from "react";
import { createRoot } from "react-dom/client";
import { useDbsc, type DbscState } from "./index.js";
import { getDbscClient } from "../client/start.js";

const originalFetch = globalThis.fetch;
(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

afterEach(() => {
  getDbscClient()?.stop();
  globalThis.fetch = originalFetch;
});

describe("useDbsc", () => {
  it("renders starting, then the outcome of registration", async () => {
    globalThis.fetch = (async () => Response.json({ phase: "unbound" })) as typeof fetch;
    const seen: DbscState[] = [];
    function Probe() {
      seen.push(useDbsc());
      return null;
    }
    const root = createRoot(document.createElement("div"));
    await act(async () => {
      root.render(createElement(Probe));
    });
    await act(async () => {
      await getDbscClient()!.ready;
    });
    expect(seen[0]?.status).toBe("starting");
    expect(seen.at(-1)?.status).toBe("unbound");
    root.unmount();
  });
});
