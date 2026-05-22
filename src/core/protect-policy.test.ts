import { describe, it, expect } from "vitest";
import { noBindingReason } from "./protect-policy.js";

describe("noBindingReason", () => {
  it("explains a quota-exceeded skip", () => {
    expect(noBindingReason([{ reason: "quota_exceeded" }])).toMatch(/quota_exceeded/);
  });

  it("gives a generic reason with no skip diagnostics", () => {
    expect(noBindingReason()).toMatch(/no active device binding/);
    expect(noBindingReason([])).toMatch(/no active device binding/);
  });
});
