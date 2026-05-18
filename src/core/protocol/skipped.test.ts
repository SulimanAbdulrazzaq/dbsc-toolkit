import { describe, it, expect } from "vitest";
import { parseSessionSkippedHeader } from "./headers.js";

describe("parseSessionSkippedHeader", () => {
  it("returns empty array when header absent", () => {
    expect(parseSessionSkippedHeader({})).toEqual([]);
  });

  it("parses single quota_exceeded with session_identifier", () => {
    const entries = parseSessionSkippedHeader({
      "secure-session-skipped": 'quota_exceeded;session_identifier="abc-123"',
    });
    expect(entries).toEqual([{ reason: "quota_exceeded", sessionId: "abc-123" }]);
  });

  it("parses multiple entries from spec example", () => {
    const entries = parseSessionSkippedHeader({
      "secure-session-skipped":
        'unreachable;session_identifier="123", quota_exceeded;session_identifier="456"',
    });
    expect(entries).toEqual([
      { reason: "unreachable", sessionId: "123" },
      { reason: "quota_exceeded", sessionId: "456" },
    ]);
  });

  it("falls back to legacy sec-session-skipped header", () => {
    const entries = parseSessionSkippedHeader({
      "sec-session-skipped": 'server_error;session_identifier="x"',
    });
    expect(entries).toEqual([{ reason: "server_error", sessionId: "x" }]);
  });

  it("drops entries with unknown reason tokens", () => {
    const entries = parseSessionSkippedHeader({
      "secure-session-skipped": 'mystery_reason;session_identifier="x", quota_exceeded',
    });
    expect(entries).toEqual([{ reason: "quota_exceeded" }]);
  });

  it("handles array-form header value", () => {
    const entries = parseSessionSkippedHeader({
      "secure-session-skipped": ["unreachable;session_identifier=\"1\"", "quota_exceeded"],
    });
    expect(entries).toEqual([
      { reason: "unreachable", sessionId: "1" },
      { reason: "quota_exceeded" },
    ]);
  });
});
