import { describe, it, expect } from "vitest";
import {
  resolveCookieScope,
  cookieNames,
  deviceCookieName,
  cookieAttributesString,
} from "./options.js";

describe("resolveCookieScope", () => {
  it("defaults to host scope with __Host- prefix when secure", () => {
    const r = resolveCookieScope({ secure: true });
    expect(r.hostPrefix).toBe(true);
    expect(r.prefix).toBe("__Host-");
    expect(r.domain).toBeUndefined();
  });

  it("drops the prefix in insecure dev mode", () => {
    const r = resolveCookieScope({ secure: false });
    expect(r.hostPrefix).toBe(false);
    expect(r.prefix).toBe("");
    expect(r.domain).toBeUndefined();
  });

  it("switches to __Secure- prefix with Domain in site scope", () => {
    const r = resolveCookieScope({
      secure: true,
      cookieScope: "site",
      cookieDomain: "example.com",
    });
    expect(r.hostPrefix).toBe(false);
    expect(r.prefix).toBe("__Secure-");
    expect(r.domain).toBe("example.com");
  });

  it("throws when site scope is set without cookieDomain", () => {
    expect(() =>
      resolveCookieScope({ secure: true, cookieScope: "site" }),
    ).toThrow(/cookieDomain/);
  });

  it("throws when site scope is set without secure", () => {
    expect(() =>
      resolveCookieScope({
        secure: false,
        cookieScope: "site",
        cookieDomain: "example.com",
      }),
    ).toThrow(/secure: true/);
  });

  it("rejects a cookieDomain with a leading dot", () => {
    expect(() =>
      resolveCookieScope({
        secure: true,
        cookieScope: "site",
        cookieDomain: ".example.com",
      }),
    ).toThrow(/leading dot/);
  });

  it("rejects cookieDomain in host scope", () => {
    expect(() =>
      resolveCookieScope({
        secure: true,
        cookieScope: "host",
        cookieDomain: "example.com",
      }),
    ).toThrow(/only valid when cookieScope: "site"/);
  });
});

describe("cookieNames", () => {
  it("returns __Host- names by default", () => {
    expect(cookieNames({ secure: true })).toEqual({
      bound: "__Host-dbsc-session",
      reg: "__Host-dbsc-reg",
      challenge: "__Host-dbsc-challenge",
    });
  });

  it("returns __Secure- names under site scope", () => {
    expect(
      cookieNames({ secure: true, cookieScope: "site", cookieDomain: "example.com" }),
    ).toEqual({
      bound: "__Secure-dbsc-session",
      reg: "__Secure-dbsc-reg",
      challenge: "__Secure-dbsc-challenge",
    });
  });

  it("returns bare names insecure", () => {
    expect(cookieNames({ secure: false })).toEqual({
      bound: "dbsc-session",
      reg: "dbsc-reg",
      challenge: "dbsc-challenge",
    });
  });
});

describe("deviceCookieName", () => {
  it("matches the binding cookie prefix", () => {
    expect(deviceCookieName({ secure: true })).toBe("__Host-dbsc-device");
    expect(
      deviceCookieName({ secure: true, cookieScope: "site", cookieDomain: "example.com" }),
    ).toBe("__Secure-dbsc-device");
    expect(deviceCookieName({ secure: false })).toBe("dbsc-device");
  });
});

describe("cookieAttributesString", () => {
  it("omits Domain in host scope", () => {
    expect(cookieAttributesString({ secure: true })).toBe(
      "Path=/; Secure; HttpOnly; SameSite=Lax",
    );
  });

  it("appends Domain in site scope", () => {
    expect(
      cookieAttributesString({
        secure: true,
        cookieScope: "site",
        cookieDomain: "example.com",
      }),
    ).toBe("Path=/; Secure; HttpOnly; SameSite=Lax; Domain=example.com");
  });
});
