import { describe, it, expect } from "vitest";
import { buildDbscRoutes, type RouteDeps } from "./routes.js";

// Minimal deps — buildDbscRoutes only wires endpoints; it does not call these
// at construction time, so stubs are enough to assert which routes are built.
function deps(extra: Partial<RouteDeps> = {}): RouteDeps {
  return {
    storageFromCtx: () => ({}) as any,
    cookies: {} as any,
    basePath: "/api/auth",
    boundCookieTtl: 600_000,
    ...extra,
  };
}

const NATIVE = ["dbscRegistration", "dbscRefresh"];
const BOUND = ["dbscBoundState", "dbscBoundChallenge", "dbscBoundRegistration", "dbscBoundRefresh"];

describe("buildDbscRoutes", () => {
  it("mounts all six endpoints by default", () => {
    const routes = buildDbscRoutes(deps());
    for (const name of [...NATIVE, ...BOUND]) {
      expect(routes[name], name).toBeDefined();
    }
    expect(Object.keys(routes)).toHaveLength(6);
  });

  it("mounts all six when bound is true explicitly", () => {
    const routes = buildDbscRoutes(deps({ bound: true }));
    expect(Object.keys(routes)).toHaveLength(6);
  });

  it("omits the three bound action routes when bound is false", () => {
    const routes = buildDbscRoutes(deps({ bound: false }));
    // Native pair always present.
    for (const name of NATIVE) expect(routes[name], name).toBeDefined();
    // State stays mounted (answers "unbound" so a client SDK stands down).
    expect(routes.dbscBoundState).toBeDefined();
    // The other three bound routes are gone.
    expect(routes.dbscBoundChallenge).toBeUndefined();
    expect(routes.dbscBoundRegistration).toBeUndefined();
    expect(routes.dbscBoundRefresh).toBeUndefined();
    expect(Object.keys(routes).sort()).toEqual(
      ["dbscBoundState", "dbscRefresh", "dbscRegistration"].sort(),
    );
  });
});
