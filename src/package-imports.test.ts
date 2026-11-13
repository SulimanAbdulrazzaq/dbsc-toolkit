import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { builtinModules } from "node:module";
import { join } from "node:path";

// Every bare import in shipped source must resolve for the people who install
// the package: it has to be a dependency or a peer dependency. A package that is
// only a devDependency works here and in CI, then fails for users under strict
// installers (pnpm) with "Cannot find module".

const root = join(import.meta.dirname, "..");
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as {
  dependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
};
const declared = new Set([
  ...Object.keys(pkg.dependencies ?? {}),
  ...Object.keys(pkg.peerDependencies ?? {}),
]);
const builtins = new Set(builtinModules);

function sourceFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) return sourceFiles(full);
    const shipped = name.endsWith(".ts") && !name.endsWith(".test.ts");
    return shipped ? [full] : [];
  });
}

function packageName(specifier: string): string {
  const parts = specifier.split("/");
  return specifier.startsWith("@") ? `${parts[0]}/${parts[1]}` : parts[0]!;
}

describe("published imports", () => {
  it("only imports packages listed in dependencies or peerDependencies", () => {
    const missing: string[] = [];
    for (const file of sourceFiles(join(root, "src"))) {
      const text = readFileSync(file, "utf8");
      // Value imports only: `import type` is erased and needs nothing at runtime.
      for (const m of text.matchAll(/^import\s+(?!type\s)[^;]*?from\s+"([^"]+)"/gm)) {
        const spec = m[1]!;
        if (spec.startsWith(".") || spec.startsWith("node:")) continue;
        const name = packageName(spec);
        if (builtins.has(name) || declared.has(name)) continue;
        missing.push(`${file.slice(root.length + 1)} -> ${name}`);
      }
    }
    expect(missing).toEqual([]);
  });
});
