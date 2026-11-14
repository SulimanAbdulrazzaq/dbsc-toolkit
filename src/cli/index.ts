#!/usr/bin/env node
import { readFileSync, existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { parseArgs } from "node:util";
import { runDoctor, formatResults } from "./doctor.js";
import { detectFramework, detectStorage, snippet, usesPassport, type Framework } from "./init.js";

const USAGE = `dbsc-toolkit <command>

Commands:
  doctor <url> [--cookie "<Cookie header>"] [--guard /api/route] [--timeout <seconds>]
      Check a running site: HTTPS, protocol routes, clock skew, the client
      SDK. With a signed-in browser's Cookie header and a guarded route, also
      checks that the cookie alone (no proof) is turned away. --timeout
      (default 30) is per request; raise it for hosts that sleep when idle.

  init [--framework express|fastify|hono|koa|nextjs|sveltekit|nestjs|node|better-auth]
       [--write <file>]
      Print the integration code for this project, detected from
      package.json. --write saves it to a new file (never overwrites).
`;

const FRAMEWORKS: Framework[] = ["express", "fastify", "hono", "koa", "nextjs", "sveltekit", "nestjs", "node", "better-auth"];

async function doctor(args: string[]): Promise<number> {
  const { values, positionals } = parseArgs({
    args,
    allowPositionals: true,
    options: {
      cookie: { type: "string" },
      guard: { type: "string" },
      "client-path": { type: "string" },
      timeout: { type: "string" },
    },
  });
  const url = positionals[0];
  if (!url) {
    process.stderr.write(USAGE);
    return 2;
  }
  if (values.guard !== undefined && !values.guard.startsWith("/")) {
    process.stderr.write(
      `--guard must be a path starting with "/", got "${values.guard}". Git Bash on Windows rewrites a leading "/" into a Windows path; run with MSYS_NO_PATHCONV=1 or write the path as //api/route.\n`,
    );
    return 2;
  }
  const timeoutSec = values.timeout === undefined ? undefined : Number(values.timeout);
  if (timeoutSec !== undefined && !(timeoutSec > 0)) {
    process.stderr.write("--timeout must be a positive number of seconds\n");
    return 2;
  }
  const results = await runDoctor(url, {
    ...(timeoutSec !== undefined && { timeoutMs: timeoutSec * 1000 }),
    ...(values.cookie !== undefined && { cookie: values.cookie }),
    ...(values.guard !== undefined && { guard: values.guard }),
    ...(values["client-path"] !== undefined && { clientPath: values["client-path"] }),
  });
  process.stdout.write(`${formatResults(results)}\n`);
  return results.some((r) => r.status === "fail") ? 1 : 0;
}

function init(args: string[]): number {
  const { values } = parseArgs({
    args,
    options: {
      framework: { type: "string" },
      write: { type: "string" },
    },
  });
  const pkgPath = join(process.cwd(), "package.json");
  const pkg = existsSync(pkgPath) ? (JSON.parse(readFileSync(pkgPath, "utf8")) as Record<string, never>) : {};
  if (values.framework !== undefined && !FRAMEWORKS.includes(values.framework as Framework)) {
    process.stderr.write(`Unknown framework "${values.framework}". Pick one of: ${FRAMEWORKS.join(", ")}\n`);
    return 2;
  }
  const fw = (values.framework as Framework | undefined) ?? detectFramework(pkg);
  const code = snippet(fw, detectStorage(pkg), usesPassport(pkg));
  if (values.write) {
    const target = join(process.cwd(), values.write);
    if (existsSync(target)) {
      process.stderr.write(`${values.write} already exists; not overwriting it.\n`);
      return 1;
    }
    writeFileSync(target, code);
    process.stdout.write(`Wrote ${values.write} (${fw}). Next: npm install dbsc-toolkit\n`);
    return 0;
  }
  process.stdout.write(`// Detected: ${fw}\n${code}`);
  return 0;
}

async function main(argv: string[]): Promise<number> {
  const [command, ...rest] = argv;
  if (command === "doctor") return doctor(rest);
  if (command === "init") return init(rest);
  process.stdout.write(USAGE);
  return command === undefined || command === "help" || command === "--help" ? 0 : 2;
}

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (err: unknown) => {
    process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`);
    process.exitCode = 1;
  },
);
