import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const here = dirname(fileURLToPath(import.meta.url));
const packageRoot = join(here, "..", "..");
const packagesDir = join(packageRoot, "..");

interface Manifest {
  readonly name: string;
  readonly private?: boolean;
  readonly type?: string;
  readonly dependencies?: Readonly<Record<string, string>>;
  readonly devDependencies?: Readonly<Record<string, string>>;
}

function manifest(dir: string): Manifest {
  return JSON.parse(
    readFileSync(join(dir, "package.json"), "utf8"),
  ) as Manifest;
}

const ALLOWED_RUNTIME_DEPS = new Set([
  "@hisoka/wallets",
  "@hisoka/howl-protocol",
  "@hisoka/pss-client",
  "@hisoka/adaptors",
  "ethers",
  "@aztec/foundation",
  "@zk-kit/baby-jubjub",
]);
const ALLOWED_DEV_DEPS = new Set([
  "@hisoka/pss-server",
  "@types/node",
  "tsup",
  "typescript",
  "vitest",
]);
const FORBIDDEN = [
  /^@hisoka\/prover$/,
  /^evm-contracts$/,
  /^@hisoka-io\/nox-client$/,
  /^@hisoka\/howl-e2e$/,
  /^@hisoka\/pss-integration$/,
  /raven/i,
];
const EXACT_VERSION = /^\d+\.\d+\.\d+$/;

function sourceFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) {
      if (entry !== "__tests__") out.push(...sourceFiles(path));
    } else if (entry.endsWith(".ts")) {
      out.push(path);
    }
  }
  return out;
}

function packageOf(specifier: string): string {
  const parts = specifier.split("/");
  return specifier.startsWith("@") ? `${parts[0]}/${parts[1]}` : parts[0]!;
}

describe("package boundary", () => {
  const runtime = manifest(packageRoot);
  const deps = Object.keys(runtime.dependencies ?? {});
  const devDeps = Object.keys(runtime.devDependencies ?? {});

  it("is a private ESM package", () => {
    expect(runtime.name).toBe("@hisoka/wallet-runtime");
    expect(runtime.private).toBe(true);
    expect(runtime.type).toBe("module");
  });

  it("depends only on the allowed edges, pinned exactly", () => {
    for (const dep of deps) {
      expect(ALLOWED_RUNTIME_DEPS.has(dep), `runtime dependency ${dep}`).toBe(
        true,
      );
    }
    for (const dep of devDeps) {
      expect(ALLOWED_DEV_DEPS.has(dep), `runtime devDependency ${dep}`).toBe(
        true,
      );
    }
    for (const dep of [...deps, ...devDeps]) {
      for (const pattern of FORBIDDEN) {
        expect(pattern.test(dep), `forbidden edge ${dep}`).toBe(false);
      }
    }
    const pins = { ...runtime.dependencies, ...runtime.devDependencies };
    for (const [dep, version] of Object.entries(pins)) {
      if (dep.startsWith("@hisoka/")) {
        expect(version, dep).toBe("workspace:*");
      } else {
        expect(EXACT_VERSION.test(version), `${dep}@${version}`).toBe(true);
      }
    }
  });

  it("imports in shipped source resolve to declared dependencies", () => {
    const declared = new Set(deps);
    const files = sourceFiles(join(packageRoot, "src"));
    expect(files.length).toBeGreaterThan(0);
    for (const file of files) {
      const text = readFileSync(file, "utf8");
      for (const match of text.matchAll(/from\s+"([^".][^"]*)"/g)) {
        const specifier = match[1]!;
        if (specifier.startsWith("node:")) continue;
        expect(
          declared.has(packageOf(specifier)),
          `${file} imports ${specifier}`,
        ).toBe(true);
      }
    }
  });

  it("keeps wallets a crypto leaf", () => {
    const wallets = manifest(join(packagesDir, "wallets"));
    const edges = [
      ...Object.keys(wallets.dependencies ?? {}),
      ...Object.keys(wallets.devDependencies ?? {}),
    ];
    expect(edges).not.toContain("@hisoka/pss-client");
    expect(edges).not.toContain("@hisoka/wallet-runtime");
  });
});
