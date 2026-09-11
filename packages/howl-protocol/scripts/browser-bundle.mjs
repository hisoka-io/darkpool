import { build } from "esbuild";

const FORBIDDEN_BROWSER_GLOBALS = ["process", "Buffer", "document"];
const BUNDLE_OPTIONS = {
  platform: "browser",
  format: "esm",
  bundle: true,
  write: false,
  logLevel: "silent",
};

const FORBIDDEN_GLOBAL_PROBES = [
  ["process", "export const probe = process.version;"],
  ["Buffer", 'export const probe = Buffer.from("00", "hex");'],
  ["document", "export const probe = document.body;"],
];
const ENTRYPOINTS = [
  ["root", "src/index.ts"],
  ["proving", "src/proving/index.ts"],
];

function bundleSource(buildResult, label) {
  if (buildResult.outputFiles.length !== 1) {
    throw new Error(
      `${label} produced ${buildResult.outputFiles.length} outputs; expected 1`,
    );
  }

  return buildResult.outputFiles[0].text;
}

function forbiddenGlobals(source) {
  return FORBIDDEN_BROWSER_GLOBALS.filter((globalName) =>
    new RegExp(`\\b${globalName}\\b`, "u").test(source),
  );
}

function assertNoForbiddenGlobals(source) {
  const detectedGlobals = forbiddenGlobals(source);
  if (detectedGlobals.length !== 0) {
    throw new Error(
      `browser bundle contains forbidden unresolved globals: ${detectedGlobals.join(", ")}`,
    );
  }
}

async function main() {
  for (const [label, entryPoint] of ENTRYPOINTS) {
    const buildResult = await build({
      entryPoints: [entryPoint],
      ...BUNDLE_OPTIONS,
    });
    assertNoForbiddenGlobals(
      bundleSource(buildResult, `${label} browser bundle`),
    );
  }

  for (const [globalName, contents] of FORBIDDEN_GLOBAL_PROBES) {
    const probeResult = await build({
      stdin: { contents, loader: "ts", sourcefile: "probe.ts" },
      ...BUNDLE_OPTIONS,
    });
    const detectedGlobals = forbiddenGlobals(
      bundleSource(probeResult, `${globalName} detector probe`),
    );
    if (!detectedGlobals.includes(globalName)) {
      throw new Error(
        `browser bundle detector failed to reject ${globalName} probe`,
      );
    }
  }

  console.log("howl-protocol root and proving bundles resolved without shims");
}

try {
  await main();
} catch (error) {
  console.error("howl-protocol browser bundle failed", error);
  process.exitCode = 1;
}
