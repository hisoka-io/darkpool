import {
  readFileSync,
  writeFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
} from "fs";
import { execFileSync } from "child_process";
import { resolve, dirname, join } from "path";
import { tmpdir, homedir } from "os";
import { fileURLToPath } from "url";
import { CIRCUITS, KAGE_CIRCUITS } from "./circuits.js";

// --optimized verifiers are CLI-only (bb.js hardcodes optimizedSolidityVerifier:false); bb.js proofs still verify
// against them via barretenberg#1649 (bb.js VK == CLI VK). After any .nr change, rerun `pnpm build` with native bb
// on PATH to regenerate the .sol + vk-hashes.json (and re-bless vk-hashes.golden.json); the VK-parity guard fails
// on drift if you skip it.
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const BB_PATH = process.env.BB_NATIVE_PATH ?? resolve(homedir(), ".bb", "bb");
const BB_VERSION = "5.0.0";

const circuitsDir = resolve(__dirname, "../../circuits");
const contractsDir = resolve(__dirname, "../../evm-contracts/contracts");
const verifiersDir = resolve(contractsDir, "verifiers");
const vkHashManifestPath = resolve(verifiersDir, "vk-hashes.json");

function assertNativeBb() {
  let version = "";
  try {
    version = execFileSync(BB_PATH, ["--version"], { encoding: "utf8" }).trim();
  } catch {
    throw new Error(
      `native bb not found at ${BB_PATH} (set BB_NATIVE_PATH; install via bbup -v ${BB_VERSION}). ` +
        `--optimized verifier generation is CLI-only, so native bb is required.`,
    );
  }
  if (version !== BB_VERSION) {
    throw new Error(
      `native bb version mismatch: got ${version} want ${BB_VERSION}`,
    );
  }
}

function generateOne(name, verifier) {
  const bytecode = resolve(circuitsDir, "target", `${name}.json`);
  if (!existsSync(bytecode)) {
    throw new Error(
      `Circuit artifact not found at ${bytecode}. Run "pnpm build" in the prover package first.`,
    );
  }
  const tmp = mkdtempSync(join(tmpdir(), "vk-"));
  try {
    execFileSync(
      BB_PATH,
      ["write_vk", "-b", bytecode, "-o", tmp, "-t", "evm"],
      { stdio: "pipe" },
    );
    const outPath = resolve(verifiersDir, verifier);
    execFileSync(
      BB_PATH,
      [
        "write_solidity_verifier",
        "-k",
        join(tmp, "vk"),
        "-o",
        outPath,
        "-t",
        "evm",
        "--optimized",
      ],
      { stdio: "pipe" },
    );
    const src = readFileSync(outPath, "utf8");
    const m = src.match(/uint256 constant VK_HASH = (0x[0-9a-fA-F]{64});/);
    if (!m) throw new Error(`VK_HASH not found in generated ${verifier}`);
    console.log(
      `Wrote ${verifier} (--optimized, VK_HASH ${m[1].slice(0, 10)}...)`,
    );
    return m[1];
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

function main() {
  console.log(
    "--- Generating Solidity Verifiers (native bb 5.0 --optimized) ---",
  );
  try {
    assertNativeBb();
  } catch (e) {
    // native bb absent (CI / bb.js-only): keep committed verifiers, VkHashParity guards drift.
    console.log(`[skip] ${e.message}; keeping committed verifiers.`);
    return;
  }
  if (!existsSync(verifiersDir)) mkdirSync(verifiersDir, { recursive: true });

  const vkHashes = {};
  for (const { name, verifier } of [...CIRCUITS, ...KAGE_CIRCUITS]) {
    if (!verifier) continue;
    vkHashes[name] = generateOne(name, verifier);
  }
  writeFileSync(vkHashManifestPath, JSON.stringify(vkHashes, null, 2) + "\n");
  console.log(`Wrote VK-hash manifest: ${vkHashManifestPath}`);
}

main();
