import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  KAGE_PROOF_TYPE,
  INTENT_VK_HASH,
  INTENT_VK_LEN,
  INTENT_PROOF_LEN,
  INTENT_PI_LEN,
} from "../config.js";

// The TS constants in config.ts are a hand-maintained mirror of kage_lib's globals: swap_settle consumes the
// Noir ones in-circuit, the prover and verifier-gen consume the TS ones. Nothing forced them to agree, so an
// edit to one side would drift silently and swap_settle would reject every real proof.
//
// kageVkParity pins INTENT_VK_HASH against the COMPILED artifact, which catches a circuit change that moves
// the VK. This pins the SOURCE globals, which catches the other direction: editing kage_lib without updating
// config.ts. Both seams matter; neither subsumes the other.
const LIB_NR = fileURLToPath(
  new URL("../../../circuits/kage/kage_lib/src/lib.nr", import.meta.url),
);

function noirGlobals(): Map<string, string> {
  const raw = readFileSync(LIB_NR, "utf8");
  // Strip line comments FIRST. Without this a commented-out `// pub global PROOF_TYPE: u32 = 7;` left beside
  // the live one wins the Map, and the test then compares config.ts against a dead constant and passes.
  const src = raw.replace(/\/\/[^\n]*/g, "");

  const globals = new Map<string, string>();
  // Column-0 globals only: the test modules further down the file declare indented fixtures of their own
  // (PSI_DOMAIN, SPEND, EPH_*) that are not part of the cross-language surface. `pub` is optional so that a
  // module-private constant like CT_LEN, which still mirrors a TS value, cannot hide from the pin.
  const re =
    /^(?:pub\s+)?global\s+(\w+)\s*:\s*[\w:<>\[\]; ]+?\s*=\s*([^;]+);/gm;
  for (const m of src.matchAll(re)) {
    globals.set(m[1]!, m[2]!.trim());
  }
  return globals;
}

describe("kage constant parity (TS config.ts <-> Noir kage_lib)", () => {
  const globals = noirGlobals();

  // Pinning the exact key set is what makes the check fail-closed: a NEW cross-language global added to
  // kage_lib with no TS counterpart breaks this case rather than being silently skipped.
  it("parses the Noir globals it claims to check", () => {
    expect([...globals.keys()].sort()).toEqual([
      "CT_LEN",
      "INTENT_PI_LEN",
      "INTENT_PROOF_LEN",
      "INTENT_VK_HASH",
      "INTENT_VK_LEN",
      "PROOF_TYPE",
    ]);
  });

  // CT_LEN is the DEM ciphertext width. It is module-private in Noir but is mirrored by every circuit's
  // [Field; 7] ciphertext block, which DarkPool reads at fixed offsets, so it is cross-language whether or
  // not it is `pub`. Checked against the compiled ABI rather than a second hand-written literal.
  it("CT_LEN matches the ciphertext width in the compiled deposit ABI", async () => {
    const raw = globals.get("CT_LEN");
    expect(raw).toBeDefined();

    const { circuit } = await import("../generated/deposit_circuit.js");
    const ret = (
      circuit as { abi: { return_type?: { abi_type: { fields?: unknown[] } } } }
    ).abi.return_type?.abi_type;
    const ctBlock = (ret?.fields ?? []).find(
      (f) => (f as { kind: string }).kind === "array",
    ) as { length: number } | undefined;

    expect(ctBlock, "deposit return has no ciphertext array").toBeDefined();
    expect(Number(raw)).toBe(ctBlock!.length);
  });

  const numeric: [string, number][] = [
    ["PROOF_TYPE", KAGE_PROOF_TYPE],
    ["INTENT_VK_LEN", INTENT_VK_LEN],
    ["INTENT_PROOF_LEN", INTENT_PROOF_LEN],
    ["INTENT_PI_LEN", INTENT_PI_LEN],
  ];

  for (const [name, tsValue] of numeric) {
    it(`${name} matches`, () => {
      const raw = globals.get(name);
      expect(raw, `${name} missing from kage_lib`).toBeDefined();
      expect(Number(raw)).toBe(tsValue);
    });
  }

  it("INTENT_VK_HASH matches", () => {
    const raw = globals.get("INTENT_VK_HASH");
    expect(raw).toBeDefined();
    expect(BigInt(raw!)).toBe(BigInt(INTENT_VK_HASH));
  });

  // PROOF_TYPE 6 is HONK_ZK. 7 is HN_FINAL, which UltraBuilder rejects, and that one constant was the whole
  // "recursion wall": pinning the value keeps the reason from being rediscovered the hard way.
  it("PROOF_TYPE is HONK_ZK", () => {
    expect(KAGE_PROOF_TYPE).toBe(6);
  });
});
