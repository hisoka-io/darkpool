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

// Pins config.ts against kage_lib SOURCE globals (kageVkParity pins the compiled artifact; both directions matter).
const LIB_NR = fileURLToPath(
  new URL("../../../circuits/kage/kage_lib/src/lib.nr", import.meta.url),
);

function noirGlobals(): Map<string, string> {
  const raw = readFileSync(LIB_NR, "utf8");
  // Strip comments first, or a commented-out `global` would win the Map over the live one.
  const src = raw.replace(/\/\/[^\n]*/g, "");

  const globals = new Map<string, string>();
  // Column-0 globals only (indented test fixtures are not cross-language); `pub` optional so CT_LEN is caught.
  const re =
    /^(?:pub\s+)?global\s+(\w+)\s*:\s*[\w:<>\[\]; ]+?\s*=\s*([^;]+);/gm;
  for (const m of src.matchAll(re)) {
    globals.set(m[1]!, m[2]!.trim());
  }
  return globals;
}

describe("kage constant parity (TS config.ts <-> Noir kage_lib)", () => {
  const globals = noirGlobals();

  // Exact key set = fail-closed: a new kage_lib global with no TS mirror breaks this case.
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

  // CT_LEN = DEM ciphertext width; checked against the compiled deposit ABI, not a second literal.
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

  // PROOF_TYPE 6 = HONK_ZK; 7 (HN_FINAL) is rejected by UltraBuilder -- the recursion-wall constant.
  it("PROOF_TYPE is HONK_ZK", () => {
    expect(KAGE_PROOF_TYPE).toBe(6);
  });
});
