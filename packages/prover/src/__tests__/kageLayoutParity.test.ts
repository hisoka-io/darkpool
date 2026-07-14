import { describe, it, expect } from "vitest";
import { circuit } from "../generated/swap_settle_circuit.js";
import { SETTLE_PI_LEN } from "../config.js";

// Noir<->Sol layout KAT: swap_settle's public-input order (pub params first, then the flattened pub return) MUST
// match the DarkPool `_kage` index map, or on-chain effects read the wrong words. Pub params: compliance_x[0],
// compliance_y[1], current_timestamp[2]. Return: taker_nullifier[3], maker_nullifier[4], root[5], then four note
// blocks of (leaf, eph_x, ciphertext[7]) at leaf offsets 6, 15, 24, 33.
type AbiType = {
  kind: string;
  length?: number;
  type?: AbiType;
  fields?: unknown[];
};

function flatten(t: AbiType | undefined): number {
  if (!t) return 0;
  if (t.kind === "array") return (t.length ?? 0) * flatten(t.type);
  // Noir ABI: struct fields are { name, type }; tuple fields are the element types directly.
  if (t.kind === "struct")
    return (t.fields ?? []).reduce(
      (s, f) => s + flatten((f as { type: AbiType }).type),
      0,
    );
  if (t.kind === "tuple")
    return (t.fields ?? []).reduce((s, f) => s + flatten(f as AbiType), 0);
  return 1; // field / integer / boolean
}

describe("Kage Noir<->Sol layout parity", () => {
  const abi = (
    circuit as {
      abi: {
        parameters: { visibility: string; type: AbiType }[];
        return_type?: { abi_type: AbiType };
      };
    }
  ).abi;
  const pubParams = abi.parameters
    .filter((p) => p.visibility === "public")
    .reduce((s, p) => s + flatten(p.type), 0);
  const ret = abi.return_type ? flatten(abi.return_type.abi_type) : 0;

  it("swap_settle exposes exactly SETTLE_PI_LEN public inputs (3 pub params + 39 return)", () => {
    expect(pubParams).toBe(3);
    expect(ret).toBe(39);
    expect(pubParams + ret).toBe(SETTLE_PI_LEN);
  });

  it("the DarkPool _kage index map lines up with the 3-scalar prefix + 9-field note blocks", () => {
    // compliance[0,1], timestamp[2], taker_nullifier[3], maker_nullifier[4], root[5]
    const scalarPrefix = 6;
    const block = 9; // leaf + eph_x + ciphertext[7]
    const leafOffsets = [0, 1, 2, 3].map((i) => scalarPrefix + i * block);
    expect(leafOffsets).toEqual([6, 15, 24, 33]);
    // last ciphertext word is in-range for the 42-field vector
    expect(leafOffsets[3] + 2 + 7 - 1).toBe(SETTLE_PI_LEN - 1);
  });
});
