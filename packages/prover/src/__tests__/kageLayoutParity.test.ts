import { describe, it, expect } from "vitest";
import { circuit } from "../generated/swap_settle_circuit.js";
import { SETTLE_PI_LEN } from "../config.js";

// Derives swap_settle's per-index layout from the ABI and pins it against DarkPool._kage's index reads;
// SETTLE_PI_LEN follows from the ABI, never the source. Not caught: a swap of two whole (identical) note blocks.

const DARKPOOL_KAGE = {
  inputsLength: 42,
  complianceX: 0,
  complianceY: 1,
  timestamp: 2,
  takerNullifier: 3,
  makerNullifier: 4,
  root: 5,
  // _insertNote(_publicInputs, leaf, ephX, ctStart) in call order.
  notes: [
    [6, 7, 8],
    [15, 16, 17],
    [24, 25, 26],
    [33, 34, 35],
  ],
};

const CIPHERTEXT_WORDS = 7;

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
  return 1;
}

function tupleElementWidths(t: AbiType | undefined): number[] {
  if (!t || t.kind !== "tuple") return [];
  return (t.fields ?? []).map((f) => flatten(f as AbiType));
}

describe("Kage Noir<->Sol layout parity", () => {
  const abi = (
    circuit as {
      abi: {
        parameters: { name: string; visibility: string; type: AbiType }[];
        return_type?: { abi_type: AbiType };
      };
    }
  ).abi;

  const pubParams = abi.parameters.filter((p) => p.visibility === "public");
  const pubWidth = pubParams.reduce((s, p) => s + flatten(p.type), 0);

  const elemWidth = tupleElementWidths(abi.return_type?.abi_type);
  const elemOffset: number[] = [];
  let cursor = pubWidth;
  for (const w of elemWidth) {
    elemOffset.push(cursor);
    cursor += w;
  }
  const totalWidth = cursor;

  const ctElements = elemWidth.flatMap((w, i) =>
    w === CIPHERTEXT_WORDS ? [i] : [],
  );

  it("pub params are the compliance point then the timestamp, at the DarkPool._kage indices", () => {
    expect(pubParams.map((p) => p.name)).toEqual([
      "compliance_pubkey_x",
      "compliance_pubkey_y",
      "current_timestamp",
    ]);
    expect(pubParams.map((_, i) => i)).toEqual([
      DARKPOOL_KAGE.complianceX,
      DARKPOOL_KAGE.complianceY,
      DARKPOOL_KAGE.timestamp,
    ]);
    expect(pubWidth).toBe(3);
  });

  it("the return's scalar prefix lands on the nullifier and root reads", () => {
    const prefixEnd = ctElements[0] - 2;
    expect(elemWidth.slice(0, prefixEnd)).toEqual([1, 1, 1]);
    expect(elemOffset.slice(0, prefixEnd)).toEqual([
      DARKPOOL_KAGE.takerNullifier,
      DARKPOOL_KAGE.makerNullifier,
      DARKPOOL_KAGE.root,
    ]);
  });

  it("every note block is (leaf, eph.x, ciphertext[7]) at the _insertNote offsets", () => {
    // Each ciphertext array is preceded by two bare fields (leaf, eph.x) so _insertNote's triple is contiguous.
    expect(ctElements.map((i) => [elemWidth[i - 2], elemWidth[i - 1]])).toEqual(
      [
        [1, 1],
        [1, 1],
        [1, 1],
        [1, 1],
      ],
    );
    expect(
      ctElements.map((i) => [
        elemOffset[i - 2],
        elemOffset[i - 1],
        elemOffset[i],
      ]),
    ).toEqual(DARKPOOL_KAGE.notes);
  });

  it("the derived width equals the DarkPool length gate, and SETTLE_PI_LEN follows from it", () => {
    const lastNote = DARKPOOL_KAGE.notes[DARKPOOL_KAGE.notes.length - 1];
    expect(lastNote[2] + CIPHERTEXT_WORDS).toBe(DARKPOOL_KAGE.inputsLength);
    expect(totalWidth).toBe(DARKPOOL_KAGE.inputsLength);
    expect(SETTLE_PI_LEN).toBe(totalWidth);
  });
});
