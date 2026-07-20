import { describe, it, expect } from "vitest";
import { circuit } from "../generated/swap_settle_circuit.js";
import { SETTLE_PI_LEN } from "../config.js";

// swap_settle's per-index public-input semantics are pinned against the two artifacts that define them: the
// Noir signature (kage/swap_settle/src/main.nr), read out of the generated ABI the prover consumes, and the
// hardcoded index reads of DarkPool._kage, transcribed below. Every index is DERIVED from the ABI here, so
// SETTLE_PI_LEN is a checked consequence and never the source: a circuit-side reorder cannot be absorbed by
// editing the constant. publicInputLayout.test.ts pins the same circuit's pub-param names/types and return
// shape alongside the other eleven.
//
// Scope, stated honestly: the four note blocks are structurally identical, so a swap of two whole blocks is
// not caught here. It is also not an on-chain effect difference (all four are self-notes inserted by the same
// _insertNote call), only an event-ordering one. What is caught is any shift of a leaf, eph.x, or ciphertext
// word relative to the offsets _insertNote copies from.

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
  return 1; // field / integer / boolean
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
    // Each ciphertext array must be preceded by exactly two bare fields; that is what makes the triple
    // _insertNote copies from contiguous.
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
