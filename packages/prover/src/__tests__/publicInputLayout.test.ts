import { describe, it, expect } from "vitest";
import { circuit as deposit } from "../generated/deposit_circuit.js";
import { circuit as transfer } from "../generated/transfer_circuit.js";
import { circuit as withdraw } from "../generated/withdraw_circuit.js";
import { circuit as join } from "../generated/join_circuit.js";
import { circuit as split } from "../generated/split_circuit.js";
import { circuit as publicClaim } from "../generated/public_claim_circuit.js";
import { circuit as transferMultisig } from "../generated/transfer_multisig_circuit.js";
import { circuit as withdrawMultisig } from "../generated/withdraw_multisig_circuit.js";
import { circuit as joinMultisig } from "../generated/join_multisig_circuit.js";
import { circuit as splitMultisig } from "../generated/split_multisig_circuit.js";
import { circuit as swapIntent } from "../generated/swap_intent_circuit.js";
import { circuit as swapSettle } from "../generated/swap_settle_circuit.js";

// Per-index public-input layout freeze. FreezeSeams.test.ts pins each verifier's public-input COUNT on the
// Solidity side; that does not catch a same-count reorder of a circuit's public inputs, which would silently
// shift what index DarkPool's hardcoded `_publicInputs[i]` reads land on. This pins the ORDERED layout on the
// Noir side, read from the generated circuit ABI (the same artifact the prover consumes), so a reorder,
// insertion, or removal of any public input fails here. kageLayoutParity.test.ts additionally derives
// swap_settle's per-index map and pins it against the DarkPool._kage reads.
//
// Scope, stated honestly: pub params are pinned by NAME and order; the return tuple is pinned by flattened
// SHAPE (field vs sized array, in position). A transposition of two adjacent bare Fields inside the return is
// therefore NOT caught here, since nothing in the ABI distinguishes them, and neither is a permutation
// inside a [Field;7] ciphertext block. RealProofE2E does NOT close that gap by mutation (a transposed circuit
// still yields internally consistent proofs, so every single-input bump still rejects); what covers it there
// is the positive path plus its explicit index assertions, e.g. isNullifierSpent(publicInputs[5]).
//
// The public-input vector is the public parameters in declaration order, then the flattened return tuple.
// Noir return tuples are positional, so only the return ARITY is pinned; pub params carry names. Each case
// below records the DarkPool index reads the layout has to keep valid.

type AbiType = {
  kind: string;
  length?: number;
  width?: number;
  sign?: string;
  type?: AbiType;
  fields?: unknown[];
};
type Abi = {
  parameters: { name: string; visibility: string; type: AbiType }[];
  return_type?: { abi_type: AbiType };
};

function flatCount(t: AbiType | undefined): number {
  if (!t) return 0;
  if (t.kind === "array") return (t.length ?? 0) * flatCount(t.type);
  if (t.kind === "struct")
    return (t.fields ?? []).reduce(
      (s, f) => s + flatCount((f as { type: AbiType }).type),
      0,
    );
  if (t.kind === "tuple")
    return (t.fields ?? []).reduce((s, f) => s + flatCount(f as AbiType), 0);
  return 1;
}

// A pub param's TYPE is load-bearing, not decoration: withdraw_value is `pub u128` and that range bound is
// the ONLY ceiling on a withdrawal, since DarkPool.sol reads uint256(_publicInputs[0]) unbounded. Widening it
// to `pub Field` leaves every name, count and index identical, so a name-only pin would accept it.
function typeTag(t: AbiType | undefined): string {
  if (!t) return "?";
  if (t.kind === "integer")
    return `${t.sign === "unsigned" ? "u" : "i"}${t.width}`;
  if (t.kind === "field") return "F";
  return t.kind;
}

// Ordered, flattened public parameters as `name:type` (one entry per field the parameter contributes).
function pubParamNames(abi: Abi): string[] {
  return abi.parameters
    .filter((p) => p.visibility === "public")
    .flatMap((p) =>
      Array<string>(flatCount(p.type)).fill(`${p.name}:${typeTag(p.type)}`),
    );
}

// The return tuple is positional, so names do not exist to pin. Pinning the flattened SHAPE instead of a
// bare count is what catches a reorder: moving a [field;7] ciphertext block leaves the count untouched while
// shifting every _insertNote(_publicInputs, leaf, ephX, ct) offset DarkPool reads at.
function returnShape(t: AbiType | undefined): string {
  if (!t) return "";
  if (t.kind === "array") return `[${returnShape(t.type)};${t.length}]`;
  if (t.kind === "struct")
    return `{${(t.fields ?? []).map((f) => returnShape((f as { type: AbiType }).type)).join(",")}}`;
  if (t.kind === "tuple")
    return `(${(t.fields ?? []).map((f) => returnShape(f as AbiType)).join(",")})`;
  return "F";
}

function returnArity(abi: Abi): number {
  return abi.return_type ? flatCount(abi.return_type.abi_type) : 0;
}

function layout(c: { abi: Abi }): {
  pub: string[];
  ret: number;
  shape: string;
  total: number;
} {
  const pub = pubParamNames(c.abi);
  const ret = returnArity(c.abi);
  return {
    pub,
    ret,
    shape: returnShape(c.abi.return_type?.abi_type),
    total: pub.length + ret,
  };
}

const COMPLIANCE = ["compliance_pubkey_x:F", "compliance_pubkey_y:F"];

describe("public-input layout freeze (Noir ABI order)", () => {
  // DarkPool.deposit: [0,1]=compliance, [4]=value, [5]=asset.
  // Return (leaf, eph.x, value, asset_id, ciphertext[7]) occupies [2..12].
  it("deposit: compliance + 11-field return = 13", () => {
    expect(layout(deposit as { abi: Abi })).toEqual({
      pub: COMPLIANCE,
      ret: 11,
      shape: "(F,F,F,F,[F;7])",
      total: 13,
    });
  });

  // DarkPool._transfer: [0,1]=compliance, [2]=nullifier, [3]=root.
  it("transfer: compliance + 22-field return = 24", () => {
    expect(layout(transfer as { abi: Abi })).toEqual({
      pub: COMPLIANCE,
      ret: 22,
      shape: "(F,F,F,F,F,F,[F;7],F,F,[F;7])",
      total: 24,
    });
  });

  // DarkPool._withdraw: [0]=withdraw_value, [1]=recipient, [3,4]=compliance, [5]=nullifier, [6]=root,
  // [7]=asset. The named pub-param prefix maps one-to-one onto those index reads.
  it("withdraw: named pub-param prefix matches the DarkPool index reads, + 12-field return = 17", () => {
    expect(layout(withdraw as { abi: Abi })).toEqual({
      pub: [
        "withdraw_value:u128",
        "_recipient:F",
        "_intent_hash:F",
        ...COMPLIANCE,
      ],
      ret: 12,
      shape: "(F,F,F,F,F,[F;7])",
      total: 17,
    });
  });

  // DarkPool._join: [0,1]=compliance, [2]=nullifier_a, [3]=nullifier_b, [4]=root.
  it("join: compliance + 12-field return = 14", () => {
    expect(layout(join as { abi: Abi })).toEqual({
      pub: COMPLIANCE,
      ret: 12,
      shape: "(F,F,F,F,F,[F;7])",
      total: 14,
    });
  });

  // DarkPool._split: [0,1]=compliance, [2]=nullifier, [3]=root.
  it("split: compliance + 20-field return = 22", () => {
    expect(layout(split as { abi: Abi })).toEqual({
      pub: COMPLIANCE,
      ret: 20,
      shape: "(F,F,F,F,[F;7],F,F,[F;7])",
      total: 22,
    });
  });

  // DarkPool.publicClaim: [0]=memo_id, [1,2]=compliance, [3]=current_timestamp.
  // memo_id leads here, unlike every other circuit, so the ordering is load-bearing.
  it("public_claim: memo_id leads the pub params, + 9-field return = 13", () => {
    expect(layout(publicClaim as { abi: Abi })).toEqual({
      pub: ["memo_id:F", ...COMPLIANCE, "current_timestamp:F"],
      ret: 9,
      shape: "(F,F,[F;7])",
      total: 13,
    });
  });

  it("transfer_multisig: shares the transfer layout (twin) = 24", () => {
    expect(layout(transferMultisig as { abi: Abi })).toEqual({
      pub: COMPLIANCE,
      ret: 22,
      shape: "(F,F,F,F,F,F,[F;7],F,F,[F;7])",
      total: 24,
    });
  });

  // Twin of withdraw, but the pub params are named without the leading underscore. The DarkPool index
  // reads are shared, so the ARITY and ORDER must stay identical even though the names differ.
  it("withdraw_multisig: shares the withdraw layout (twin) = 17", () => {
    expect(layout(withdrawMultisig as { abi: Abi })).toEqual({
      pub: [
        "withdraw_value:u128",
        "recipient:F",
        "intent_hash:F",
        ...COMPLIANCE,
      ],
      ret: 12,
      shape: "(F,F,F,F,F,[F;7])",
      total: 17,
    });
  });

  it("join_multisig: shares the join layout (twin) = 14", () => {
    expect(layout(joinMultisig as { abi: Abi })).toEqual({
      pub: COMPLIANCE,
      ret: 12,
      shape: "(F,F,F,F,F,[F;7])",
      total: 14,
    });
  });

  it("split_multisig: shares the split layout (twin) = 22", () => {
    expect(layout(splitMultisig as { abi: Abi })).toEqual({
      pub: COMPLIANCE,
      ret: 20,
      shape: "(F,F,F,F,[F;7],F,F,[F;7])",
      total: 22,
    });
  });

  // Kage inner. Nothing is a pub PARAMETER: the whole vector is the returned [Field; INTENT_PI_LEN], which
  // swap_settle consumes positionally as `intent_public_inputs`. A change to this arity breaks that seam.
  it("swap_intent: no pub params, 27-field return = 27", () => {
    expect(layout(swapIntent as { abi: Abi })).toEqual({
      pub: [],
      ret: 27,
      shape: "[F;27]",
      total: 27,
    });
  });

  // Kage outer, the widest return in the set. DarkPool._kage: [0,1]=compliance, [2]=current_timestamp,
  // [3,4]=nullifiers, [5]=root, then four (leaf, eph.x, ciphertext[7]) blocks at leaf offsets 6, 15, 24, 33.
  // The four blocks are what the shape has to hold in place: moving one shifts every _insertNote offset.
  it("swap_settle: compliance + timestamp, 39-field return = 42", () => {
    expect(layout(swapSettle as { abi: Abi })).toEqual({
      pub: [...COMPLIANCE, "current_timestamp:F"],
      ret: 39,
      shape: "(F,F,F,F,F,[F;7],F,F,[F;7],F,F,[F;7],F,F,[F;7])",
      total: 42,
    });
  });

  // The standard/multisig twins share DarkPool's index reads, so a change to one alone is a parity break
  // that the per-circuit cases above would each still accept.
  it("standard and multisig twins have identical layouts", () => {
    const pairs: [string, { abi: Abi }, { abi: Abi }][] = [
      ["transfer", transfer as { abi: Abi }, transferMultisig as { abi: Abi }],
      ["join", join as { abi: Abi }, joinMultisig as { abi: Abi }],
      ["split", split as { abi: Abi }, splitMultisig as { abi: Abi }],
    ];
    for (const [name, std, multi] of pairs) {
      expect(layout(multi), `${name}_multisig drifted from ${name}`).toEqual(
        layout(std),
      );
    }
    // withdraw's twin renames the pub params, so only arity and order are comparable.
    const w = layout(withdraw as { abi: Abi });
    const wm = layout(withdrawMultisig as { abi: Abi });
    expect([wm.pub.length, wm.ret, wm.total]).toEqual([
      w.pub.length,
      w.ret,
      w.total,
    ]);
  });
});
