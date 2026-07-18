import { describe, it, expect } from "vitest";
import { circuit as deposit } from "../generated/deposit_circuit.js";
import { circuit as transfer } from "../generated/transfer_circuit.js";
import { circuit as withdraw } from "../generated/withdraw_circuit.js";
import { circuit as transferMultisig } from "../generated/transfer_multisig_circuit.js";

// Per-index public-input layout freeze. FreezeSeams.test.ts pins each verifier's public-input COUNT on the
// Solidity side; that does not catch a same-count reorder of a circuit's public inputs, which would silently
// shift what index DarkPool's hardcoded `_publicInputs[i]` reads land on. This pins the ORDERED layout on the
// Noir side, read from the generated circuit ABI (the same artifact the prover consumes), so a reorder,
// insertion, or removal of any public input fails here. swap_settle is covered by kageLayoutParity.test.ts.
//
// The public-input vector is the public parameters in declaration order, then the flattened return tuple.
// Noir return tuples are positional, so only the return ARITY is pinned here; the pub params carry names, and
// for withdraw those names are exactly the fields DarkPool reads at the matching index (value[0], recipient[1],
// intent_hash[2], compliance[3,4]).

type AbiType = {
  kind: string;
  length?: number;
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

// Ordered, flattened public-parameter names (one entry per field the parameter contributes).
function pubParamNames(abi: Abi): string[] {
  return abi.parameters
    .filter((p) => p.visibility === "public")
    .flatMap((p) => Array<string>(flatCount(p.type)).fill(p.name));
}

function returnArity(abi: Abi): number {
  return abi.return_type ? flatCount(abi.return_type.abi_type) : 0;
}

function layout(c: { abi: Abi }): {
  pub: string[];
  ret: number;
  total: number;
} {
  const pub = pubParamNames(c.abi);
  const ret = returnArity(c.abi);
  return { pub, ret, total: pub.length + ret };
}

describe("public-input layout freeze (Noir ABI order)", () => {
  it("deposit: [compliance_x, compliance_y] + 11-field return = 13", () => {
    expect(layout(deposit as { abi: Abi })).toEqual({
      pub: ["compliance_pubkey_x", "compliance_pubkey_y"],
      ret: 11,
      total: 13,
    });
  });

  it("transfer: [compliance_x, compliance_y] + 22-field return = 24", () => {
    expect(layout(transfer as { abi: Abi })).toEqual({
      pub: ["compliance_pubkey_x", "compliance_pubkey_y"],
      ret: 22,
      total: 24,
    });
  });

  // withdraw's named pub params map one-to-one onto DarkPool's index reads:
  // _publicInputs[0]=withdraw_value, [1]=recipient, [2]=intent_hash, [3,4]=compliance.
  it("withdraw: named pub-param prefix matches the DarkPool index reads, + 12-field return = 17", () => {
    expect(layout(withdraw as { abi: Abi })).toEqual({
      pub: [
        "withdraw_value",
        "_recipient",
        "_intent_hash",
        "compliance_pubkey_x",
        "compliance_pubkey_y",
      ],
      ret: 12,
      total: 17,
    });
  });

  it("transfer_multisig: shares the transfer layout (twin) = 24", () => {
    expect(layout(transferMultisig as { abi: Abi })).toEqual({
      pub: ["compliance_pubkey_x", "compliance_pubkey_y"],
      ret: 22,
      total: 24,
    });
  });
});
