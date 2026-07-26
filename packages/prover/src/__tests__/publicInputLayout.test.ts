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

// withdraw_value's u128 bound is the only withdrawal ceiling; widening it to Field would not move any index.
function typeTag(t: AbiType | undefined): string {
  if (!t) return "?";
  if (t.kind === "integer")
    return `${t.sign === "unsigned" ? "u" : "i"}${t.width}`;
  if (t.kind === "field") return "F";
  return t.kind;
}

function pubParamNames(abi: Abi): string[] {
  return abi.parameters
    .filter((p) => p.visibility === "public")
    .flatMap((p) =>
      Array<string>(flatCount(p.type)).fill(`${p.name}:${typeTag(p.type)}`),
    );
}

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
  it("deposit: compliance + 11-field return = 13", () => {
    expect(layout(deposit as { abi: Abi })).toEqual({
      pub: COMPLIANCE,
      ret: 11,
      shape: "(F,F,F,F,[F;7])",
      total: 13,
    });
  });

  it("transfer: compliance + 22-field return = 24", () => {
    expect(layout(transfer as { abi: Abi })).toEqual({
      pub: COMPLIANCE,
      ret: 22,
      shape: "(F,F,F,F,F,F,[F;7],F,F,[F;7])",
      total: 24,
    });
  });

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

  it("join: compliance + 12-field return = 14", () => {
    expect(layout(join as { abi: Abi })).toEqual({
      pub: COMPLIANCE,
      ret: 12,
      shape: "(F,F,F,F,F,[F;7])",
      total: 14,
    });
  });

  it("split: compliance + 20-field return = 22", () => {
    expect(layout(split as { abi: Abi })).toEqual({
      pub: COMPLIANCE,
      ret: 20,
      shape: "(F,F,F,F,[F;7],F,F,[F;7])",
      total: 22,
    });
  });

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

  it("swap_intent: no pub params, 27-field return = 27", () => {
    expect(layout(swapIntent as { abi: Abi })).toEqual({
      pub: [],
      ret: 27,
      shape: "[F;27]",
      total: 27,
    });
  });

  it("swap_settle: compliance + timestamp, 39-field return = 42", () => {
    expect(layout(swapSettle as { abi: Abi })).toEqual({
      pub: [...COMPLIANCE, "current_timestamp:F"],
      ret: 39,
      shape: "(F,F,F,F,F,[F;7],F,F,[F;7],F,F,[F;7],F,F,[F;7])",
      total: 42,
    });
  });

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
    const w = layout(withdraw as { abi: Abi });
    const wm = layout(withdrawMultisig as { abi: Abi });
    expect([wm.pub.length, wm.ret, wm.total]).toEqual([
      w.pub.length,
      w.ret,
      w.total,
    ]);
  });
});
