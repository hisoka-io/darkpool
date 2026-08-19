/**
 * Transaction-level golden vectors: the CROSS-LANGUAGE CONTRACT for assembly.
 *
 * The existing `gen_*.ts` vectors pin primitives (a hash, a KEM, a nullifier). Nothing pinned a whole
 * TRANSACTION, so a second implementation could get every primitive right and still marshal the witness
 * differently. The Nox Rust client already has a complete parallel implementation of exactly this layer, so
 * the contract it needs is the marshalled Noir `InputMap`, not a TypeScript interface it cannot consume.
 *
 * What is frozen here: for each circuit family, the marshalled witness the prover would hand to Noir, plus
 * the values the assembler derived (commitments, change, tags). A Rust implementation that produces this
 * JSON byte-for-byte is a differential oracle; one that does not has a real divergence.
 *
 * REGENERATE (only when the witness shape legitimately changes, and say why in the commit):
 *   GEN_TX_VECTORS=1 npx vitest run src/__tests__/txVectors.test.ts
 */
import { describe, it, expect } from "vitest";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { Fr } from "@aztec/foundation/fields";
import { Base8, mulPointEscalar } from "@zk-kit/baby-jubjub";
import {
  toFr,
  mintSelfNote,
  publicKey,
  type DerivedEph,
} from "@hisoka/wallets";
import {
  assembleDeposit,
  assembleWithdraw,
  assembleTransfer,
  assembleSplit,
  assembleJoin,
  type AssemblyContext,
  type SpendableNote,
  type MerkleWitnessSource,
} from "@hisoka/wallets/tx";
import { marshalNote, marshalU128, pointHex } from "../marshal.js";

const VECTORS = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../tx-vectors.json",
);

// Every input is fixed. A vector that moves because of a clock, a counter or a CSPRNG is not a vector.
const COMPLIANCE_PK = mulPointEscalar(Base8, 987654321n);
const ASSET = toFr(0x1234567890123456789012345678901234567890n);
const SPEND = toFr(789n);
const RECIPIENT_IN_KEY = toFr(31n);
const eph = (n: bigint): DerivedEph => toFr(n) as DerivedEph;

const byLeaf = new Map<string, number>();
const SIBLINGS = Array.from({ length: 32 }, (_, i) => toFr(BigInt(i) + 1n));
const ROOT = toFr(0xf00dn);

const merkle: MerkleWitnessSource = {
  witnessFor: async (leaf: Fr) => ({
    leafIndex: byLeaf.get(leaf.toString()) ?? 1,
    siblings: SIBLINGS,
    root: ROOT,
  }),
};
const ctx: AssemblyContext = { compliancePk: COMPLIANCE_PK, merkle };

async function spendable(
  value: bigint,
  leafIndex: number,
): Promise<SpendableNote> {
  const m = await mintSelfNote(
    eph(BigInt(500 + leafIndex)),
    value,
    SPEND,
    ASSET,
    COMPLIANCE_PK,
  );
  byLeaf.set(m.commitment.toString(), leafIndex);
  return {
    note: m.note,
    leaf: m.commitment,
    leafIndex,
    spendScalar: SPEND,
  };
}

/** Marshal exactly as the prover does. Divergence here IS the bug this file exists to catch. */
function marshalWithdraw(i: Record<string, unknown>): unknown {
  const c = pointHex(i["compliancePk"] as [bigint, bigint]);
  return {
    withdraw_value: marshalU128(
      "withdraw",
      "withdraw_value",
      i["withdrawValue"] as Fr,
    ),
    _recipient: (i["recipient"] as Fr).toString(),
    _intent_hash: (i["intentHash"] as Fr).toString(),
    compliance_pubkey_x: c.x,
    compliance_pubkey_y: c.y,
    old_note: marshalNote("withdraw", i["oldNote"] as never),
    spend_scalar: (i["spendScalar"] as Fr).toString(),
    old_note_index: String(i["oldNoteIndex"]),
    old_note_path: (i["oldNotePath"] as Fr[]).map((p) => p.toString()),
    change_note: marshalNote("withdraw", i["changeNote"] as never),
    change_eph: (i["changeEph"] as Fr).toString(),
  };
}

function marshalSplit(i: Record<string, unknown>): unknown {
  const c = pointHex(i["compliancePk"] as [bigint, bigint]);
  return {
    compliance_pubkey_x: c.x,
    compliance_pubkey_y: c.y,
    note_in: marshalNote("split", i["noteIn"] as never),
    spend_scalar: (i["spendScalar"] as Fr).toString(),
    index_in: String(i["indexIn"]),
    path_in: (i["pathIn"] as Fr[]).map((p) => p.toString()),
    note_out_1: marshalNote("split", i["noteOut1"] as never),
    eph_1: (i["eph1"] as Fr).toString(),
    note_out_2: marshalNote("split", i["noteOut2"] as never),
    eph_2: (i["eph2"] as Fr).toString(),
  };
}

function marshalJoin(i: Record<string, unknown>): unknown {
  const c = pointHex(i["compliancePk"] as [bigint, bigint]);
  return {
    compliance_pubkey_x: c.x,
    compliance_pubkey_y: c.y,
    note_a: marshalNote("join", i["noteA"] as never),
    spend_scalar_a: (i["spendScalarA"] as Fr).toString(),
    index_a: String(i["indexA"]),
    path_a: (i["pathA"] as Fr[]).map((p) => p.toString()),
    note_b: marshalNote("join", i["noteB"] as never),
    spend_scalar_b: (i["spendScalarB"] as Fr).toString(),
    index_b: String(i["indexB"]),
    path_b: (i["pathB"] as Fr[]).map((p) => p.toString()),
    note_out: marshalNote("join", i["noteOut"] as never),
    eph_out: (i["ephOut"] as Fr).toString(),
  };
}

async function buildVectors(): Promise<Record<string, unknown>> {
  const dep = await assembleDeposit(ctx, {
    value: 1000n,
    assetId: ASSET,
    spendScalar: SPEND,
    eph: eph(5n),
  });

  const wIn = await spendable(1000n, 1);
  const wd = await assembleWithdraw(ctx, {
    input: wIn,
    value: 300n,
    recipient: toFr(0xbeefn),
    selfSpendScalar: SPEND,
    changeEph: eph(21n),
  });

  const tIn = await spendable(1000n, 2);
  const tr = await assembleTransfer(ctx, {
    input: tIn,
    value: 250n,
    recipientInPub: publicKey(RECIPIENT_IN_KEY),
    recipientInKey: RECIPIENT_IN_KEY,
    selfSpendScalar: SPEND,
    memoEph: toFr(77n),
    changeEph: eph(78n),
  });

  const sIn = await spendable(1000n, 3);
  const sp = await assembleSplit(ctx, {
    input: sIn,
    value1: 400n,
    selfSpendScalar: SPEND,
    eph1: eph(51n),
    eph2: eph(52n),
  });

  const jA = await spendable(600n, 4);
  const jB = await spendable(400n, 9);
  const jn = await assembleJoin(ctx, {
    inputA: jA,
    inputB: jB,
    selfSpendScalar: SPEND,
    ephOut: eph(60n),
  });

  return {
    // Bump when the witness SHAPE changes, so a stale foreign implementation fails loudly not silently.
    schema: 1,
    deposit: {
      witness: {
        compliance_pubkey_x: pointHex(COMPLIANCE_PK).x,
        compliance_pubkey_y: pointHex(COMPLIANCE_PK).y,
        note: marshalNote("deposit", dep.inputs.note as never),
        eph: dep.inputs.eph.toString(),
      },
      derived: {
        commitment: dep.minted.commitment.toString(),
        tag: dep.minted.tag.toString(),
        psi: dep.minted.psi.toString(),
      },
    },
    withdraw: {
      witness: marshalWithdraw(wd.inputs),
      derived: {
        root: wd.root.toString(),
        changeCommitment: wd.change.commitment.toString(),
        changeValue: wd.change.note.value.toString(),
      },
    },
    transfer: {
      witness: {
        compliance_pubkey_x: pointHex(COMPLIANCE_PK).x,
        compliance_pubkey_y: pointHex(COMPLIANCE_PK).y,
        old_note: marshalNote("transfer", tr.inputs["oldNote"] as never),
        spend_scalar: (tr.inputs["spendScalar"] as Fr).toString(),
        old_note_index: String(tr.inputs["oldNoteIndex"]),
        old_note_path: (tr.inputs["oldNotePath"] as Fr[]).map((p) =>
          p.toString(),
        ),
        memo_note: marshalNote("transfer", tr.inputs["memoNote"] as never),
        memo_eph: (tr.inputs["memoEph"] as Fr).toString(),
        change_note: marshalNote("transfer", tr.inputs["changeNote"] as never),
        change_eph: (tr.inputs["changeEph"] as Fr).toString(),
      },
      derived: {
        root: tr.root.toString(),
        memoCommitment: tr.memo.commitment.toString(),
        memoTag: tr.memo.tag.toString(),
        memoCekWrap: tr.memo.cekWrap?.toString() ?? null,
        changeCommitment: tr.change.commitment.toString(),
      },
    },
    split: {
      witness: marshalSplit(sp.inputs),
      derived: {
        root: sp.root.toString(),
        out1: sp.out1.commitment.toString(),
        out2: sp.out2.commitment.toString(),
      },
    },
    join: {
      witness: marshalJoin(jn.inputs),
      derived: {
        root: jn.root.toString(),
        out: jn.out.commitment.toString(),
        outValue: jn.out.note.value.toString(),
      },
    },
  };
}

describe("transaction golden vectors", () => {
  it("assembly marshals byte-identically to the frozen contract", async () => {
    const built = await buildVectors();

    if (process.env["GEN_TX_VECTORS"] === "1") {
      writeFileSync(VECTORS, `${JSON.stringify(built, null, 2)}\n`);
      console.log(`wrote ${VECTORS}`);
      return;
    }

    expect(
      existsSync(VECTORS),
      "tx-vectors.json missing; regenerate with GEN_TX_VECTORS=1",
    ).toBe(true);
    const frozen: unknown = JSON.parse(readFileSync(VECTORS, "utf8"));
    expect(built).toEqual(frozen);
  });

  it("the join vector is index-ordered, which the circuit asserts", async () => {
    const built = (await buildVectors()) as {
      join: { witness: { index_a: string; index_b: string } };
    };
    expect(Number(built.join.witness.index_a)).toBeLessThan(
      Number(built.join.witness.index_b),
    );
  });
});
