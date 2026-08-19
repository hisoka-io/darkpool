import { describe, it, expect } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import { Base8, mulPointEscalar } from "@zk-kit/baby-jubjub";
import { toFr } from "../crypto/fields.js";
import { PARENTS_HIDDEN, packParents } from "../note/note.js";
import { publicKey, pubkeyOwner } from "../note/keys.js";
import type { DerivedEph } from "../types/ephemeral.js";
import {
  assembleDeposit,
  assembleWithdraw,
  assembleTransfer,
  assembleSplit,
  assembleJoin,
  AssemblyError,
  type AssemblyContext,
  type SpendableNote,
} from "../tx/assemble.js";
import { mintSelfNote } from "../note/mint.js";
import type { MerkleWitnessSource } from "../tx/ports.js";

const COMPLIANCE_PK = mulPointEscalar(Base8, 987654321n);
const ASSET = toFr(0x1234567890123456789012345678901234567890n);
const SPEND = toFr(789n);
const eph = (n: bigint): DerivedEph => toFr(n) as DerivedEph;

/** Populated by `spendable()` so the stub agrees with the wallet about where each note sits. */
const byLeaf = new Map<string, number>();

/** Stub source. Resolves the index per LEAF, because the assembler cross-checks it against the wallet's. */
function source(index: number, root = toFr(0xf00dn)): MerkleWitnessSource {
  return {
    witnessFor: async (leaf: Fr) => ({
      leafIndex: byLeaf.get(leaf.toString()) ?? index,
      siblings: Array.from({ length: 32 }, () => toFr(0n)),
      root,
    }),
  };
}

async function spendable(
  value: bigint,
  leafIndex: number,
): Promise<SpendableNote> {
  // Distinct ephemeral per note so two notes of equal value are still distinct leaves.
  const m = await mintSelfNote(
    eph(BigInt(100 + leafIndex)),
    value,
    SPEND,
    ASSET,
    COMPLIANCE_PK,
  );
  byLeaf.set(m.commitment.toString(), leafIndex);
  return { note: m.note, leaf: m.commitment, leafIndex, spendScalar: SPEND };
}

const ctx = (index: number, root?: Fr): AssemblyContext => ({
  compliancePk: COMPLIANCE_PK,
  merkle: source(index, root),
});

describe("assembleDeposit", () => {
  it("mints a self note the depositor owns", async () => {
    const a = await assembleDeposit(ctx(1), {
      value: 100n,
      assetId: ASSET,
      spendScalar: SPEND,
      eph: eph(5n),
    });
    expect(a.inputs.note.value.toBigInt()).toBe(100n);
    expect(a.minted.commitment).toBeInstanceOf(Fr);
    // A self note's discovery tag IS the ephemeral's own public x.
    expect(a.minted.tag.toBigInt()).toBe(publicKey(eph(5n))[0]);
  });
});

describe("assembleWithdraw", () => {
  it("computes change and binds it to the consumed leaf", async () => {
    const input = await spendable(100n, 7);
    const a = await assembleWithdraw(ctx(7), {
      input,
      value: 30n,
      recipient: toFr(0xbeefn),
      selfSpendScalar: SPEND,
      changeEph: eph(21n),
    });
    expect(a.change.note.value.toBigInt()).toBe(70n);
    expect(a.change.note.parents.toString()).toBe(
      packParents([{ leafIndex: 7 }, { leafIndex: 0 }]).toString(),
    );
  });

  it("fails CLOSED when the value exceeds the note", async () => {
    const input = await spendable(10n, 3);
    await expect(
      assembleWithdraw(ctx(3), {
        input,
        value: 999n,
        recipient: toFr(1n),
        selfSpendScalar: SPEND,
        changeEph: eph(2n),
      }),
    ).rejects.toThrow(AssemblyError);
  });

  it("refuses a merkle source that places the note somewhere else", async () => {
    const input = await spendable(10n, 3);
    // A LYING source: says index 9 while the wallet holds 3. Building on it would derive a nullifier for a
    // leaf the wallet does not own, so assembly must refuse rather than emit an unusable proof.
    const lying: AssemblyContext = {
      compliancePk: COMPLIANCE_PK,
      merkle: {
        witnessFor: async () => ({
          leafIndex: 9,
          siblings: Array.from({ length: 32 }, () => toFr(0n)),
          root: toFr(0xf00dn),
        }),
      },
    };
    await expect(
      assembleWithdraw(lying, {
        input,
        value: 1n,
        recipient: toFr(1n),
        selfSpendScalar: SPEND,
        changeEph: eph(2n),
      }),
    ).rejects.toThrow(/MERKLE_INDEX_MISMATCH|index/);
  });
});

describe("assembleTransfer", () => {
  it("forces the memo parents to PARENTS_HIDDEN", async () => {
    const input = await spendable(100n, 4);
    const a = await assembleTransfer(ctx(4), {
      input,
      value: 25n,
      recipientInPub: publicKey(toFr(31n)),
      recipientInKey: toFr(31n),
      selfSpendScalar: SPEND,
      memoEph: toFr(77n),
      changeEph: eph(78n),
    });
    // The circuit asserts this, and it is what hides the sender's leaf index from the recipient.
    expect(a.memo.note.parents.toString()).toBe(PARENTS_HIDDEN.toString());
    expect(a.change.note.value.toBigInt()).toBe(75n);
    // An incoming note's tag is the RECIPIENT's key, never the ephemeral's.
    expect(a.memo.tag.toBigInt()).toBe(publicKey(toFr(31n))[0]);
    expect(a.memo.cekWrap).toBeDefined();
  });
});

describe("assembleSplit", () => {
  it("conserves value across both outputs", async () => {
    const input = await spendable(100n, 2);
    const a = await assembleSplit(ctx(2), {
      input,
      value1: 40n,
      selfSpendScalar: SPEND,
      eph1: eph(51n),
      eph2: eph(52n),
    });
    expect(a.out1.note.value.toBigInt()).toBe(40n);
    expect(a.out2.note.value.toBigInt()).toBe(60n);
    expect(a.out1.note.assetId.toString()).toBe(a.out2.note.assetId.toString());
  });

  it("rejects a reused ephemeral across the two outputs", async () => {
    const input = await spendable(100n, 2);
    await expect(
      assembleSplit(ctx(2), {
        input,
        value1: 40n,
        selfSpendScalar: SPEND,
        eph1: eph(51n),
        eph2: eph(51n),
      }),
    ).rejects.toThrow(/EPHEMERAL_REUSE|distinct/);
  });
});

describe("assembleJoin", () => {
  it("sorts the pair ascending regardless of argument order", async () => {
    const hi = await spendable(30n, 9);
    const lo = await spendable(20n, 4);
    const a = await assembleJoin(ctx(0), {
      inputA: hi,
      inputB: lo,
      selfSpendScalar: SPEND,
      ephOut: eph(60n),
    });
    expect(a.inputs["indexA"]).toBe(4);
    expect(a.inputs["indexB"]).toBe(9);
  });

  it("refuses to join a note with itself", async () => {
    const n = await spendable(20n, 4);
    await expect(
      assembleJoin(ctx(4), {
        inputA: n,
        inputB: n,
        selfSpendScalar: SPEND,
        ephOut: eph(60n),
      }),
    ).rejects.toThrow(/JOIN_SELF|itself/);
  });

  it("sums both inputs into the output", async () => {
    const a1 = await spendable(20n, 4);
    const b1 = await spendable(30n, 9);
    const a = await assembleJoin(ctx(0), {
      inputA: a1,
      inputB: b1,
      selfSpendScalar: SPEND,
      ephOut: eph(60n),
    });
    expect(a.out.note.value.toBigInt()).toBe(50n);
  });
});

// REGRESSION. The assemblers first reused `input.spendScalar` to own the change, which is correct only when
// the input is a self note. Spending a RECEIVED note opens with the per-address incoming key, so the change
// was minted under that key instead of the wallet's self-spend key and the wallet's own scanner then
// rejected it at the leaf check. Caught by the multi-hop economy test, not by any unit test, so pin it here.
describe("output ownership is independent of input ownership", () => {
  it("owns change with the self-spend key even when the input opens with another key", async () => {
    const INCOMING_KEY = toFr(4242n);
    const received = await mintSelfNote(
      eph(31n),
      100n,
      INCOMING_KEY,
      ASSET,
      COMPLIANCE_PK,
    );
    byLeaf.set(received.commitment.toString(), 5);

    const a = await assembleWithdraw(ctx(5), {
      input: {
        note: received.note,
        leaf: received.commitment,
        leafIndex: 5,
        spendScalar: INCOMING_KEY,
      },
      value: 40n,
      recipient: toFr(1n),
      selfSpendScalar: SPEND,
      changeEph: eph(32n),
    });

    const selfOwned = await pubkeyOwner(publicKey(SPEND));
    const incomingOwned = await pubkeyOwner(publicKey(INCOMING_KEY));
    expect(a.change.note.owner.toString()).toBe(selfOwned.toString());
    expect(a.change.note.owner.toString()).not.toBe(incomingOwned.toString());
  });
});
