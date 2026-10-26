import { describe, it, expect } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import { Base8, mulPointEscalar, type Point } from "@zk-kit/baby-jubjub";
import { toFr } from "../crypto/fields.js";
import { BJJ_SUBGROUP_ORDER } from "../crypto/constants.js";
import { unwrapCek } from "../crypto/kem.js";
import { demDecrypt, demEncrypt } from "../crypto/dem.js";
import { LeanIMT } from "../merkle/LeanIMT.js";
import { TREE_DEPTH } from "../merkle/genesis.js";
import { computePsi } from "../note/nullifier.js";
import { leaf, PARENTS_HIDDEN, packParents } from "../note/note.js";
import { isEvenY, publicKey, pubkeyOwner, recoverEvenY } from "../note/keys.js";
import {
  markDerivedSelfMintCandidate,
  type DerivedEph,
} from "../types/ephemeral.js";
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
import { MemoMintError, mintSelfNote } from "../note/mint.js";
import type { MerkleWitnessSource } from "../tx/ports.js";
import { LocalTreeWitnessSource } from "../tx/witnessSources.js";
import { completeComplianceHistory } from "../note/complianceKeys.js";
import { SelfMintPreflight } from "../discovery/preflight.js";
import {
  CIPHERTEXT_KEPT_INDICES,
  COMMITMENT_PREFIX_BYTES,
  HOWL_NOTE_LAYOUT_VERSION,
  RECORD_KIND_INCOMING,
  type DiscoverySource,
  type HowlNoteRecord,
} from "../discovery/types.js";

const COMPLIANCE_PK = mulPointEscalar(Base8, 987654321n);
const ASSET = toFr(0x1234567890123456789012345678901234567890n);
const SPEND = toFr(789n);
const eph = (n: bigint): DerivedEph => toFr(n) as DerivedEph;
const COMPLIANCE_HISTORY = completeComplianceHistory({
  genesisPk: COMPLIANCE_PK,
  rotations: [],
  currentPk: COMPLIANCE_PK,
  currentVersion: 1,
});
const DOMAIN = {
  chainId: 31337n,
  poolAddress: "0x0000000000000000000000000000000000000001",
  deploymentAnchor: 1n,
};
const MISS_RECORD: HowlNoteRecord = {
  layoutVersion: HOWL_NOTE_LAYOUT_VERSION,
  recordKind: RECORD_KIND_INCOMING,
  leafIndex: 0,
  commitmentPrefix: new Uint8Array(COMMITMENT_PREFIX_BYTES),
  ephemeralPkX: Fr.ZERO,
  cekWrap: Fr.ZERO,
  ciphertextKept: CIPHERTEXT_KEPT_INDICES.map(() => Fr.ZERO),
};

const emptyDiscovery: DiscoverySource = {
  probeFirst: (tags) =>
    Promise.resolve(
      tags.map((tag) => ({ tag, record: MISS_RECORD, occurrenceCount: 0 })),
    ),
  fetchOccurrences: () => Promise.resolve([]),
  fetchLeafBlock: () => Promise.resolve([]),
};

async function preflighted(n: bigint) {
  const scalar = eph(n);
  const ephPub = publicKey(scalar);
  const ownerCommitment = await pubkeyOwner(publicKey(SPEND));
  const preflight = new SelfMintPreflight({
    allocator: {
      next: () =>
        Promise.resolve(
          markDerivedSelfMintCandidate(
            {
              eph: scalar,
              ephPub,
              tag: new Fr(ephPub[0]),
              index: Number(n),
            },
            ownerCommitment,
          ),
        ),
    },
    discovery: emptyDiscovery,
    history: COMPLIANCE_HISTORY,
    ownerCommitment,
    domain: DOMAIN,
  });
  return (await preflight.take(1))[0];
}

/** The latest leaf placed at each index, so the tree agrees with the wallet about where each note sits. */
const placed = new Map<number, Fr>();

/** A real LeanIMT over the placed notes, filler leaves elsewhere, so every witness folds to its root. */
async function placedTree(): Promise<LeanIMT> {
  const tree = new LeanIMT(TREE_DEPTH);
  const top = Math.max(0, ...placed.keys());
  for (let i = 0; i <= top; i++) {
    await tree.insert(placed.get(i) ?? toFr(BigInt(0x10000 + i)));
  }
  return tree;
}

function source(): MerkleWitnessSource {
  return {
    witnessFor: async (leafValue: Fr, expectedLeafIndex: number) =>
      new LocalTreeWitnessSource(await placedTree()).witnessFor(
        leafValue,
        expectedLeafIndex,
      ),
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
  placed.set(leafIndex, m.commitment);
  return { note: m.note, leaf: m.commitment, leafIndex, spendScalar: SPEND };
}

const ctx = (): AssemblyContext => ({
  compliancePk: COMPLIANCE_PK,
  complianceVersion: 1,
  complianceHistory: COMPLIANCE_HISTORY,
  ...DOMAIN,
  merkle: source(),
});

async function expectAssemblyError(
  pending: Promise<unknown>,
  reason: string,
): Promise<void> {
  const err: unknown = await pending.then(
    () => null,
    (e: unknown) => e,
  );
  expect(err).toBeInstanceOf(AssemblyError);
  expect((err as AssemblyError).reason).toBe(reason);
}

describe("assembleDeposit", () => {
  it("mints a self note the depositor owns", async () => {
    const a = await assembleDeposit(ctx(), {
      value: 100n,
      assetId: ASSET,
      spendScalar: SPEND,
      selfMint: await preflighted(5n),
    });
    expect(a.inputs.note.value.toBigInt()).toBe(100n);
    expect(a.minted.commitment).toBeInstanceOf(Fr);
    // A self note's discovery tag IS the ephemeral's own public x.
    expect(a.minted.tag.toBigInt()).toBe(publicKey(eph(5n))[0]);
  });

  it("consumes one authorization once and rejects runtime forgeries", async () => {
    const authorization = await preflighted(70n);
    const request = {
      value: 10n,
      assetId: ASSET,
      spendScalar: SPEND,
      selfMint: authorization,
    };
    await expect(assembleDeposit(ctx(), request)).resolves.toBeDefined();
    await expect(assembleDeposit(ctx(), request)).rejects.toThrow(/consumed/);

    await expect(
      Reflect.apply(assembleDeposit, undefined, [
        ctx(),
        { ...request, selfMint: {} },
      ]),
    ).rejects.toThrow(/unknown|copied/);
  });

  it("checks owner and compliance context before consuming", async () => {
    const authorization = await preflighted(71n);
    await expect(
      assembleDeposit(ctx(), {
        value: 10n,
        assetId: ASSET,
        spendScalar: toFr(999n),
        selfMint: authorization,
      }),
    ).rejects.toThrow(/context/);
    await expect(
      assembleDeposit(
        { ...ctx(), complianceVersion: 2 },
        {
          value: 10n,
          assetId: ASSET,
          spendScalar: SPEND,
          selfMint: authorization,
        },
      ),
    ).rejects.toThrow(/context/);
    await expect(
      assembleDeposit(ctx(), {
        value: 10n,
        assetId: ASSET,
        spendScalar: SPEND,
        selfMint: authorization,
      }),
    ).resolves.toBeDefined();
  });

  it("does not burn authorization on request validation failure", async () => {
    const authorization = await preflighted(72n);
    await expect(
      assembleDeposit(ctx(), {
        value: -1n,
        assetId: ASSET,
        spendScalar: SPEND,
        selfMint: authorization,
      }),
    ).rejects.toThrow(AssemblyError);
    await expect(
      assembleDeposit(ctx(), {
        value: 1n,
        assetId: ASSET,
        spendScalar: SPEND,
        selfMint: authorization,
      }),
    ).resolves.toBeDefined();
  });
});

describe("assembleWithdraw", () => {
  it("computes change and binds it to the consumed leaf", async () => {
    const input = await spendable(100n, 7);
    const a = await assembleWithdraw(ctx(), {
      input,
      value: 30n,
      recipient: toFr(0xbeefn),
      selfSpendScalar: SPEND,
      changeMint: await preflighted(21n),
    });
    expect(a.change.note.value.toBigInt()).toBe(70n);
    expect(a.change.note.parents.toString()).toBe(
      packParents([{ leafIndex: 7 }, { leafIndex: 0 }]).toString(),
    );
  });

  it("fails CLOSED when the value exceeds the note", async () => {
    const input = await spendable(10n, 3);
    await expect(
      assembleWithdraw(ctx(), {
        input,
        value: 999n,
        recipient: toFr(1n),
        selfSpendScalar: SPEND,
        changeMint: await preflighted(2n),
      }),
    ).rejects.toThrow(AssemblyError);
  });

  it("refuses a merkle source that places the note somewhere else", async () => {
    const input = await spendable(10n, 3);
    // A LYING source: says index 9 while the wallet holds 3. Building on it would derive a nullifier for a
    // leaf the wallet does not own, so assembly must refuse rather than emit an unusable proof.
    const lying: AssemblyContext = {
      ...ctx(),
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
        changeMint: await preflighted(2n),
      }),
    ).rejects.toThrow(/MERKLE_INDEX_MISMATCH|index/);
  });

  it("asks the merkle source for the wallet's own index, so a duplicated leaf opens the right copy", async () => {
    const input = await spendable(10n, 6);
    const asked: number[] = [];
    const recording: AssemblyContext = {
      ...ctx(),
      merkle: {
        witnessFor: async (leafValue: Fr, expectedLeafIndex: number) => {
          asked.push(expectedLeafIndex);
          return source().witnessFor(leafValue, expectedLeafIndex);
        },
      },
    };
    const a = await assembleWithdraw(recording, {
      input,
      value: 1n,
      recipient: toFr(1n),
      selfSpendScalar: SPEND,
      changeMint: await preflighted(3n),
    });
    expect(asked).toEqual([6]);
    expect(a.inputs.oldNoteIndex).toBe(6);
  });

  /** A source that answers with the real path for the index it was asked, then lets `tamper` edit it. */
  function tampered(
    tamper: (w: { leafIndex: number; siblings: readonly Fr[]; root: Fr }) => {
      leafIndex: number;
      siblings: readonly Fr[];
      root: Fr;
    },
  ): AssemblyContext {
    return {
      ...ctx(),
      merkle: {
        witnessFor: async (leafValue: Fr, expectedLeafIndex: number) =>
          tamper(await source().witnessFor(leafValue, expectedLeafIndex)),
      },
    };
  }

  const withdrawFrom = async (c: AssemblyContext, input: SpendableNote) =>
    assembleWithdraw(c, {
      input,
      value: 1n,
      recipient: toFr(1n),
      selfSpendScalar: SPEND,
      changeMint: await preflighted(4n),
    });

  it("refuses a witness whose path does not fold to the root it claims", async () => {
    const input = await spendable(10n, 6);
    await expectAssemblyError(
      withdrawFrom(
        tampered((w) => ({ ...w, root: toFr(0xf00dn) })),
        input,
      ),
      "MERKLE_ROOT_MISMATCH",
    );
  });

  it("refuses a path with a right child at an empty level", async () => {
    // Index 6 has bits 1 and 2 set; all-zero siblings make those empty levels, which LeanIMT never produces.
    const input = await spendable(10n, 6);
    await expectAssemblyError(
      withdrawFrom(
        tampered((w) => ({
          ...w,
          siblings: Array.from({ length: TREE_DEPTH }, () => toFr(0n)),
        })),
        input,
      ),
      "MERKLE_PATH_NONCANONICAL",
    );
  });

  it("refuses a path that is not exactly the circuit depth", async () => {
    const input = await spendable(10n, 6);
    await expectAssemblyError(
      withdrawFrom(
        tampered((w) => ({ ...w, siblings: w.siblings.slice(0, -1) })),
        input,
      ),
      "MERKLE_PATH_LENGTH",
    );
  });

  it("refuses an index the circuit's 32-bit decomposition rejects", async () => {
    // 2^32 + 6 folds exactly like 6, because only the low TREE_DEPTH bits pick sides.
    const input = await spendable(10n, 6);
    const aliased = 2 ** TREE_DEPTH + 6;
    const aliasing: AssemblyContext = {
      ...ctx(),
      merkle: {
        witnessFor: async (leafValue: Fr) => ({
          ...(await source().witnessFor(leafValue, 6)),
          leafIndex: aliased,
        }),
      },
    };
    await expectAssemblyError(
      withdrawFrom(aliasing, { ...input, leafIndex: aliased }),
      "MERKLE_INDEX_RANGE",
    );
  });
});

describe("assembleTransfer", () => {
  // 76 and 31 are even-y scalars; the circuit rejects an odd-y memo ephemeral or recipient key.
  const MEMO_EPH = toFr(76n);
  const RECIPIENT_IN_KEY = toFr(31n);

  it("forces the memo parents to PARENTS_HIDDEN", async () => {
    const input = await spendable(100n, 4);
    const a = await assembleTransfer(ctx(), {
      input,
      value: 25n,
      recipientInPub: publicKey(RECIPIENT_IN_KEY),
      selfSpendScalar: SPEND,
      memoEph: MEMO_EPH,
      changeMint: await preflighted(78n),
    });
    // The circuit asserts this, and it is what hides the sender's leaf index from the recipient.
    expect(a.memo.note.parents.toString()).toBe(PARENTS_HIDDEN.toString());
    expect(a.change.note.value.toBigInt()).toBe(75n);
    // An incoming note's tag is the RECIPIENT's key, never the ephemeral's.
    expect(a.memo.tag.toBigInt()).toBe(publicKey(RECIPIENT_IN_KEY)[0]);
    expect(a.memo.cekWrap).toBeDefined();
  });

  it("builds a memo the recipient opens from the event fields and its own key alone", async () => {
    const input = await spendable(100n, 5);
    const a = await assembleTransfer(ctx(), {
      input,
      value: 25n,
      recipientInPub: publicKey(RECIPIENT_IN_KEY),
      selfSpendScalar: SPEND,
      memoEph: toFr(79n),
      changeMint: await preflighted(80n),
    });
    expect("spendScalar" in a.memo).toBe(false);

    // What the chain carries: eph_pub.x, cek_wrap, and the ciphertext the circuit computes under the cek.
    const n = a.memo.note;
    const ciphertext = await demEncrypt(a.memo.cek, [
      n.noteVersion,
      n.assetId,
      n.noteType,
      n.conditionsHash,
      n.value,
      n.owner,
      n.parents,
    ]);

    const cek = await unwrapCek(
      a.memo.cekWrap,
      RECIPIENT_IN_KEY,
      recoverEvenY(a.memo.ephPub[0]),
    );
    const [
      noteVersion,
      assetId,
      noteType,
      conditionsHash,
      value,
      owner,
      parents,
    ] = await demDecrypt(cek, ciphertext);
    const rebuilt = await leaf({
      noteVersion: noteVersion!,
      assetId: assetId!,
      noteType: noteType!,
      conditionsHash: conditionsHash!,
      value: value!.toBigInt(),
      owner: owner!,
      psi: await computePsi(cek),
      parents: parents!,
    });
    expect(rebuilt.toString()).toBe(a.memo.commitment.toString());
    expect(owner!.toString()).toBe(
      (await pubkeyOwner(publicKey(RECIPIENT_IN_KEY))).toString(),
    );
    expect(value!.toBigInt()).toBe(25n);
  });

  async function transferWith(memoEph: Fr, recipientInPub: Point<bigint>) {
    return assembleTransfer(ctx(), {
      input: await spendable(100n, 4),
      value: 25n,
      recipientInPub,
      selfSpendScalar: SPEND,
      memoEph,
      changeMint: await preflighted(81n),
    });
  }

  async function expectMemoError(
    pending: Promise<unknown>,
    reason: MemoMintError["reason"],
  ): Promise<void> {
    const err: unknown = await pending.then(
      () => null,
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(MemoMintError);
    expect((err as MemoMintError).reason).toBe(reason);
  }

  it("refuses an odd-y memo ephemeral", async () => {
    expect(isEvenY(publicKey(toFr(77n)))).toBe(false);
    await expectMemoError(
      transferWith(toFr(77n), publicKey(RECIPIENT_IN_KEY)),
      "MEMO_EPH_ODD_Y",
    );
  });

  it("refuses a memo ephemeral outside [1, subgroup order)", async () => {
    await expectMemoError(
      transferWith(toFr(0n), publicKey(RECIPIENT_IN_KEY)),
      "MEMO_EPH_RANGE",
    );
    await expectMemoError(
      transferWith(toFr(BJJ_SUBGROUP_ORDER), publicKey(RECIPIENT_IN_KEY)),
      "MEMO_EPH_RANGE",
    );
  });

  it("refuses a recipient key that is the identity, low order or off the curve", async () => {
    const BN254_P = Fr.MODULUS;
    const lowOrder: Point<bigint> = [0n, BN254_P - 1n];
    for (const bad of [[0n, 1n], lowOrder, [1n, 2n]] as Point<bigint>[]) {
      await expectMemoError(
        transferWith(MEMO_EPH, bad),
        "RECIPIENT_KEY_INVALID",
      );
    }
  });

  it("refuses an odd-y recipient key, whose x would not identify it", async () => {
    const oddKey = publicKey(toFr(55n));
    expect(isEvenY(oddKey)).toBe(false);
    await expectMemoError(
      transferWith(MEMO_EPH, oddKey),
      "RECIPIENT_KEY_ODD_Y",
    );
  });

  it("checks the memo before consuming the change authorization", async () => {
    const changeMint = await preflighted(82n);
    const request = {
      input: await spendable(100n, 4),
      value: 25n,
      recipientInPub: publicKey(RECIPIENT_IN_KEY),
      selfSpendScalar: SPEND,
      changeMint,
    };
    await expectMemoError(
      assembleTransfer(ctx(), { ...request, memoEph: toFr(77n) }),
      "MEMO_EPH_ODD_Y",
    );
    await expect(
      assembleTransfer(ctx(), { ...request, memoEph: MEMO_EPH }),
    ).resolves.toBeDefined();
  });
});

describe("assembleSplit", () => {
  it("conserves value across both outputs", async () => {
    const input = await spendable(100n, 2);
    const a = await assembleSplit(ctx(), {
      input,
      value1: 40n,
      selfSpendScalar: SPEND,
      selfMints: [await preflighted(51n), await preflighted(52n)],
    });
    expect(a.out1.note.value.toBigInt()).toBe(40n);
    expect(a.out2.note.value.toBigInt()).toBe(60n);
    expect(a.out1.note.assetId.toString()).toBe(a.out2.note.assetId.toString());
  });

  it("rejects a reused ephemeral across the two outputs", async () => {
    const input = await spendable(100n, 2);
    const repeated = await preflighted(51n);
    await expect(
      assembleSplit(ctx(), {
        input,
        value1: 40n,
        selfSpendScalar: SPEND,
        selfMints: [repeated, repeated],
      }),
    ).rejects.toThrow(/duplicate|EPHEMERAL_REUSE|distinct/);
  });
});

describe("assembleJoin", () => {
  it("sorts the pair ascending regardless of argument order", async () => {
    const hi = await spendable(30n, 9);
    const lo = await spendable(20n, 4);
    const a = await assembleJoin(ctx(), {
      inputA: hi,
      inputB: lo,
      selfSpendScalar: SPEND,
      selfMint: await preflighted(60n),
    });
    expect(a.inputs["indexA"]).toBe(4);
    expect(a.inputs["indexB"]).toBe(9);
  });

  it("refuses to join a note with itself", async () => {
    const n = await spendable(20n, 4);
    await expect(
      assembleJoin(ctx(), {
        inputA: n,
        inputB: n,
        selfSpendScalar: SPEND,
        selfMint: await preflighted(60n),
      }),
    ).rejects.toThrow(/JOIN_SELF|itself/);
  });

  it("sums both inputs into the output", async () => {
    const a1 = await spendable(20n, 4);
    const b1 = await spendable(30n, 9);
    const a = await assembleJoin(ctx(), {
      inputA: a1,
      inputB: b1,
      selfSpendScalar: SPEND,
      selfMint: await preflighted(60n),
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
    placed.set(5, received.commitment);

    const a = await assembleWithdraw(ctx(), {
      input: {
        note: received.note,
        leaf: received.commitment,
        leafIndex: 5,
        spendScalar: INCOMING_KEY,
      },
      value: 40n,
      recipient: toFr(1n),
      selfSpendScalar: SPEND,
      changeMint: await preflighted(32n),
    });

    const selfOwned = await pubkeyOwner(publicKey(SPEND));
    const incomingOwned = await pubkeyOwner(publicKey(INCOMING_KEY));
    expect(a.change.note.owner.toString()).toBe(selfOwned.toString());
    expect(a.change.note.owner.toString()).not.toBe(incomingOwned.toString());
  });
});
