/**
 * Transaction-level golden vectors: the marshalled Noir `InputMap` each standard circuit receives.
 *
 * Primitive vectors pin a hash, a KEM, a nullifier. This pins a whole TRANSACTION, so a change to assembly
 * or marshalling that keeps every primitive right but moves the witness fails here.
 *
 * What is frozen here: for each circuit family, the marshalled witness the prover would hand to Noir, plus
 * the values the assembler derived (commitments, change, tags). Any other implementation of this layer that
 * reproduces this JSON byte-for-byte agrees with this one; one that does not has a real divergence.
 *
 * REGENERATE (only when the witness shape legitimately changes, and say why in the commit):
 *   GEN_TX_VECTORS=1 npx vitest run src/__tests__/txVectors.test.ts
 */
import { describe, it, expect } from "vitest";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { Fr } from "@aztec/foundation/fields";
import { Base8, mulPointEscalar, subOrder } from "@zk-kit/baby-jubjub";
import { BN254_FR_MODULUS, fieldHexFromBigInt } from "@hisoka/howl-protocol";
import { standardWitnessDtoToNoirInput } from "@hisoka/howl-protocol/proving";
import {
  buildPublicClaim,
  buildPublicTransfer,
  encodeHisokaPublicAddress,
  LeanIMT,
  TREE_DEPTH,
  toFr,
  toBjjScalar,
  publicKey,
  pubkeyOwner,
  completeComplianceHistory,
  SelfMintPreflight,
  SelfEphemeralAllocator,
  InMemoryEphemeralCounterStore,
  DarkAccount,
  type DerivedEph,
  CIPHERTEXT_KEPT_INDICES,
  COMMITMENT_PREFIX_BYTES,
  HOWL_NOTE_LAYOUT_VERSION,
  RECORD_KIND_INCOMING,
  type HowlNoteRecord,
} from "@hisoka/wallets";
import {
  assembleDeposit,
  assembleWithdraw,
  assembleTransfer,
  assembleSplit,
  assembleJoin,
  toStandardWitnessDto,
  LocalTreeWitnessSource,
  type AssemblyContext,
  type SpendableNote,
  type MerkleWitnessSource,
} from "@hisoka/wallets/tx";

const VECTORS = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../tx-vectors.json",
);

// Every input is fixed. A vector that moves because of a clock or a CSPRNG is not a vector. Self ephemerals come
// from the production allocator over a fresh counter, so each build derives the same even-y sequence.
const COMPLIANCE_PK = mulPointEscalar(Base8, 987654321n);
const ASSET = toFr(0x1234567890123456789012345678901234567890n);
const ASSET_ADDRESS = "0x1234567890123456789012345678901234567890";
const SENDER_MNEMONIC =
  "test test test test test test test test test test test junk";
const RECIPIENT_MNEMONIC =
  "legal winner thank year wave sausage worth useful legal winner thank yellow";
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

const SIBLINGS = Array.from({ length: 32 }, (_, i) => toFr(BigInt(i) + 1n));

const ctx = (merkle: MerkleWitnessSource): AssemblyContext => ({
  compliancePk: COMPLIANCE_PK,
  complianceVersion: 1,
  complianceHistory: COMPLIANCE_HISTORY,
  ...DOMAIN,
  merkle,
});

async function buildVectors(): Promise<Record<string, unknown>> {
  const account = await DarkAccount.fromMnemonic(SENDER_MNEMONIC);
  const recipient = await DarkAccount.fromMnemonic(RECIPIENT_MNEMONIC);
  const spendScalar = await account.getSelfSpendKey();
  const preflight = new SelfMintPreflight({
    allocator: new SelfEphemeralAllocator(
      account,
      new InMemoryEphemeralCounterStore(),
    ),
    discovery: {
      probeFirst: (tags) =>
        Promise.resolve(
          tags.map((tag) => ({ tag, record: MISS_RECORD, occurrenceCount: 0 })),
        ),
      fetchOccurrences: () => Promise.resolve([]),
      fetchLeafBlock: () => Promise.resolve([]),
    },
    history: COMPLIANCE_HISTORY,
    ownerCommitment: await pubkeyOwner(await account.getSelfSpendPub()),
    domain: DOMAIN,
  });
  const checked = async () => (await preflight.take(1))[0];

  // Every spent note at its index, fixed filler leaves elsewhere, so each witness is a real LeanIMT path.
  const placed = new Map<number, Fr>();
  const merkle: MerkleWitnessSource = {
    witnessFor: async (leaf: Fr, expectedLeafIndex: number) => {
      const tree = new LeanIMT(TREE_DEPTH);
      const top = Math.max(0, ...placed.keys());
      for (let i = 0; i <= top; i++) {
        await tree.insert(placed.get(i) ?? toFr(BigInt(0x10000 + i)));
      }
      return new LocalTreeWitnessSource(tree).witnessFor(
        leaf,
        expectedLeafIndex,
      );
    },
  };
  const spendable = async (
    value: bigint,
    leafIndex: number,
  ): Promise<SpendableNote> => {
    const { minted } = await assembleDeposit(ctx(merkle), {
      value,
      assetId: ASSET,
      spendScalar,
      selfMint: await checked(),
    });
    placed.set(leafIndex, minted.commitment);
    return {
      note: minted.note,
      leaf: minted.commitment,
      leafIndex,
      spendScalar,
    };
  };

  const dep = await assembleDeposit(ctx(merkle), {
    value: 1000n,
    assetId: ASSET,
    spendScalar,
    selfMint: await checked(),
  });

  const wIn = await spendable(1000n, 1);
  const wd = await assembleWithdraw(ctx(merkle), {
    input: wIn,
    value: 300n,
    recipient: toFr(0xbeefn),
    selfSpendScalar: spendScalar,
    changeMint: await checked(),
  });

  const tIn = await spendable(1000n, 2);
  const tr = await assembleTransfer(ctx(merkle), {
    input: tIn,
    value: 250n,
    recipientInPub: (await recipient.canonicalIncomingAddress(0n)).pub,
    selfSpendScalar: spendScalar,
    // A memo ephemeral is sampled in production; fixed here, with the even-y key the circuit asserts.
    memoEph: toFr(76n),
    changeMint: await checked(),
  });

  const sIn = await spendable(1000n, 3);
  const sp = await assembleSplit(ctx(merkle), {
    input: sIn,
    value1: 400n,
    selfSpendScalar: spendScalar,
    selfMints: [await checked(), await checked()],
  });

  const jA = await spendable(600n, 4);
  const jB = await spendable(400n, 9);
  const jn = await assembleJoin(ctx(merkle), {
    inputA: jA,
    inputB: jB,
    selfSpendScalar: spendScalar,
    selfMint: await checked(),
  });

  const publicAddress = await recipient.canonicalPublicAddress(0n);
  const publicTransfer = await buildPublicTransfer({
    darkPool: DOMAIN.poolAddress,
    recipient: encodeHisokaPublicAddress({
      ownerPub: publicAddress.pub,
      index: publicAddress.index,
    }),
    asset: ASSET_ADDRESS,
    value: 125n,
    timelock: 1_700_000_000n,
    salt: toFr(444n),
  });
  const publicClaim = await buildPublicClaim({
    memo: publicTransfer.memo,
    viewKey: await recipient.getViewKey(),
    ownerIndex: publicAddress.index,
    compliancePk: COMPLIANCE_PK,
    complianceVersion: 1,
    complianceHistory: COMPLIANCE_HISTORY,
    ...DOMAIN,
    keys: account,
    selfMint: await checked(),
    currentTimestamp: 1_800_000_000,
  });

  const depositWitness = standardWitnessDtoToNoirInput(
    "deposit",
    toStandardWitnessDto("deposit", dep.inputs),
  );
  const withdrawWitness = standardWitnessDtoToNoirInput(
    "withdraw",
    toStandardWitnessDto("withdraw", wd.inputs),
  );
  const transferWitness = standardWitnessDtoToNoirInput(
    "transfer",
    toStandardWitnessDto("transfer", tr.inputs),
  );
  const splitWitness = standardWitnessDtoToNoirInput(
    "split",
    toStandardWitnessDto("split", sp.inputs),
  );
  const joinWitness = standardWitnessDtoToNoirInput(
    "join",
    toStandardWitnessDto("join", jn.inputs),
  );
  const publicClaimWitness = standardWitnessDtoToNoirInput(
    "public_claim",
    toStandardWitnessDto("public_claim", publicClaim.inputs),
  );

  return {
    // Bump when the witness SHAPE changes, so a stale foreign implementation fails loudly not silently.
    schema: 2,
    deposit: {
      witness: depositWitness,
      derived: {
        commitment: dep.minted.commitment.toString(),
        tag: dep.minted.tag.toString(),
        psi: dep.minted.psi.toString(),
      },
    },
    withdraw: {
      witness: withdrawWitness,
      derived: {
        root: wd.root.toString(),
        changeCommitment: wd.change.commitment.toString(),
        changeValue: wd.change.note.value.toString(),
      },
    },
    transfer: {
      witness: transferWitness,
      derived: {
        root: tr.root.toString(),
        memoCommitment: tr.memo.commitment.toString(),
        memoTag: tr.memo.tag.toString(),
        memoCekWrap: tr.memo.cekWrap?.toString() ?? null,
        changeCommitment: tr.change.commitment.toString(),
      },
    },
    split: {
      witness: splitWitness,
      derived: {
        root: sp.root.toString(),
        out1: sp.out1.commitment.toString(),
        out2: sp.out2.commitment.toString(),
      },
    },
    join: {
      witness: joinWitness,
      derived: {
        root: jn.root.toString(),
        out: jn.out.commitment.toString(),
        outValue: jn.out.note.value.toString(),
      },
    },
    public_claim: {
      witness: publicClaimWitness,
      derived: {
        memoId: publicTransfer.memo.memoId.toString(),
        commitment: publicClaim.commitment.toString(),
        tag: new Fr(publicKey(publicClaim.inputs.eph)[0]).toString(),
      },
    },
  };
}

describe("transaction golden vectors", () => {
  it("pins the protocol modulus to the installed field implementation", () => {
    expect(BigInt(BN254_FR_MODULUS)).toBe(Fr.MODULUS);
  });

  it("preserves public-claim subgroup reduction through the Noir map", () => {
    const oversized = new Fr(subOrder + 7n);
    const zero = Fr.ZERO;
    const dto = toStandardWitnessDto("public_claim", {
      memoId: zero,
      compliancePk: COMPLIANCE_PK,
      currentTimestamp: 0,
      val: zero,
      assetId: zero,
      timelock: zero,
      ownerX: zero,
      ownerY: zero,
      salt: zero,
      recipientSk: oversized,
      noteOut: {
        noteVersion: zero,
        assetId: zero,
        noteType: zero,
        conditionsHash: zero,
        value: zero,
        owner: zero,
        psi: zero,
        parents: zero,
      },
      eph: eph(1n),
    });
    const witness = standardWitnessDtoToNoirInput("public_claim", dto);

    expect(dto.recipient_sk).toBe(fieldHexFromBigInt(7n));
    expect(witness.recipient_sk).toBe(toBjjScalar(oversized).toString());
  });

  it("preserves standard and multisig transfer recipient points", () => {
    const spendPub = publicKey(toFr(81n));
    const viewPub = publicKey(toFr(82n));
    const zeroNote = {
      noteVersion: Fr.ZERO,
      assetId: Fr.ZERO,
      noteType: Fr.ZERO,
      conditionsHash: Fr.ZERO,
      value: Fr.ZERO,
      owner: Fr.ZERO,
      psi: Fr.ZERO,
      parents: Fr.ZERO,
    };
    const transfer = {
      compliancePk: COMPLIANCE_PK,
      oldNote: zeroNote,
      spendScalar: Fr.ZERO,
      oldNoteIndex: 0,
      oldNotePath: SIBLINGS,
      memoNote: zeroNote,
      memoEph: Fr.ZERO,
      changeNote: zeroNote,
      changeEph: eph(1n),
    };

    const standard = toStandardWitnessDto("transfer", {
      ...transfer,
      recipientInPub: spendPub,
    });
    expect(standard.recipient_spend_pub).toEqual(standard.recipient_view_pub);

    const multisig = toStandardWitnessDto("transfer", {
      ...transfer,
      recipientMultisig: { gpk: spendPub, viewPub },
      memoNote: { ...zeroNote, noteType: toFr(1n) },
    });
    expect(multisig.recipient_spend_pub.x).toBe(
      fieldHexFromBigInt(spendPub[0]),
    );
    expect(multisig.recipient_view_pub.x).toBe(fieldHexFromBigInt(viewPub[0]));
  });

  it("contains every schema-2 standard witness", () => {
    const frozen = JSON.parse(readFileSync(VECTORS, "utf8")) as {
      schema?: number;
      transfer?: { witness?: Record<string, unknown> };
      public_claim?: unknown;
    };
    expect(frozen.schema).toBe(2);
    expect(frozen.transfer?.witness).toHaveProperty("recipient_spend_pub");
    expect(frozen.transfer?.witness).toHaveProperty("recipient_view_pub");
    expect(frozen.public_claim).toBeDefined();
  });

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
