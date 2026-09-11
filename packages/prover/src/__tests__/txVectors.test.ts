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
import { Base8, mulPointEscalar, subOrder } from "@zk-kit/baby-jubjub";
import { BN254_FR_MODULUS, fieldHexFromBigInt } from "@hisoka/howl-protocol";
import { standardWitnessDtoToNoirInput } from "@hisoka/howl-protocol/proving";
import {
  buildPublicClaim,
  buildPublicTransfer,
  canonicalPublicAddress,
  encodeHisokaPublicAddress,
  toFr,
  toBjjScalar,
  publicKey,
  pubkeyOwner,
  completeComplianceHistory,
  SelfMintPreflight,
  type DerivedEph,
  CIPHERTEXT_KEPT_INDICES,
  COMMITMENT_PREFIX_BYTES,
  HOWL_NOTE_LAYOUT_VERSION,
  RECORD_KIND_INCOMING,
  type HowlNoteRecord,
} from "@hisoka/wallets";
import {
  markDerivedSelfMintCandidate,
  mintSelfNote,
} from "@hisoka/wallets/unsafe-sim";
import {
  assembleDeposit,
  assembleWithdraw,
  assembleTransfer,
  assembleSplit,
  assembleJoin,
  toStandardWitnessDto,
  type AssemblyContext,
  type SpendableNote,
  type MerkleWitnessSource,
} from "@hisoka/wallets/tx";

const VECTORS = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../tx-vectors.json",
);

// Every input is fixed. A vector that moves because of a clock, a counter or a CSPRNG is not a vector.
const COMPLIANCE_PK = mulPointEscalar(Base8, 987654321n);
const ASSET = toFr(0x1234567890123456789012345678901234567890n);
const ASSET_ADDRESS = "0x1234567890123456789012345678901234567890";
const SPEND = toFr(789n);
const RECIPIENT_IN_KEY = toFr(31n);
const eph = (n: bigint): DerivedEph => toFr(n) as DerivedEph;
const COMPLIANCE_HISTORY = completeComplianceHistory({
  genesisPk: COMPLIANCE_PK,
  rotations: [],
  currentPk: COMPLIANCE_PK,
  currentVersion: 1,
});
const OWNER_COMMITMENT = await pubkeyOwner(publicKey(SPEND));
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

async function checked(n: bigint) {
  const scalar = eph(n);
  const ephPub = publicKey(scalar);
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
            OWNER_COMMITMENT,
          ),
        ),
    },
    discovery: {
      probeFirst: (tags) =>
        Promise.resolve(
          tags.map((tag) => ({ tag, record: MISS_RECORD, occurrenceCount: 0 })),
        ),
      fetchOccurrences: () => Promise.resolve([]),
      fetchLeafBlock: () => Promise.resolve([]),
    },
    history: COMPLIANCE_HISTORY,
    ownerCommitment: OWNER_COMMITMENT,
    domain: DOMAIN,
  });
  return (await preflight.take(1))[0];
}

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
const ctx: AssemblyContext = {
  compliancePk: COMPLIANCE_PK,
  complianceVersion: 1,
  complianceHistory: COMPLIANCE_HISTORY,
  ...DOMAIN,
  merkle,
};

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

async function buildVectors(): Promise<Record<string, unknown>> {
  const dep = await assembleDeposit(ctx, {
    value: 1000n,
    assetId: ASSET,
    spendScalar: SPEND,
    selfMint: await checked(5n),
  });

  const wIn = await spendable(1000n, 1);
  const wd = await assembleWithdraw(ctx, {
    input: wIn,
    value: 300n,
    recipient: toFr(0xbeefn),
    selfSpendScalar: SPEND,
    changeMint: await checked(21n),
  });

  const tIn = await spendable(1000n, 2);
  const tr = await assembleTransfer(ctx, {
    input: tIn,
    value: 250n,
    recipientInPub: publicKey(RECIPIENT_IN_KEY),
    recipientInKey: RECIPIENT_IN_KEY,
    selfSpendScalar: SPEND,
    memoEph: toFr(77n),
    changeMint: await checked(78n),
  });

  const sIn = await spendable(1000n, 3);
  const sp = await assembleSplit(ctx, {
    input: sIn,
    value1: 400n,
    selfSpendScalar: SPEND,
    selfMints: [await checked(51n), await checked(52n)],
  });

  const jA = await spendable(600n, 4);
  const jB = await spendable(400n, 9);
  const jn = await assembleJoin(ctx, {
    inputA: jA,
    inputB: jB,
    selfSpendScalar: SPEND,
    selfMint: await checked(60n),
  });

  const publicViewKey = toFr(1234n);
  const publicAddress = await canonicalPublicAddress(publicViewKey, 0n);
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
    viewKey: publicViewKey,
    ownerIndex: publicAddress.index,
    compliancePk: COMPLIANCE_PK,
    complianceVersion: 1,
    complianceHistory: COMPLIANCE_HISTORY,
    ...DOMAIN,
    keys: { getSelfSpendPub: () => Promise.resolve(publicKey(SPEND)) },
    selfMint: await checked(70n),
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
