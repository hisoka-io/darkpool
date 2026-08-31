import { describe, it, expect } from "vitest";
import { Point } from "@zk-kit/baby-jubjub";
import {
  buildPublicClaim,
  buildPublicTransfer,
  canonicalPublicAddress,
  completeComplianceHistory,
  DarkAccount,
  encodeHisokaPublicAddress,
  Fr,
  pubkeyOwner,
  SelfMintPreflight,
  CIPHERTEXT_KEPT_INDICES,
  COMMITMENT_PREFIX_BYTES,
  HOWL_NOTE_LAYOUT_VERSION,
  RECORD_KIND_INCOMING,
  type HowlNoteRecord,
} from "@hisoka/wallets";
import {
  InMemoryEphemeralCounterStore,
  KeyRepository,
} from "@hisoka/wallets/reference";
import { provePublicClaim } from "../provers/standard/public_claim.js";
import { PublicClaimInputs } from "../types.js";

const MNEMONIC = "test test test test test test test test test test test junk";
const DARKPOOL = "0x5FbDB2315678afecb367f032d93F642f64180aa3";
const TOKEN = "0x1234567890123456789012345678901234567890";
const VALUE = 100n;

// Fixture from the wallets parity vectors.
const COMPLIANCE_PK: Point<bigint> = [
  0x085ed469c9a9f102b6d4f6f909b8ceaf6ca49b39759ac2e0feb7e0aada8b7111n,
  0x245e25ab2bd42f0280a5ade750828dd6868f5225ae798d6b51c676f519c8f4e8n,
];
const DOMAIN = {
  chainId: 31337n,
  poolAddress: DARKPOOL,
  deploymentAnchor: 1n,
};
const HISTORY = completeComplianceHistory({
  genesisPk: COMPLIANCE_PK,
  rotations: [],
  currentPk: COMPLIANCE_PK,
  currentVersion: 1,
});
const MISS_RECORD: HowlNoteRecord = {
  layoutVersion: HOWL_NOTE_LAYOUT_VERSION,
  recordKind: RECORD_KIND_INCOMING,
  leafIndex: 0,
  commitmentPrefix: new Uint8Array(COMMITMENT_PREFIX_BYTES),
  ephemeralPkX: Fr.ZERO,
  cekWrap: Fr.ZERO,
  ciphertextKept: CIPHERTEXT_KEPT_INDICES.map(() => Fr.ZERO),
};

describe("public transfer -> public_claim (SDK assembly)", () => {
  it("proves the witness the wallet assembles for a posted memo", async () => {
    const account = await DarkAccount.fromMnemonic(MNEMONIC);
    const viewKey = await account.getViewKey();
    const canonical = await canonicalPublicAddress(viewKey, 0n);

    const plan = await buildPublicTransfer({
      darkPool: DARKPOOL,
      recipient: encodeHisokaPublicAddress({
        ownerPub: canonical.pub,
        index: canonical.index,
      }),
      asset: TOKEN,
      value: VALUE,
    });

    const keys = new KeyRepository(
      account,
      new InMemoryEphemeralCounterStore(),
    );
    const preflight = new SelfMintPreflight({
      allocator: { next: () => keys.nextSelfEphemeral() },
      discovery: {
        probeFirst: (tags) =>
          Promise.resolve(
            tags.map((tag) => ({
              tag,
              record: MISS_RECORD,
              occurrenceCount: 0,
            })),
          ),
        fetchOccurrences: () => Promise.resolve([]),
        fetchLeafBlock: () => Promise.resolve([]),
      },
      history: HISTORY,
      ownerCommitment: await pubkeyOwner(await keys.getSelfSpendPub()),
      domain: DOMAIN,
    });

    const claim = await buildPublicClaim({
      memo: plan.memo,
      viewKey,
      ownerIndex: canonical.index,
      compliancePk: COMPLIANCE_PK,
      complianceVersion: 1,
      complianceHistory: HISTORY,
      ...DOMAIN,
      keys,
      selfMint: (await preflight.take(1))[0],
      currentTimestamp: Math.floor(Date.now() / 1000),
    });

    // Assignability is the parity check: PublicClaimWitness mirrors this interface across the package edge.
    const inputs: PublicClaimInputs = claim.inputs;
    const { verified, publicInputs } = await provePublicClaim(inputs);

    expect(verified).toBe(true);
    expect(BigInt(publicInputs[0])).toBe(plan.memo.memoId.toBigInt());
    expect(BigInt(publicInputs[4])).toBe(claim.commitment.toBigInt());
  }, 180000);
});
