import { describe, it, expect, beforeAll } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import { AbiCoder, id, Interface } from "ethers";
import { Point } from "@zk-kit/baby-jubjub";
import { DarkAccount } from "../keys/DarkAccount";
import { KeyRepository } from "../state/KeyRepository";
import {
  InMemoryEphemeralCounterStore,
  SealedEphemeralCounterStore,
} from "../state/EphemeralCounterStore";
import {
  canonicalPublicAddress,
  derivePublicIncomingKey,
  publicKey,
  pubkeyOwner,
} from "../note/keys";
import { encodeHisokaPublicAddress, encodeHisokaAddress } from "../address";
import { leaf as computeLeaf, NOTE_VERSION } from "../note/note";
import { computePsi } from "../note/nullifier";
import { deriveCek } from "../crypto/kem";
import { addressToFr, toFr } from "../crypto/fields";
import { calculatePublicMemoId } from "../crypto/index";
import { buildPublicTransfer } from "../public/publicTransfer";
import { buildPublicClaim } from "../public/publicClaim";
import { PublicMemo, PublicMemoError } from "../public/memo";
import type { DiscoveredPublicMemo } from "../sync/types";
import { completeComplianceHistory } from "../note/complianceKeys";
import { SelfMintPreflight } from "../discovery/preflight";
import {
  CIPHERTEXT_KEPT_INDICES,
  COMMITMENT_PREFIX_BYTES,
  HOWL_NOTE_LAYOUT_VERSION,
  RECORD_KIND_INCOMING,
  type DiscoverySource,
  type HowlNoteRecord,
} from "../discovery/types";

const MNEMONIC = "test test test test test test test test test test test junk";
const DARKPOOL = "0x5FbDB2315678afecb367f032d93F642f64180aa3";
const TOKEN = "0x1234567890123456789012345678901234567890";
const VALUE = 50_000_000_000_000_000_000n;

// The wallets parity fixture also used by the prover and evm suites.
const COMPLIANCE_PK: Point<bigint> = [
  0x085ed469c9a9f102b6d4f6f909b8ceaf6ca49b39759ac2e0feb7e0aada8b7111n,
  0x245e25ab2bd42f0280a5ade750828dd6868f5225ae798d6b51c676f519c8f4e8n,
];

// Pinned from DarkPool.sol; the SDK's calldata must match this ABI exactly or the memo escrows to nobody.
const TRANSFER_SIGNATURE =
  "publicTransfer(uint256,uint256,address,uint256,uint256,uint256)";
const TRANSFER_TYPES = [
  "uint256",
  "uint256",
  "address",
  "uint256",
  "uint256",
  "uint256",
];

// Order-2 point (0, -1): on the curve, outside the prime-order subgroup, claimable by no witness.
const ORDER_TWO_POINT: Point<bigint> = [
  0n,
  21888242871839275222246405745257275088548364400416034343698204186575808495616n,
];
const OFF_CURVE_POINT: Point<bigint> = [1n, 1n];
const IDENTITY_POINT: Point<bigint> = [0n, 1n];

let account: DarkAccount;
let viewKey: Fr;
let address: string;
let addressIndex: bigint;

beforeAll(async () => {
  account = await DarkAccount.fromMnemonic(MNEMONIC);
  viewKey = await account.getViewKey();
  addressIndex = 3n;
  const canonical = await canonicalPublicAddress(viewKey, addressIndex);
  address = encodeHisokaPublicAddress({
    ownerPub: canonical.pub,
    index: canonical.index,
  });
});

function keyRepo(
  store: InMemoryEphemeralCounterStore | SealedEphemeralCounterStore,
): KeyRepository {
  return new KeyRepository(account, store);
}

const emptyDiscovery: DiscoverySource = {
  probeFirst: (tags) =>
    Promise.resolve(
      tags.map((tag) => ({ tag, record: MISS_RECORD, occurrenceCount: 0 })),
    ),
  fetchOccurrences: () => Promise.resolve([]),
  fetchLeafBlock: () => Promise.resolve([]),
};

const COMPLIANCE_HISTORY = completeComplianceHistory({
  genesisPk: COMPLIANCE_PK,
  rotations: [],
  currentPk: COMPLIANCE_PK,
  currentVersion: 1,
});
const DOMAIN = {
  chainId: 31337n,
  poolAddress: DARKPOOL,
  deploymentAnchor: 1n,
};
const CLAIM_CONTEXT = {
  compliancePk: COMPLIANCE_PK,
  complianceVersion: 1,
  complianceHistory: COMPLIANCE_HISTORY,
  ...DOMAIN,
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

async function preflight(repo: KeyRepository): Promise<
  SelfMintPreflight<
    Awaited<ReturnType<KeyRepository["nextSelfEphemeral"]>> & {
      readonly tag: Fr;
    }
  >
> {
  return new SelfMintPreflight({
    allocator: { next: () => repo.nextSelfEphemeral() },
    discovery: emptyDiscovery,
    history: COMPLIANCE_HISTORY,
    ownerCommitment: await pubkeyOwner(await repo.getSelfSpendPub()),
    domain: DOMAIN,
  });
}

describe("buildPublicTransfer (MetaMask-only sender)", () => {
  it("encodes the calldata ethers produces from the DarkPool ABI", async () => {
    const plan = await buildPublicTransfer({
      darkPool: DARKPOOL,
      recipient: address,
      asset: TOKEN,
      value: VALUE,
    });

    const expected =
      id(TRANSFER_SIGNATURE).slice(0, 10) +
      AbiCoder.defaultAbiCoder()
        .encode(TRANSFER_TYPES, [
          plan.ownerPub[0],
          plan.ownerPub[1],
          TOKEN,
          VALUE,
          0n,
          plan.memo.salt.toBigInt(),
        ])
        .slice(2);

    expect(plan.transfer.to).toBe(DARKPOOL);
    expect(plan.transfer.data).toBe(expected);
  });

  it("decodes back to the argument order the contract declares", async () => {
    const plan = await buildPublicTransfer({
      darkPool: DARKPOOL,
      recipient: address,
      asset: TOKEN,
      value: VALUE,
      timelock: 1_700_000_000n,
    });

    const decoded = new Interface([
      `function ${TRANSFER_SIGNATURE}`,
    ]).decodeFunctionData(TRANSFER_SIGNATURE, plan.transfer.data);

    expect(decoded[0]).toBe(plan.ownerPub[0]);
    expect(decoded[1]).toBe(plan.ownerPub[1]);
    expect(decoded[2]).toBe(TOKEN);
    expect(decoded[3]).toBe(VALUE);
    expect(decoded[4]).toBe(1_700_000_000n);
    expect(decoded[5]).toBe(plan.memo.salt.toBigInt());
  });

  it("approves the exact amount to the pool, never an unlimited allowance", async () => {
    const plan = await buildPublicTransfer({
      darkPool: DARKPOOL,
      recipient: address,
      asset: TOKEN,
      value: VALUE,
    });

    const expected =
      id("approve(address,uint256)").slice(0, 10) +
      AbiCoder.defaultAbiCoder()
        .encode(["address", "uint256"], [DARKPOOL, VALUE])
        .slice(2);

    expect(plan.approval.to).toBe(TOKEN);
    expect(plan.approval.data).toBe(expected);
  });

  it("computes the memoId the contract will key the escrow by", async () => {
    const plan = await buildPublicTransfer({
      darkPool: DARKPOOL,
      recipient: address,
      asset: TOKEN,
      value: VALUE,
      timelock: 42n,
    });

    const expected = await calculatePublicMemoId(
      toFr(VALUE),
      addressToFr(TOKEN),
      toFr(42n),
      new Fr(plan.ownerPub[0]),
      new Fr(plan.ownerPub[1]),
      plan.memo.salt,
    );
    expect(plan.memo.memoId.equals(expected)).toBe(true);
  });

  it("draws a fresh salt per send so a repeat payment cannot revert MemoCollision", async () => {
    const request = {
      darkPool: DARKPOOL,
      recipient: address,
      asset: TOKEN,
      value: VALUE,
    };
    const salts = new Set<string>();
    for (let i = 0; i < 8; i++) {
      const plan = await buildPublicTransfer(request);
      salts.add(plan.memo.salt.toString());
    }
    expect(salts.size).toBe(8);
  });

  it("reproduces a memoId when the caller pins the salt", async () => {
    const salt = new Fr(0x1234n);
    const a = await buildPublicTransfer({
      darkPool: DARKPOOL,
      recipient: address,
      asset: TOKEN,
      value: VALUE,
      salt,
    });
    const b = await buildPublicTransfer({
      darkPool: DARKPOOL,
      recipient: address,
      asset: TOKEN,
      value: VALUE,
      salt,
    });
    expect(a.transfer.data).toBe(b.transfer.data);
    expect(a.memo.memoId.equals(b.memo.memoId)).toBe(true);
  });

  it.each([
    ["outside the prime-order subgroup", ORDER_TWO_POINT],
    ["off the curve", OFF_CURVE_POINT],
    ["the identity", IDENTITY_POINT],
  ])(
    "refuses a recipient point %s",
    async (_label: string, ownerPub: Point<bigint>) => {
      await expect(
        buildPublicTransfer({
          darkPool: DARKPOOL,
          recipient: { ownerPub, index: 0n },
          asset: TOKEN,
          value: VALUE,
        }),
      ).rejects.toThrow(PublicMemoError);
    },
  );

  it("refuses a private hiso_ address, which would deanonymize its private payments", async () => {
    const priv = encodeHisokaAddress({
      inPub: (await account.canonicalIncomingAddress(0n)).pub,
      index: 0n,
    });
    await expect(
      buildPublicTransfer({
        darkPool: DARKPOOL,
        recipient: priv,
        asset: TOKEN,
        value: VALUE,
      }),
    ).rejects.toThrow(PublicMemoError);
  });

  it.each([
    ["a zero value", { value: 0n }],
    ["a value above u128", { value: 1n << 128n }],
    ["a timelock above u64", { timelock: 1n << 64n }],
  ])(
    "refuses %s the contract would reject",
    async (_label: string, overrides: Record<string, unknown>) => {
      await expect(
        buildPublicTransfer({
          darkPool: DARKPOOL,
          recipient: address,
          asset: TOKEN,
          value: VALUE,
          ...overrides,
        }),
      ).rejects.toThrow(PublicMemoError);
    },
  );

  it.each([
    ["asset", { asset: "0xnot-an-address" }],
    ["darkPool", { darkPool: "0x00" }],
  ])(
    "refuses a malformed %s address",
    async (_label: string, overrides: Record<string, unknown>) => {
      await expect(
        buildPublicTransfer({
          darkPool: DARKPOOL,
          recipient: address,
          asset: TOKEN,
          value: VALUE,
          ...overrides,
        }),
      ).rejects.toThrow(PublicMemoError);
    },
  );

  it("refuses the zero asset address", async () => {
    await expect(
      buildPublicTransfer({
        darkPool: DARKPOOL,
        recipient: address,
        asset: "0x0000000000000000000000000000000000000000",
        value: VALUE,
      }),
    ).rejects.toThrow(PublicMemoError);
  });
});

describe("public claim assembly", () => {
  async function postedMemo(timelock = 0n): Promise<PublicMemo> {
    const plan = await buildPublicTransfer({
      darkPool: DARKPOOL,
      recipient: address,
      asset: TOKEN,
      value: VALUE,
      timelock,
    });
    return plan.memo;
  }

  it("accepts a scanner DiscoveredPublicMemo without a shape adapter", async () => {
    const memo = await postedMemo();
    const discovered: DiscoveredPublicMemo = {
      memoId: memo.memoId,
      ownerIndex: addressIndex,
      ownerPub: publicKey(await derivePublicIncomingKey(viewKey, addressIndex)),
      recipientSk: await derivePublicIncomingKey(viewKey, addressIndex),
      asset: TOKEN,
      assetId: memo.assetId,
      value: memo.value,
      timelock: memo.timelock,
      salt: memo.salt,
      spent: false,
      matured: true,
      claimable: true,
      blockNumber: 1,
      logIndex: 0,
      txHash: "0x",
    };
    const repo = keyRepo(new InMemoryEphemeralCounterStore());
    const claim = await buildPublicClaim({
      memo: discovered,
      viewKey,
      ownerIndex: discovered.ownerIndex,
      ...CLAIM_CONTEXT,
      keys: repo,
      selfMint: (await (await preflight(repo)).take(1))[0],
      currentTimestamp: 1_800_000_000,
    });
    expect(claim.inputs.memoId.equals(memo.memoId)).toBe(true);
  });

  it("consumes authorization once and binds the claim owner and compliance version", async () => {
    const memo = await postedMemo();
    const repo = keyRepo(new InMemoryEphemeralCounterStore());
    const authorization = (await (await preflight(repo)).take(1))[0];
    const request = {
      memo,
      viewKey,
      ownerIndex: addressIndex,
      ...CLAIM_CONTEXT,
      keys: repo,
      selfMint: authorization,
      currentTimestamp: 1_800_000_000,
    };

    await expect(
      buildPublicClaim({ ...request, complianceVersion: 2 }),
    ).rejects.toThrow(/context/);
    await expect(
      buildPublicClaim({
        ...request,
        keys: {
          getSelfSpendPub: () => Promise.resolve(publicKey(new Fr(99n))),
        },
      }),
    ).rejects.toThrow(/context/);
    await expect(buildPublicClaim(request)).resolves.toBeDefined();
    await expect(buildPublicClaim(request)).rejects.toThrow(/consumed/);
  });

  it("assembles a witness the public_claim circuit accepts", async () => {
    const memo = await postedMemo();
    const repo = keyRepo(new InMemoryEphemeralCounterStore());
    const checked = await preflight(repo);
    const selfMint = (await checked.take(1))[0];
    const claim = await buildPublicClaim({
      memo,
      viewKey,
      ownerIndex: addressIndex,
      ...CLAIM_CONTEXT,
      keys: repo,
      selfMint,
      currentTimestamp: 1_800_000_000,
    });

    expect(claim.inputs.memoId.equals(memo.memoId)).toBe(true);
    expect(claim.inputs.val.equals(toFr(VALUE))).toBe(true);
    expect(claim.inputs.assetId.equals(addressToFr(TOKEN))).toBe(true);
    expect(claim.inputs.timelock.equals(toFr(0n))).toBe(true);
    expect(claim.inputs.salt.equals(memo.salt)).toBe(true);
    expect(claim.inputs.currentTimestamp).toBe(1_800_000_000);
    expect(Object.keys(selfMint)).toEqual([]);

    // memo id mismatch / recipient key mismatch are the circuit's first two asserts.
    const expectedSk = await derivePublicIncomingKey(viewKey, addressIndex);
    expect(claim.inputs.recipientSk.equals(expectedSk)).toBe(true);
    const ownerPub = publicKey(expectedSk);
    expect(claim.inputs.ownerX.toBigInt()).toBe(ownerPub[0]);
    expect(claim.inputs.ownerY.toBigInt()).toBe(ownerPub[1]);
    const recomputed = await calculatePublicMemoId(
      claim.inputs.val,
      claim.inputs.assetId,
      claim.inputs.timelock,
      claim.inputs.ownerX,
      claim.inputs.ownerY,
      claim.inputs.salt,
    );
    expect(recomputed.equals(memo.memoId)).toBe(true);

    // mint_self_note: STANDARD, zero conditions, zero parents, psi bound to the CEK, owner = the spend key.
    expect(claim.inputs.noteOut.noteVersion.equals(NOTE_VERSION)).toBe(true);
    expect(claim.inputs.noteOut.noteType.toBigInt()).toBe(0n);
    expect(claim.inputs.noteOut.conditionsHash.toBigInt()).toBe(0n);
    expect(claim.inputs.noteOut.parents.toBigInt()).toBe(0n);
    expect(claim.inputs.noteOut.value.equals(toFr(VALUE))).toBe(true);
    expect(claim.inputs.noteOut.assetId.equals(addressToFr(TOKEN))).toBe(true);

    const psi = await computePsi(deriveCek(claim.inputs.eph, COMPLIANCE_PK));
    expect(claim.inputs.noteOut.psi.equals(psi)).toBe(true);
    const owner = await pubkeyOwner(await repo.getSelfSpendPub());
    expect(claim.inputs.noteOut.owner.equals(owner)).toBe(true);
    expect(claim.note.value).toBe(VALUE);
    expect(claim.commitment.equals(await computeLeaf(claim.note))).toBe(true);
  });

  it("reserves each self ephemeral from the durable counter, never reusing an index", async () => {
    const store = new InMemoryEphemeralCounterStore();
    const repo = keyRepo(store);
    const checked = await preflight(repo);
    const first = await buildPublicClaim({
      memo: await postedMemo(),
      viewKey,
      ownerIndex: addressIndex,
      ...CLAIM_CONTEXT,
      keys: repo,
      selfMint: (await checked.take(1))[0],
      currentTimestamp: 1_800_000_000,
    });
    const second = await buildPublicClaim({
      memo: await postedMemo(),
      viewKey,
      ownerIndex: addressIndex,
      ...CLAIM_CONTEXT,
      keys: repo,
      selfMint: (await checked.take(1))[0],
      currentTimestamp: 1_800_000_000,
    });

    expect(second.ephemeralIndex).toBeGreaterThan(first.ephemeralIndex);
    expect(first.inputs.eph.equals(second.inputs.eph)).toBe(false);
    expect(await store.highWater("self")).toBeGreaterThan(
      second.ephemeralIndex,
    );
  });

  it("refuses to mint without a durable counter (two-time-pad hazard)", async () => {
    const repo = keyRepo(new SealedEphemeralCounterStore());
    await expect((await preflight(repo)).take(1)).rejects.toThrow(
      /durable ephemeral counter/,
    );
  });

  it("refuses an index the memo is not addressed to without allocating inside assembly", async () => {
    const store = new InMemoryEphemeralCounterStore();
    const repo = keyRepo(store);
    const checked = await preflight(repo);
    const selfMint = (await checked.take(1))[0];
    const highWater = await store.highWater("self");
    await expect(
      buildPublicClaim({
        memo: await postedMemo(),
        viewKey,
        ownerIndex: addressIndex + 1n,
        ...CLAIM_CONTEXT,
        keys: repo,
        selfMint,
        currentTimestamp: 1_800_000_000,
      }),
    ).rejects.toThrow(PublicMemoError);
    expect(await store.highWater("self")).toBe(highWater);
  });

  it("refuses a claim before the timelock expires", async () => {
    const repo = keyRepo(new InMemoryEphemeralCounterStore());
    await expect(
      buildPublicClaim({
        memo: await postedMemo(1_900_000_000n),
        viewKey,
        ownerIndex: addressIndex,
        ...CLAIM_CONTEXT,
        keys: repo,
        selfMint: (await (await preflight(repo)).take(1))[0],
        currentTimestamp: 1_800_000_000,
      }),
    ).rejects.toThrow(PublicMemoError);
  });

  it("accepts the claim once the timelock has passed", async () => {
    const repo = keyRepo(new InMemoryEphemeralCounterStore());
    const claim = await buildPublicClaim({
      memo: await postedMemo(1_700_000_000n),
      viewKey,
      ownerIndex: addressIndex,
      ...CLAIM_CONTEXT,
      keys: repo,
      selfMint: (await (await preflight(repo)).take(1))[0],
      currentTimestamp: 1_800_000_000,
    });
    expect(claim.inputs.timelock.equals(toFr(1_700_000_000n))).toBe(true);
  });
});
