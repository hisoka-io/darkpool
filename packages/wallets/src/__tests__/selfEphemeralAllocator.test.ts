import { describe, expect, it } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import { subOrder } from "@zk-kit/baby-jubjub";
import {
  COMMITMENT_PREFIX_BYTES,
  CIPHERTEXT_KEPT_INDICES,
  DarkAccount,
  HOWL_NOTE_LAYOUT_VERSION,
  InMemoryEphemeralCounterStore,
  RECORD_KIND_INCOMING,
  SELF_EPHEMERAL_SCOPE,
  SealedEphemeralCounterStore,
  SelfEphemeralAllocator,
  SelfEphemeralAllocatorError,
  SelfMintError,
  SelfMintPreflight,
  SelfMintPreflightError,
  completeComplianceHistory,
  isEvenY,
  publicKey,
  pubkeyOwner,
  reconcileCounterWithChain,
  type DiscoverySource,
  type EphemeralCounterStore,
  type HowlNoteRecord,
  type SelfMintCandidate,
} from "../index.js";
import { assembleDeposit } from "../tx/assemble.js";
import { mintSelfNote } from "../note/mint.js";
import {
  asDerivedEph,
  markDerivedSelfMintCandidate,
} from "../types/ephemeral.js";

const MNEMONIC = "test test test test test test test test test test test junk";
const COMPLIANCE_PK = publicKey(new Fr(987654321n));
const HISTORY = completeComplianceHistory({
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

const account = await DarkAccount.fromMnemonic(MNEMONIC);
const ownerCommitment = await pubkeyOwner(await account.getSelfSpendPub());

function countingStore(inner: EphemeralCounterStore) {
  const spans: number[] = [];
  const commits: number[] = [];
  const store: EphemeralCounterStore = {
    reserve: async (scope, span) => {
      spans.push(span);
      const reservation = await inner.reserve(scope, span);
      return {
        ...reservation,
        commit: (usedThrough: number) => {
          commits.push(usedThrough);
          return reservation.commit(usedThrough);
        },
      };
    },
    highWater: (scope) => inner.highWater(scope),
  };
  return { store, spans, commits };
}

async function firstIndexWithOddY(odd: boolean): Promise<number> {
  for (let index = 0; ; index++) {
    const pub = publicKey(await account.getSelfEphemeral(BigInt(index)));
    if (isEvenY(pub) !== odd) return index;
  }
}

describe("SelfEphemeralAllocator", () => {
  it("derives every candidate at a fresh durable index, even-y, burning each odd-y index", async () => {
    const inner = new InMemoryEphemeralCounterStore();
    const { store, spans, commits } = countingStore(inner);
    const allocator = new SelfEphemeralAllocator(account, store);

    const candidates: SelfMintCandidate[] = [];
    for (let i = 0; i < 8; i++) candidates.push(await allocator.next());

    let expectedFrom = 0;
    for (const candidate of candidates) {
      const derived = await account.getSelfEphemeral(BigInt(candidate.index));
      expect(candidate.eph.equals(derived)).toBe(true);
      expect(candidate.ephPub).toEqual(publicKey(derived));
      expect(isEvenY(candidate.ephPub)).toBe(true);
      expect(candidate.tag.equals(new Fr(candidate.ephPub[0]))).toBe(true);
      for (let skipped = expectedFrom; skipped < candidate.index; skipped++) {
        const skippedPub = publicKey(
          await account.getSelfEphemeral(BigInt(skipped)),
        );
        expect(isEvenY(skippedPub)).toBe(false);
      }
      expectedFrom = candidate.index + 1;
    }
    const last = candidates[candidates.length - 1];
    expect(spans.every((span) => span === 1)).toBe(true);
    expect(spans).toHaveLength(last.index + 1);
    expect(commits).toEqual(candidates.map((candidate) => candidate.index));
    expect(await inner.highWater(SELF_EPHEMERAL_SCOPE)).toBe(last.index + 1);
    expect(candidates.some((candidate) => candidate.index > 7)).toBe(true);
  });

  it("never reissues an index or tag after a restart from the durable snapshot", async () => {
    const first = new InMemoryEphemeralCounterStore();
    const before = new SelfEphemeralAllocator(account, first);
    const issued = [
      await before.next(),
      await before.next(),
      await before.next(),
    ];

    const restarted = new SelfEphemeralAllocator(
      account,
      new InMemoryEphemeralCounterStore(first.snapshot()),
    );
    const after = await restarted.next();
    expect(after.index).toBeGreaterThan(
      Math.max(...issued.map((candidate) => candidate.index)),
    );
    for (const candidate of issued) {
      expect(after.tag.equals(candidate.tag)).toBe(false);
    }
  });

  it("hands concurrent callers distinct indices", async () => {
    const allocator = new SelfEphemeralAllocator(
      account,
      new InMemoryEphemeralCounterStore(),
    );
    const candidates = await Promise.all(
      Array.from({ length: 6 }, () => allocator.next()),
    );
    expect(new Set(candidates.map((c) => c.index)).size).toBe(6);
    expect(new Set(candidates.map((c) => c.tag.toString())).size).toBe(6);
  });

  it("starts after the high-water that chain reconciliation ratchets on its scope", async () => {
    const store = new InMemoryEphemeralCounterStore();
    const occupiedIndex = 12;
    const occupiedTag = new Fr(
      publicKey(await account.getSelfEphemeral(BigInt(occupiedIndex)))[0],
    );
    const occupiedSource: DiscoverySource = {
      ...emptyDiscovery,
      probeFirst: (tags) =>
        Promise.resolve(
          tags.map((tag) => ({
            tag,
            record: MISS_RECORD,
            occurrenceCount: tag.equals(occupiedTag) ? 1 : 0,
          })),
        ),
    };
    await reconcileCounterWithChain(
      occupiedSource,
      store,
      SELF_EPHEMERAL_SCOPE,
      [{ index: occupiedIndex, tag: occupiedTag }],
    );

    const next = await new SelfEphemeralAllocator(account, store).next();
    expect(next.index).toBeGreaterThan(occupiedIndex);
  });

  it("is the allocator SelfMintPreflight takes, and its authorization mints the derived note", async () => {
    const allocator = new SelfEphemeralAllocator(
      account,
      new InMemoryEphemeralCounterStore(),
    );
    const preflight = new SelfMintPreflight({
      allocator,
      discovery: emptyDiscovery,
      history: HISTORY,
      ownerCommitment,
      domain: DOMAIN,
    });
    const [authorization] = await preflight.take(1);
    const deposit = await assembleDeposit(
      {
        compliancePk: COMPLIANCE_PK,
        complianceVersion: 1,
        complianceHistory: HISTORY,
        ...DOMAIN,
        merkle: { witnessFor: () => Promise.reject(new Error("unused")) },
      },
      {
        value: 10n,
        assetId: new Fr(0xa11cen),
        spendScalar: await account.getSelfSpendKey(),
        selfMint: authorization,
      },
    );
    const expected = await account.getSelfEphemeral(
      BigInt(await firstIndexWithOddY(false)),
    );
    expect(deposit.inputs.eph.equals(expected)).toBe(true);
    expect(deposit.minted.tag.equals(new Fr(publicKey(expected)[0]))).toBe(
      true,
    );
  });

  it("refuses with a typed error when no durable counter is configured", async () => {
    const attempt = new SelfEphemeralAllocator(
      account,
      new SealedEphemeralCounterStore(),
    ).next();
    await expect(attempt).rejects.toBeInstanceOf(SelfEphemeralAllocatorError);
    await expect(attempt).rejects.toMatchObject({
      reason: "COUNTER_UNAVAILABLE",
    });
    await expect(attempt).rejects.toThrow(
      /no durable ephemeral counter configured/,
    );
  });

  it("refuses a counter that returns an unusable base", async () => {
    const broken: EphemeralCounterStore = {
      reserve: () =>
        Promise.resolve({
          base: -1,
          span: 1,
          commit: () => Promise.resolve(),
          release: () => Promise.resolve(),
        }),
      highWater: () => Promise.resolve(0),
    };
    await expect(
      new SelfEphemeralAllocator(account, broken).next(),
    ).rejects.toMatchObject({ reason: "COUNTER_INVALID" });
  });

  it("types a failed commit and never reissues the burned index", async () => {
    const inner = new InMemoryEphemeralCounterStore();
    const backendError = new Error("commit write failed");
    let failCommit = true;
    const flaky: EphemeralCounterStore = {
      reserve: async (scope, span) => {
        const reservation = await inner.reserve(scope, span);
        return {
          ...reservation,
          commit: (usedThrough: number) => {
            if (failCommit) {
              failCommit = false;
              return Promise.reject(backendError);
            }
            return reservation.commit(usedThrough);
          },
        };
      },
      highWater: (scope) => inner.highWater(scope),
    };
    const allocator = new SelfEphemeralAllocator(account, flaky);
    const burned = await firstIndexWithOddY(false);

    const attempt = allocator.next();
    await expect(attempt).rejects.toBeInstanceOf(SelfEphemeralAllocatorError);
    await expect(attempt).rejects.toMatchObject({
      reason: "COUNTER_COMMIT_FAILED",
      cause: backendError,
    });
    await expect(attempt).rejects.toThrow(
      new RegExp(`index ${burned} was reserved but its commit failed`),
    );
    expect(await inner.highWater(SELF_EPHEMERAL_SCOPE)).toBe(burned + 1);

    const next = await allocator.next();
    expect(next.index).toBeGreaterThan(burned);
  });

  it("gives up with a typed refusal when no reserved index is even-y, committing none", async () => {
    const odd = await firstIndexWithOddY(true);
    let commits = 0;
    let reservations = 0;
    const stuck: EphemeralCounterStore = {
      reserve: () => {
        reservations += 1;
        return Promise.resolve({
          base: odd,
          span: 1,
          commit: () => {
            commits += 1;
            return Promise.resolve();
          },
          release: () => Promise.resolve(),
        });
      },
      highWater: () => Promise.resolve(odd + 1),
    };
    await expect(
      new SelfEphemeralAllocator(account, stuck).next(),
    ).rejects.toMatchObject({ reason: "NO_CANONICAL_EPHEMERAL" });
    expect(reservations).toBe(256);
    expect(commits).toBe(0);
  });

  it("accepts only a DarkAccount, whose derivation is what makes the note findable", () => {
    const impostor = {
      getSelfEphemeral: (index: bigint) =>
        Promise.resolve(asDerivedEph(new Fr(index + 1n))),
      getSelfSpendPub: () => account.getSelfSpendPub(),
    } as unknown as DarkAccount;
    let caught: unknown;
    try {
      new SelfEphemeralAllocator(impostor, new InMemoryEphemeralCounterStore());
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(SelfEphemeralAllocatorError);
    expect(caught).toMatchObject({ reason: "INVALID_ACCOUNT" });
  });
});

describe("odd-y and out-of-range self ephemerals are refused before proving", () => {
  function oddYScalar(): Fr {
    let scalar = 2n;
    while (isEvenY(publicKey(new Fr(scalar)))) scalar += 1n;
    return new Fr(scalar);
  }

  function preflightOver(eph: Fr) {
    const ephPub = publicKey(eph);
    return new SelfMintPreflight({
      allocator: {
        next: () =>
          Promise.resolve(
            markDerivedSelfMintCandidate(
              {
                eph: asDerivedEph(eph),
                ephPub,
                tag: new Fr(ephPub[0]),
                index: 3,
              },
              ownerCommitment,
            ),
          ),
      },
      discovery: emptyDiscovery,
      history: HISTORY,
      ownerCommitment,
      domain: DOMAIN,
    });
  }

  it("SelfMintPreflight refuses an odd-y candidate", async () => {
    const attempt = preflightOver(oddYScalar()).take(1);
    await expect(attempt).rejects.toBeInstanceOf(SelfMintPreflightError);
    await expect(attempt).rejects.toMatchObject({ reason: "CANDIDATE_ODD_Y" });
  });

  it("SelfMintPreflight refuses a candidate scalar at or above the subgroup order", async () => {
    await expect(
      preflightOver(new Fr(subOrder + 2n)).take(1),
    ).rejects.toMatchObject({ reason: "CANDIDATE_EPH_RANGE" });
  });

  it("mintSelfNote refuses an odd-y or out-of-range ephemeral", async () => {
    const spend = await account.getSelfSpendKey();
    const mint = (eph: Fr) =>
      mintSelfNote(
        asDerivedEph(eph),
        1n,
        spend,
        new Fr(0xa11cen),
        COMPLIANCE_PK,
      );
    await expect(mint(oddYScalar())).rejects.toBeInstanceOf(SelfMintError);
    await expect(mint(oddYScalar())).rejects.toMatchObject({
      reason: "SELF_EPH_ODD_Y",
    });
    await expect(mint(Fr.ZERO)).rejects.toMatchObject({
      reason: "SELF_EPH_RANGE",
    });
    await expect(mint(new Fr(subOrder))).rejects.toMatchObject({
      reason: "SELF_EPH_RANGE",
    });
  });
});
