import { describe, expect, it } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import {
  asDerivedEph,
  markDerivedSelfMintCandidate,
} from "../types/ephemeral.js";
import { publicKey, pubkeyOwner } from "../note/keys.js";
import {
  completeComplianceHistory,
  type ComplianceKeyRotation,
} from "../note/complianceKeys.js";
import {
  SelfMintAuthorizationError,
  SelfMintPreflight,
  consumeSelfMints,
  type SelfMintCandidate,
  type SelfMintContext,
  type SelfMintAuthorization,
} from "../discovery/preflight.js";
import {
  CIPHERTEXT_KEPT_INDICES,
  COMMITMENT_PREFIX_BYTES,
  HOWL_NOTE_LAYOUT_VERSION,
  RECORD_KIND_INCOMING,
  type HowlNoteRecord,
} from "../discovery/types.js";
import { DarkAccount } from "../keys/DarkAccount.js";
import { KeyRepository } from "../state/KeyRepository.js";
import { InMemoryEphemeralCounterStore } from "../state/EphemeralCounterStore.js";

const OWNER_A_SCALAR = new Fr(0x1111n);
const OWNER_B_SCALAR = new Fr(0x2222n);
const OWNER_A_COMMITMENT = await pubkeyOwner(publicKey(OWNER_A_SCALAR));
const OWNER_B_COMMITMENT = await pubkeyOwner(publicKey(OWNER_B_SCALAR));
const GENESIS_PK = publicKey(new Fr(0x3333n));
const ROTATED_PK = publicKey(new Fr(0x4444n));
const ROTATION: ComplianceKeyRotation = {
  oldVersion: 1,
  newVersion: 2,
  newX: ROTATED_PK[0],
  newY: ROTATED_PK[1],
  blockNumber: 100,
};
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

function candidate(
  seed: bigint,
  ownerCommitment = OWNER_A_COMMITMENT,
): SelfMintCandidate {
  const eph = asDerivedEph(new Fr(seed));
  const ephPub = publicKey(eph);
  return markDerivedSelfMintCandidate(
    {
      eph,
      ephPub,
      tag: new Fr(ephPub[0]),
      index: Number(seed),
    },
    ownerCommitment,
  );
}

function history(
  rotations: readonly ComplianceKeyRotation[] = [],
  currentPk = rotations.length === 0 ? GENESIS_PK : ROTATED_PK,
  currentVersion = rotations.length + 1,
) {
  return completeComplianceHistory({
    genesisPk: GENESIS_PK,
    rotations,
    currentPk,
    currentVersion,
  });
}

async function context(
  ownerScalar = OWNER_A_SCALAR,
  compliance = history(),
): Promise<SelfMintContext> {
  return {
    ownerCommitment: await pubkeyOwner(publicKey(ownerScalar)),
    compliancePk: compliance.currentPk,
    complianceVersion: compliance.currentVersion,
    complianceHistory: compliance,
    ...DOMAIN,
  };
}

async function preflight(
  values: readonly SelfMintCandidate[],
  ownerScalar = OWNER_A_SCALAR,
) {
  let index = 0;
  const certified = await context(ownerScalar);
  return {
    certified,
    preflight: new SelfMintPreflight({
      allocator: {
        next: () => {
          const value = values[index++];
          return value === undefined
            ? Promise.reject(new Error("fixture exhausted"))
            : Promise.resolve(value);
        },
      },
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
      history: history(),
      ownerCommitment: certified.ownerCommitment,
      domain: DOMAIN,
    }),
  };
}

describe("complete compliance history", () => {
  it("pins initialization at version 1 and validates a contiguous rotation", () => {
    const genesis = history();
    expect(genesis.currentVersion).toBe(1);
    expect(genesis.ring.epochs.map((epoch) => epoch.version)).toEqual([1]);

    const rotated = history([ROTATION]);
    expect(rotated.currentVersion).toBe(2);
    expect(rotated.ring.epochs.map((epoch) => epoch.version)).toEqual([1, 2]);
    expect(Object.isFrozen(rotated.ring.epochs)).toBe(true);
    expect(Reflect.deleteProperty(rotated.ring.epochs, "0")).toBe(false);
    expect(rotated.ring.epochs).toHaveLength(2);
  });

  it("rejects missing, out-of-order, and wrong-current histories", () => {
    expect(() => history([], ROTATED_PK, 2)).toThrow(/incomplete|version/i);
    expect(() =>
      history([{ ...ROTATION, oldVersion: 2, newVersion: 3 }], ROTATED_PK, 3),
    ).toThrow(/version/i);
    expect(() =>
      completeComplianceHistory({
        genesisPk: GENESIS_PK,
        rotations: [
          { ...ROTATION, blockNumber: 200 },
          {
            oldVersion: 2,
            newVersion: 3,
            newX: GENESIS_PK[0],
            newY: GENESIS_PK[1],
            blockNumber: 100,
          },
        ],
        currentPk: GENESIS_PK,
        currentVersion: 3,
      }),
    ).toThrow(/block|order/i);
    expect(() => history([ROTATION], GENESIS_PK, 2)).toThrow(/current key/i);
    expect(() =>
      Reflect.construct(SelfMintPreflight, [
        {
          allocator: { next: () => Promise.resolve(candidate(3n)) },
          discovery: {
            probeFirst: () => Promise.resolve([]),
            fetchOccurrences: () => Promise.resolve([]),
            fetchLeafBlock: () => Promise.resolve([]),
          },
          history: {
            ring: history().ring,
            currentPk: GENESIS_PK,
            currentVersion: 1,
          },
          ownerCommitment: Fr.ZERO,
        },
      ]),
    ).toThrow(/not created|history/i);
  });
});

describe("opaque self-mint authorization", () => {
  it("exposes no candidate fields and rejects replay, copies, and plain objects", async () => {
    const publicSurface = await import("../index.js");
    expect("mintSelfNote" in publicSurface).toBe(false);
    expect("asDerivedEph" in publicSurface).toBe(false);
    const { preflight: checked, certified } = await preflight([candidate(5n)]);
    const [authorization] = await checked.take(1);
    expect(Object.isFrozen(authorization)).toBe(true);
    expect(Object.keys(authorization)).toEqual([]);
    expect(Object.getOwnPropertySymbols(authorization)).toEqual([]);
    const copied = { ...authorization };
    if (false) {
      // @ts-expect-error spreading drops the private nominal authorization identity
      const _authorization: SelfMintAuthorization = copied;
    }

    const [mint] = consumeSelfMints([authorization], certified);
    expect(mint.eph.toBigInt()).toBe(5n);
    expect(() => consumeSelfMints([authorization], certified)).toThrow(
      SelfMintAuthorizationError,
    );
    expect(() => consumeSelfMints([copied], certified)).toThrow(
      /unknown|copy/i,
    );
    expect(() => consumeSelfMints([{}], certified)).toThrow(/unknown|copy/i);

    const aliased = candidate(6n);
    const aliasCheck = await preflight([aliased]);
    const [aliasAuthorization] = await aliasCheck.preflight.take(1);
    Reflect.set(aliased.eph, "asBigInt", 99n);
    const [snapshotted] = consumeSelfMints(
      [aliasAuthorization],
      aliasCheck.certified,
    );
    expect(snapshotted.eph.toBigInt()).toBe(6n);

    const ownerAliasCheck = await preflight([candidate(13n)]);
    const [ownerAliasAuthorization] = await ownerAliasCheck.preflight.take(1);
    Reflect.set(
      ownerAliasCheck.certified.ownerCommitment,
      "asBigInt",
      OWNER_B_SCALAR.toBigInt(),
    );
    expect(() =>
      consumeSelfMints([ownerAliasAuthorization], ownerAliasCheck.certified),
    ).toThrow(/context/i);

    const mutableCandidate = candidate(14n);
    const replacement = candidate(140n);
    Reflect.set(mutableCandidate, "eph", replacement.eph);
    Reflect.set(mutableCandidate, "ephPub", replacement.ephPub);
    Reflect.set(mutableCandidate, "tag", replacement.tag);
    const mutatedCheck = await preflight([mutableCandidate]);
    await expect(mutatedCheck.preflight.take(1)).rejects.toMatchObject({
      reason: "CANDIDATE_PROVENANCE_MISMATCH",
    });

    const sequentialCandidate = candidate(15n);
    const sequentialFirst = await preflight([sequentialCandidate]);
    const sequentialSecond = await preflight([sequentialCandidate]);
    await expect(sequentialFirst.preflight.take(1)).resolves.toHaveLength(1);
    await expect(sequentialSecond.preflight.take(1)).rejects.toMatchObject({
      reason: "CANDIDATE_ALREADY_CLAIMED",
    });

    const concurrentCandidate = candidate(16n);
    const concurrentLeft = await preflight([concurrentCandidate]);
    const concurrentRight = await preflight([concurrentCandidate]);
    const claims = await Promise.allSettled([
      concurrentLeft.preflight.take(1),
      concurrentRight.preflight.take(1),
    ]);
    expect(claims.filter((claim) => claim.status === "fulfilled")).toHaveLength(
      1,
    );
    expect(claims.filter((claim) => claim.status === "rejected")).toHaveLength(
      1,
    );
  });

  it("checks the whole set and context before consuming either handle", async () => {
    const { preflight: checked, certified } = await preflight([
      candidate(7n),
      candidate(8n),
    ]);
    const [first, second] = await checked.take(2);
    expect(() => consumeSelfMints([first, first], certified)).toThrow(
      /duplicate/i,
    );

    const wrongOwner = await context(OWNER_B_SCALAR);
    expect(() => consumeSelfMints([first, second], wrongOwner)).toThrow(
      /context/i,
    );
    expect(() =>
      consumeSelfMints([first, second], {
        ...certified,
        compliancePk: ROTATED_PK,
      }),
    ).toThrow(/context/i);
    expect(() =>
      consumeSelfMints([first, second], {
        ...certified,
        complianceVersion: certified.complianceVersion + 1,
      }),
    ).toThrow(/context/i);
    expect(() =>
      consumeSelfMints([first, second], {
        ...certified,
        poolAddress: "0x0000000000000000000000000000000000000002",
      }),
    ).toThrow(/context/i);

    const mints = consumeSelfMints([first, second], certified);
    expect(mints.map((mint) => mint.eph.toBigInt())).toEqual([7n, 8n]);

    const left = await preflight([candidate(9n)]);
    const right = await preflight(
      [candidate(10n, OWNER_B_COMMITMENT)],
      OWNER_B_SCALAR,
    );
    const [leftHandle] = await left.preflight.take(1);
    const [rightHandle] = await right.preflight.take(1);
    expect(() =>
      consumeSelfMints([leftHandle, rightHandle], left.certified),
    ).toThrow(/context/i);
    expect(consumeSelfMints([leftHandle], left.certified)).toHaveLength(1);
    expect(consumeSelfMints([rightHandle], right.certified)).toHaveLength(1);

    const correctRotated = history([ROTATION]);
    const wrongGenesis = publicKey(new Fr(0x5555n));
    const wrongRotated = completeComplianceHistory({
      genesisPk: wrongGenesis,
      rotations: [
        {
          ...ROTATION,
          newX: ROTATED_PK[0],
          newY: ROTATED_PK[1],
        },
      ],
      currentPk: ROTATED_PK,
      currentVersion: 2,
    });
    const rotatedOwner = await pubkeyOwner(publicKey(OWNER_A_SCALAR));
    const rotatedPreflight = new SelfMintPreflight({
      allocator: { next: () => Promise.resolve(candidate(12n)) },
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
      history: correctRotated,
      ownerCommitment: rotatedOwner,
      domain: DOMAIN,
    });
    const [rotatedAuthorization] = await rotatedPreflight.take(1);
    expect(() =>
      consumeSelfMints([rotatedAuthorization], {
        ownerCommitment: rotatedOwner,
        compliancePk: wrongRotated.currentPk,
        complianceVersion: wrongRotated.currentVersion,
        complianceHistory: wrongRotated,
        ...DOMAIN,
      }),
    ).toThrow(/context/i);

    const walletA = await DarkAccount.fromMnemonic(
      "test test test test test test test test test test test junk",
    );
    const walletB = await DarkAccount.fromMnemonic(
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    );
    const walletACandidate = await new KeyRepository(
      walletA,
      new InMemoryEphemeralCounterStore(),
    ).nextSelfEphemeral();
    const walletBOwner = await pubkeyOwner(await walletB.getSelfSpendPub());
    const crossWallet = new SelfMintPreflight({
      allocator: { next: () => Promise.resolve(walletACandidate) },
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
      history: history(),
      ownerCommitment: walletBOwner,
      domain: DOMAIN,
    });
    await expect(crossWallet.take(1)).rejects.toMatchObject({
      reason: "CANDIDATE_OWNER_MISMATCH",
    });
  });
});
