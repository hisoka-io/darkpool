import { describe, expect, it } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import {
  asDerivedEph,
  markDerivedSelfMintCandidate,
  type DerivedEph,
} from "../types/ephemeral.js";
import { deriveCek } from "../crypto/kem.js";
import { demEncrypt } from "../crypto/dem.js";
import { computePsi } from "../note/nullifier.js";
import { publicKey, pubkeyOwner } from "../note/keys.js";
import {
  leaf as computeLeaf,
  NOTE_TYPE_STANDARD,
  NOTE_VERSION,
} from "../note/note.js";
import {
  completeComplianceHistory,
  type CompleteComplianceHistory,
} from "../note/complianceKeys.js";
import {
  COMMITMENT_PREFIX_BYTES,
  CIPHERTEXT_KEPT_INDICES,
  HOWL_NOTE_LAYOUT_VERSION,
  RECORD_KIND_INCOMING,
  RECORD_KIND_SELF,
  type DiscoverySource,
  type FirstOccurrence,
  type HowlNoteRecord,
  type OccurrenceRequest,
} from "../discovery/types.js";
import {
  MAX_PREFLIGHT_CANDIDATES,
  PREFLIGHT_COLLISION_BATCH_SIZE,
  SelfMintPreflight,
  consumeSelfMints,
  opensExistingSelfRecord,
  type SelfMintAuthorization,
  type SelfMintAllocator,
  type SelfMintCandidate,
} from "../discovery/preflight.js";

const ZERO = Fr.ZERO;
const ASSET = new Fr(0xa11cen);
const OWNER_SCALAR = new Fr(0x1234n);
const OWNER_COMMITMENT = await pubkeyOwner(publicKey(OWNER_SCALAR));
const OLD_COMPLIANCE = publicKey(new Fr(0x2222n));
const CURRENT_COMPLIANCE = publicKey(new Fr(0x3333n));
const DOMAIN = {
  chainId: 31337n,
  poolAddress: "0x0000000000000000000000000000000000000001",
  deploymentAnchor: 1n,
};

function candidate(
  seed: bigint,
): SelfMintCandidate & { readonly eph: DerivedEph } {
  let eph = asDerivedEph(new Fr(seed));
  let ephPub = publicKey(eph);
  while ((ephPub[1] & 1n) !== 0n) {
    eph = asDerivedEph(new Fr(eph.toBigInt() + 1n));
    ephPub = publicKey(eph);
  }
  return markDerivedSelfMintCandidate(
    {
      eph,
      ephPub,
      tag: new Fr(ephPub[0]),
      index: Number(seed),
    },
    OWNER_COMMITMENT,
  );
}

const CURRENT_HISTORY = completeComplianceHistory({
  genesisPk: CURRENT_COMPLIANCE,
  rotations: [],
  currentPk: CURRENT_COMPLIANCE,
  currentVersion: 1,
});

const ROTATED_HISTORY = completeComplianceHistory({
  genesisPk: OLD_COMPLIANCE,
  rotations: [
    {
      oldVersion: 1,
      newVersion: 2,
      newX: CURRENT_COMPLIANCE[0],
      newY: CURRENT_COMPLIANCE[1],
    },
  ],
  currentPk: CURRENT_COMPLIANCE,
  currentVersion: 2,
});

function consume(
  handles: readonly SelfMintAuthorization[],
  ownerCommitment: Fr,
  history: CompleteComplianceHistory = CURRENT_HISTORY,
) {
  return consumeSelfMints(handles, {
    ownerCommitment,
    compliancePk: history.currentPk,
    complianceVersion: history.currentVersion,
    complianceHistory: history,
    ...DOMAIN,
  });
}

async function recordFor(
  mint: SelfMintCandidate,
  ownerCommitment: Fr,
  compliancePk = CURRENT_COMPLIANCE,
  value = 9n,
): Promise<HowlNoteRecord> {
  const cek = deriveCek(mint.eph, compliancePk);
  const psi = await computePsi(cek);
  const plaintext = [
    NOTE_VERSION,
    ASSET,
    new Fr(NOTE_TYPE_STANDARD),
    ZERO,
    new Fr(value),
    ownerCommitment,
    ZERO,
  ];
  const commitment = await computeLeaf({
    noteVersion: plaintext[0],
    assetId: plaintext[1],
    noteType: plaintext[2],
    conditionsHash: plaintext[3],
    value,
    owner: plaintext[5],
    psi,
    parents: plaintext[6],
  });
  const ciphertext = await demEncrypt(cek, plaintext);
  return {
    layoutVersion: HOWL_NOTE_LAYOUT_VERSION,
    recordKind: RECORD_KIND_SELF,
    leafIndex: 7,
    commitmentPrefix: commitment
      .toBuffer()
      .subarray(0, COMMITMENT_PREFIX_BYTES),
    ephemeralPkX: ZERO,
    cekWrap: ZERO,
    ciphertextKept: CIPHERTEXT_KEPT_INDICES.map((index) => ciphertext[index]),
  };
}

class SequenceAllocator<
  T extends SelfMintCandidate,
> implements SelfMintAllocator<T> {
  readonly #values: readonly T[];
  calls = 0;

  constructor(values: readonly T[]) {
    this.#values = values;
  }

  next(): Promise<T> {
    const value = this.#values[this.calls++];
    return value === undefined
      ? Promise.reject(new Error(`fixture exhausted after ${this.calls - 1}`))
      : Promise.resolve(value);
  }
}

class FixtureDiscovery implements DiscoverySource {
  readonly batches: readonly Fr[][] = [];
  readonly #records: ReadonlyMap<string, HowlNoteRecord>;
  readonly #miss: HowlNoteRecord | null;

  constructor(
    records: ReadonlyMap<string, HowlNoteRecord>,
    miss: HowlNoteRecord | null,
  ) {
    this.#records = records;
    this.#miss = miss;
  }

  probeFirst(tags: readonly Fr[]): Promise<readonly FirstOccurrence[]> {
    (this.batches as Fr[][]).push([...tags]);
    return Promise.resolve(
      tags.map((tag) => {
        const record = this.#records.get(tag.toString());
        return {
          tag,
          record: record ?? this.#miss,
          occurrenceCount: record === undefined ? 0 : 1,
        };
      }),
    );
  }

  fetchOccurrences(
    _requests: readonly OccurrenceRequest[],
  ): Promise<readonly (HowlNoteRecord | null)[]> {
    return Promise.resolve([]);
  }

  fetchLeafBlock(_blockIndex: number): Promise<readonly Fr[]> {
    return Promise.resolve([]);
  }
}

async function owner(): Promise<Fr> {
  return pubkeyOwner(publicKey(OWNER_SCALAR));
}

describe("opensExistingSelfRecord", () => {
  it("opens a real self record under the current compliance key", async () => {
    const mint = candidate(1n);
    const ownerCommitment = await owner();
    await expect(
      opensExistingSelfRecord(
        mint,
        await recordFor(mint, ownerCommitment),
        CURRENT_HISTORY,
        ownerCommitment,
      ),
    ).resolves.toBe(true);
  });

  it("opens a real self record under an older compliance epoch", async () => {
    const mint = candidate(10n);
    const ownerCommitment = await owner();
    await expect(
      opensExistingSelfRecord(
        mint,
        await recordFor(mint, ownerCommitment, OLD_COMPLIANCE),
        ROTATED_HISTORY,
        ownerCommitment,
      ),
    ).resolves.toBe(true);
  });

  it("rejects misses, incoming rows, wrong owners, and wrong prefixes", async () => {
    const mint = candidate(20n);
    const other = candidate(30n);
    const ownerCommitment = await owner();
    const real = await recordFor(mint, ownerCommitment);
    const decoy = await recordFor(other, ownerCommitment);
    const wrongOwner = await recordFor(mint, new Fr(0xdeadn));
    const wrongPrefix = {
      ...real,
      commitmentPrefix: Uint8Array.from(real.commitmentPrefix, (byte, index) =>
        index === 0 ? byte ^ 1 : byte,
      ),
    };
    for (const record of [
      null,
      decoy,
      { ...real, recordKind: RECORD_KIND_INCOMING } as HowlNoteRecord,
      wrongOwner,
      wrongPrefix,
      { ...real, ciphertextKept: [Fr.ZERO] },
    ]) {
      await expect(
        opensExistingSelfRecord(mint, record, CURRENT_HISTORY, ownerCommitment),
      ).resolves.toBe(false);
    }
  });
});

describe("SelfMintPreflight", () => {
  it("returns one privately branded miss from one normal query", async () => {
    const available = candidate(100n);
    const decoyCandidate = candidate(200n);
    const ownerCommitment = await owner();
    const allocator = new SequenceAllocator([available]);
    const discovery = new FixtureDiscovery(
      new Map(),
      await recordFor(decoyCandidate, ownerCommitment),
    );
    const preflight = new SelfMintPreflight({
      allocator,
      discovery,
      history: CURRENT_HISTORY,
      ownerCommitment,
      domain: DOMAIN,
    });

    const [authorization] = await preflight.take(1);
    const [mint] = consume([authorization], ownerCommitment);
    expect(mint.eph.equals(available.eph)).toBe(true);
    expect(allocator.calls).toBe(1);
    expect(discovery.batches.map((batch) => batch.length)).toEqual([1]);
  });

  it("replaces a confirmed hit with one five-candidate batch and queues clean extras", async () => {
    const values = Array.from({ length: 7 }, (_, index) =>
      candidate(1_000n + BigInt(index) * 100n),
    );
    const ownerCommitment = await owner();
    const occupied = await recordFor(values[0], ownerCommitment);
    const miss = await recordFor(candidate(9_000n), ownerCommitment);
    const allocator = new SequenceAllocator(values);
    const discovery = new FixtureDiscovery(
      new Map([[values[0].tag.toString(), occupied]]),
      miss,
    );
    const preflight = new SelfMintPreflight({
      allocator,
      discovery,
      history: CURRENT_HISTORY,
      ownerCommitment,
      domain: DOMAIN,
    });

    const first = consume(await preflight.take(1), ownerCommitment)[0];
    expect(first.tag.toString()).toBe(values[1].tag.toString());
    expect(discovery.batches.map((batch) => batch.length)).toEqual([
      1,
      PREFLIGHT_COLLISION_BATCH_SIZE,
    ]);
    const second = consume(await preflight.take(1), ownerCommitment)[0];
    expect(second.tag.toString()).toBe(values[2].tag.toString());
    expect(discovery.batches).toHaveLength(2);
  });

  it("keeps sending five-candidate batches while every replacement collides", async () => {
    const values = Array.from({ length: 11 }, (_, index) =>
      candidate(10_000n + BigInt(index) * 100n),
    );
    const ownerCommitment = await owner();
    const records = new Map<string, HowlNoteRecord>();
    for (const value of values.slice(0, 6)) {
      records.set(
        value.tag.toString(),
        await recordFor(value, ownerCommitment),
      );
    }
    const discovery = new FixtureDiscovery(
      records,
      await recordFor(candidate(99_000n), ownerCommitment),
    );
    const preflight = new SelfMintPreflight({
      allocator: new SequenceAllocator(values),
      discovery,
      history: CURRENT_HISTORY,
      ownerCommitment,
      domain: DOMAIN,
    });

    await expect(preflight.take(1)).resolves.toHaveLength(1);
    expect(discovery.batches.map((batch) => batch.length)).toEqual([1, 5, 5]);
  });

  it("returns two distinct values together and replaces collisions in batches", async () => {
    const values = Array.from({ length: 7 }, (_, index) =>
      candidate(20_000n + BigInt(index) * 100n),
    );
    const ownerCommitment = await owner();
    const discovery = new FixtureDiscovery(
      new Map([
        [values[0].tag.toString(), await recordFor(values[0], ownerCommitment)],
      ]),
      await recordFor(candidate(199_000n), ownerCommitment),
    );
    const preflight = new SelfMintPreflight({
      allocator: new SequenceAllocator(values),
      discovery,
      history: CURRENT_HISTORY,
      ownerCommitment,
      domain: DOMAIN,
    });

    const minted = consume(await preflight.take(2), ownerCommitment);
    expect(minted.map((value) => value.tag.toString())).toEqual([
      values[1].tag.toString(),
      values[2].tag.toString(),
    ]);
    expect(new Set(minted.map((value) => value.tag.toString())).size).toBe(2);
    expect(discovery.batches.map((batch) => batch.length)).toEqual([2, 5]);
  });

  it("serializes concurrent takes on one preflight instance", async () => {
    const values = [candidate(21_000n), candidate(21_100n), candidate(21_200n)];
    const ownerCommitment = await owner();
    const miss = await recordFor(candidate(219_000n), ownerCommitment);
    const batches: Fr[][] = [];
    let releaseFirst: (() => void) | undefined;
    const firstReleased = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    const discovery: DiscoverySource = {
      probeFirst: async (tags) => {
        batches.push([...tags]);
        if (batches.length === 1) await firstReleased;
        return tags.map((tag) => ({
          tag,
          record: miss,
          occurrenceCount: 0,
        }));
      },
      fetchOccurrences: () => Promise.resolve([]),
      fetchLeafBlock: () => Promise.resolve([]),
    };
    const preflight = new SelfMintPreflight({
      allocator: new SequenceAllocator(values),
      discovery,
      history: CURRENT_HISTORY,
      ownerCommitment,
      domain: DOMAIN,
    });

    const pairPromise = preflight.take(2);
    for (let turn = 0; turn < 4; turn++) await Promise.resolve();
    const singlePromise = preflight.take(1);
    for (let turn = 0; turn < 4; turn++) await Promise.resolve();
    const concurrentBatchCount = batches.length;
    releaseFirst?.();
    const [pairHandles, singleHandles] = await Promise.all([
      pairPromise,
      singlePromise,
    ]);

    expect(concurrentBatchCount).toBe(1);
    expect(pairHandles).toHaveLength(2);
    expect(singleHandles).toHaveLength(1);
    const minted = [
      ...consume(pairHandles, ownerCommitment),
      ...consume(singleHandles, ownerCommitment),
    ];
    expect(new Set(minted.map((value) => value.tag.toString())).size).toBe(3);
    expect(batches.map((batch) => batch.length)).toEqual([2, 1]);
  });

  it("binds complete reordered responses by tag and rejects missing, duplicate, or unknown tags", async () => {
    const values = [candidate(30_000n), candidate(31_000n)];
    const ownerCommitment = await owner();
    const miss = await recordFor(candidate(299_000n), ownerCommitment);
    const base = {
      allocator: new SequenceAllocator(values),
      history: CURRENT_HISTORY,
      ownerCommitment,
      domain: DOMAIN,
    };
    const response = (
      entries: readonly FirstOccurrence[],
    ): DiscoverySource => ({
      probeFirst: () => Promise.resolve(entries),
      fetchOccurrences: () => Promise.resolve([]),
      fetchLeafBlock: () => Promise.resolve([]),
    });
    const entry = (tag: Fr): FirstOccurrence => ({
      tag,
      record: miss,
      occurrenceCount: 0,
    });

    await expect(
      new SelfMintPreflight({
        ...base,
        discovery: response([entry(values[1].tag), entry(values[0].tag)]),
      }).take(2),
    ).resolves.toHaveLength(2);

    const malformedResponses = [
      (attempt: readonly SelfMintCandidate[]) => [entry(attempt[0].tag)],
      (attempt: readonly SelfMintCandidate[]) => [
        entry(attempt[0].tag),
        entry(attempt[0].tag),
      ],
      (attempt: readonly SelfMintCandidate[]) => [
        entry(attempt[0].tag),
        entry(candidate(999_000n).tag),
      ],
    ];
    for (let i = 0; i < malformedResponses.length; i++) {
      const attempt = [
        candidate(32_000n + BigInt(i) * 200n),
        candidate(32_100n + BigInt(i) * 200n),
      ];
      await expect(
        new SelfMintPreflight({
          ...base,
          allocator: new SequenceAllocator(attempt),
          discovery: response(malformedResponses[i](attempt)),
        }).take(2),
      ).rejects.toMatchObject({ reason: "DISCOVERY_PROTOCOL" });
    }
  });

  it("wraps discovery failure once with an actionable typed error", async () => {
    const ownerCommitment = await owner();
    const preflight = new SelfMintPreflight({
      allocator: new SequenceAllocator([candidate(40_000n)]),
      discovery: {
        probeFirst: () => Promise.reject(new Error("raven offline")),
        fetchOccurrences: () => Promise.resolve([]),
        fetchLeafBlock: () => Promise.resolve([]),
      },
      history: CURRENT_HISTORY,
      ownerCommitment,
      domain: DOMAIN,
    });

    await expect(preflight.take(1)).rejects.toMatchObject({
      name: "SelfMintPreflightError",
      reason: "DISCOVERY_UNAVAILABLE",
      cause: expect.objectContaining({ message: "raven offline" }),
    });
  });

  it("rejects inconsistent allocator candidates and malformed responses", async () => {
    const valid = candidate(45_000n);
    const structuralCopy = { ...valid };
    const inconsistent = candidate(45_100n);
    Reflect.set(inconsistent, "tag", inconsistent.tag.add(new Fr(1n)));
    const ownerCommitment = await owner();
    await expect(
      new SelfMintPreflight({
        allocator: new SequenceAllocator([structuralCopy]),
        discovery: new FixtureDiscovery(new Map(), null),
        history: CURRENT_HISTORY,
        ownerCommitment,
        domain: DOMAIN,
      }).take(1),
    ).rejects.toMatchObject({ reason: "DISCOVERY_PROTOCOL" });

    await expect(
      new SelfMintPreflight({
        allocator: new SequenceAllocator([inconsistent]),
        discovery: new FixtureDiscovery(new Map(), null),
        history: CURRENT_HISTORY,
        ownerCommitment,
        domain: DOMAIN,
      }).take(1),
    ).rejects.toMatchObject({ reason: "CANDIDATE_PROVENANCE_MISMATCH" });

    const nullCandidate = candidate(45_200n);
    await expect(
      new SelfMintPreflight({
        allocator: new SequenceAllocator([nullCandidate]),
        discovery: {
          probeFirst: () =>
            Promise.resolve([
              { tag: nullCandidate.tag, record: null, occurrenceCount: 0 },
            ]),
          fetchOccurrences: () => Promise.resolve([]),
          fetchLeafBlock: () => Promise.resolve([]),
        },
        history: CURRENT_HISTORY,
        ownerCommitment,
        domain: DOMAIN,
      }).take(1),
    ).rejects.toMatchObject({ reason: "DISCOVERY_PROTOCOL" });

    const entryCandidate = candidate(45_300n);
    await expect(
      new SelfMintPreflight({
        allocator: new SequenceAllocator([entryCandidate]),
        discovery: {
          probeFirst: () => Promise.resolve([null] as never),
          fetchOccurrences: () => Promise.resolve([]),
          fetchLeafBlock: () => Promise.resolve([]),
        },
        history: CURRENT_HISTORY,
        ownerCommitment,
        domain: DOMAIN,
      }).take(1),
    ).rejects.toMatchObject({ reason: "DISCOVERY_PROTOCOL" });

    const queryMutationCandidate = candidate(45_400n);
    const queryMutationMiss = await recordFor(
      candidate(45_500n),
      ownerCommitment,
    );
    await expect(
      new SelfMintPreflight({
        allocator: new SequenceAllocator([queryMutationCandidate]),
        discovery: {
          probeFirst: (tags) => {
            Reflect.set(tags[0], "asBigInt", 123n);
            return Promise.resolve([
              { tag: tags[0], record: queryMutationMiss, occurrenceCount: 0 },
            ]);
          },
          fetchOccurrences: () => Promise.resolve([]),
          fetchLeafBlock: () => Promise.resolve([]),
        },
        history: CURRENT_HISTORY,
        ownerCommitment,
        domain: DOMAIN,
      }).take(1),
    ).rejects.toMatchObject({ reason: "DISCOVERY_PROTOCOL" });
  });

  it("rejects malformed nested records and oversized response arrays before opening", async () => {
    const valid = candidate(46_000n);
    const ownerCommitment = await owner();
    const source = (rows: unknown[]): DiscoverySource => ({
      probeFirst: () => Promise.resolve(rows as never),
      fetchOccurrences: () => Promise.resolve([]),
      fetchLeafBlock: () => Promise.resolve([]),
    });
    const record = await recordFor(valid, ownerCommitment);
    const malformedRecords: unknown[] = [
      { recordKind: RECORD_KIND_SELF },
      { ...record, layoutVersion: 2 },
      { ...record, recordKind: 9 },
      { ...record, leafIndex: -1 },
      {
        ...record,
        commitmentPrefix: new Uint8Array(COMMITMENT_PREFIX_BYTES - 1),
      },
      { ...record, ephemeralPkX: 1n },
      { ...record, cekWrap: 1n },
      { ...record, ciphertextKept: record.ciphertextKept.slice(1) },
      { ...record, ciphertextKept: [1n, ...record.ciphertextKept.slice(1)] },
    ];
    for (let i = 0; i < malformedRecords.length; i++) {
      const attempt = candidate(46_100n + BigInt(i) * 100n);
      await expect(
        new SelfMintPreflight({
          allocator: new SequenceAllocator([attempt]),
          discovery: source([
            {
              tag: attempt.tag,
              record: malformedRecords[i],
              occurrenceCount: 0,
            },
          ]),
          history: CURRENT_HISTORY,
          ownerCommitment,
          domain: DOMAIN,
        }).take(1),
      ).rejects.toMatchObject({ reason: "DISCOVERY_PROTOCOL" });
    }

    const oversizedCandidate = candidate(47_000n);
    const oversized = Array.from({ length: 6 }, () => ({
      tag: oversizedCandidate.tag,
      record: null,
      occurrenceCount: 0,
    }));
    await expect(
      new SelfMintPreflight({
        allocator: new SequenceAllocator([oversizedCandidate]),
        discovery: source(oversized),
        history: CURRENT_HISTORY,
        ownerCommitment,
        domain: DOMAIN,
      }).take(1),
    ).rejects.toMatchObject({ reason: "DISCOVERY_PROTOCOL" });
  });

  it("recognizes old-key occupancy and fails closed after the candidate cap", async () => {
    const values = Array.from(
      { length: MAX_PREFLIGHT_CANDIDATES },
      (_, index) => candidate(50_000n + BigInt(index) * 100n),
    );
    const ownerCommitment = await owner();
    const records = new Map<string, HowlNoteRecord>();
    for (const value of values) {
      records.set(
        value.tag.toString(),
        await recordFor(value, ownerCommitment, OLD_COMPLIANCE),
      );
    }
    const preflight = new SelfMintPreflight({
      allocator: new SequenceAllocator(values),
      discovery: new FixtureDiscovery(records, null),
      history: ROTATED_HISTORY,
      ownerCommitment,
      domain: DOMAIN,
    });

    await expect(preflight.take(1)).rejects.toMatchObject({
      name: "SelfMintPreflightError",
      reason: "CANDIDATES_EXHAUSTED",
    });
  }, 120_000);

  it("applies the candidate cap per take rather than across the wallet lifetime", async () => {
    const values = Array.from(
      { length: MAX_PREFLIGHT_CANDIDATES + 1 },
      (_, index) => candidate(90_000n + BigInt(index) * 100n),
    );
    const miss = await recordFor(candidate(999_000n), await owner());
    const preflight = new SelfMintPreflight({
      allocator: new SequenceAllocator(values),
      discovery: new FixtureDiscovery(new Map(), miss),
      history: CURRENT_HISTORY,
      ownerCommitment: await owner(),
      domain: DOMAIN,
    });

    for (const expected of values) {
      const [mint] = consume(await preflight.take(1), await owner());
      expect(mint.tag.toString()).toBe(expected.tag.toString());
    }
  });
});
