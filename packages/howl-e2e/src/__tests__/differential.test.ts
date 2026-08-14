import { describe, expect, it } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import { Point } from "@zk-kit/baby-jubjub";
import {
  deriveCek,
  demEncrypt,
  discoveryTag,
  leaf as computeLeaf,
  NOTE_VERSION,
  publicKey,
  pubkeyOwner,
  unwrapCek,
  wrapCek,
  computePsi,
  recoverEvenY,
  type HowlNoteRecord,
} from "@hisoka/wallets";
import { NoteProcessor } from "@hisoka/wallets/reference";
import { MockRaven } from "../mockRaven.js";
import { indexEvents, type ChainNoteEvent } from "../indexer.js";
import { syncViaDiscovery, type TagCandidate } from "../discoveryClient.js";

const ZERO = new Fr(0n);
const ASSET = new Fr(0xaaaan);
const COMPLIANCE_SK = new Fr(0x1f3n);
const COMPLIANCE_PK: Point<bigint> = publicKey(COMPLIANCE_SK);
const SPEND = new Fr(0x2ab1n);
const hex = (f: Fr) => f.toString();

/** Deterministic even-y scalars so the tags are stable across runs. */
function evenYScalar(seed: bigint): Fr {
  let s = seed;
  for (let i = 0n; i < 512n; i++) {
    const candidate = new Fr(s);
    if (publicKey(candidate)[1] % 2n === 0n) return candidate;
    s += 1n;
  }
  throw new Error("no even-y scalar found");
}

interface Minted {
  event: ChainNoteEvent;
  unprocessed: {
    type: "NEW_NOTE" | "NEW_MEMO";
    blockNumber: number;
    txHash: string;
    args: Record<string, unknown>;
  };
  value: bigint;
  leafIndex: number;
}

async function mintSelf(
  eph: Fr,
  value: bigint,
  leafIndex: number,
): Promise<Minted> {
  const owner = await pubkeyOwner(publicKey(SPEND));
  const cek = deriveCek(eph, COMPLIANCE_PK);
  const psi = await computePsi(cek);
  const fields = [NOTE_VERSION, ASSET, ZERO, ZERO, new Fr(value), owner, ZERO];
  const commitment = await computeLeaf({
    noteVersion: NOTE_VERSION,
    assetId: ASSET,
    noteType: ZERO,
    conditionsHash: ZERO,
    value,
    owner,
    psi,
    parents: ZERO,
  });
  const ct = await demEncrypt(cek, fields);
  const ephPub = publicKey(eph);
  return {
    value,
    leafIndex,
    event: {
      kind: "NEW_NOTE",
      leafIndex,
      commitment,
      ephemeralX: new Fr(ephPub[0]),
      packedCiphertext: ct,
    },
    unprocessed: {
      type: "NEW_NOTE",
      blockNumber: 1,
      txHash: "0x00",
      args: {
        leafIndex: BigInt(leafIndex),
        commitment: hex(commitment),
        ephemeralX: ephPub[0],
        packedCiphertext: ct.map(hex),
      },
    },
  };
}

async function mintIncoming(
  inKey: Fr,
  eph: Fr,
  value: bigint,
  leafIndex: number,
): Promise<Minted> {
  const inPub = publicKey(inKey);
  // Spend authority for a memo is the incoming key (NoteProcessor.processMemo passes match.inKey),
  // so owner binds in_pub_j, not the self-spend key.
  const owner = await pubkeyOwner(inPub);
  const cek = deriveCek(eph, COMPLIANCE_PK);
  const psi = await computePsi(cek);
  const fields = [NOTE_VERSION, ASSET, ZERO, ZERO, new Fr(value), owner, ZERO];
  const commitment = await computeLeaf({
    noteVersion: NOTE_VERSION,
    assetId: ASSET,
    noteType: ZERO,
    conditionsHash: ZERO,
    value,
    owner,
    psi,
    parents: ZERO,
  });
  const ct = await demEncrypt(cek, fields);
  const cekWrap = await wrapCek(cek, eph, inPub);
  const ephPub = publicKey(eph);
  return {
    value,
    leafIndex,
    event: {
      kind: "NEW_MEMO",
      leafIndex,
      commitment,
      tag: discoveryTag(inPub),
      ephemeralX: new Fr(ephPub[0]),
      cekWrap,
      packedCiphertext: ct,
    },
    unprocessed: {
      type: "NEW_MEMO",
      blockNumber: 1,
      txHash: "0x00",
      args: {
        leafIndex: BigInt(leafIndex),
        commitment: hex(commitment),
        ephemeralX: ephPub[0],
        packedCiphertext: ct.map(hex),
        tag: discoveryTag(inPub).toBigInt(),
        cekWrap: cekWrap.toBigInt(),
      },
    },
  };
}

class FixtureRepo {
  constructor(
    private readonly selfTags: Map<string, { eph: Fr; index: number }>,
    private readonly incomingTags: Map<string, { inKey: Fr; index: number }>,
  ) {}
  matchSelfTag(tag: bigint | string) {
    return this.selfTags.get(new Fr(BigInt(tag as bigint)).toString()) ?? null;
  }
  matchIncomingTag(tag: bigint | string) {
    return (
      this.incomingTags.get(new Fr(BigInt(tag as bigint)).toString()) ?? null
    );
  }
  async getSelfSpendScalar() {
    return SPEND;
  }
  async getSelfSpendPub() {
    return publicKey(SPEND);
  }
  recordIncomingMatch() {}
  async ensureSelfLookahead() {
    return false;
  }
  async ensureIncomingLookahead() {
    return false;
  }
  nextSelfEphemeral(): Promise<never> {
    return Promise.reject(new Error("fixture does not mint"));
  }
  nextIncomingAddress(): Promise<never> {
    return Promise.reject(new Error("fixture does not issue"));
  }
  getState(): never {
    throw new Error("not durable");
  }
  async restore() {}
}

describe("differential gate: MockRaven must find exactly what NoteProcessor finds", () => {
  it("agrees on the note set for a mixed self and incoming history", async () => {
    // Widely spaced: evenYScalar walks forward, so adjacent seeds can land on ONE scalar and share a tag.
    const ephs = [1n, 2n, 3n].map((s) => evenYScalar(0x100000n * s));
    const inKey = evenYScalar(0x9000n);
    const memoEphs = [7n, 8n].map((s) => evenYScalar(0x900000n * s));

    const minted: Minted[] = [];
    let leafIndex = 0;
    for (const [i, eph] of ephs.entries()) {
      minted.push(await mintSelf(eph, 100n * BigInt(i + 1), leafIndex++));
    }
    // Two notes under ONE incoming tag: the one-to-many case a single-occurrence design would miss.
    for (const [i, eph] of memoEphs.entries()) {
      minted.push(
        await mintIncoming(inKey, eph, 500n * BigInt(i + 1), leafIndex++),
      );
    }
    // Somebody else's note, under a tag this wallet does not hold. Neither path may claim it.
    minted.push(await mintSelf(evenYScalar(0xdead0000n), 999n, leafIndex++));

    // ---- ORACLE: NoteProcessor, the O(pool) local-filter path. Never the path under test. ----
    const selfTags = new Map(
      ephs.map((eph, index) => [
        discoveryTag(publicKey(eph)).toString(),
        { eph, index },
      ]),
    );
    const incomingTags = new Map([
      [discoveryTag(publicKey(inKey)).toString(), { inKey, index: 0 }],
    ]);
    const processor = new NoteProcessor(
      new FixtureRepo(selfTags, incomingTags) as never,
      COMPLIANCE_PK,
    );
    const oracle: number[] = [];
    for (const m of minted) {
      const note = await processor.process(m.unprocessed as never);
      if (note) oracle.push(m.leafIndex);
    }

    // ---- UNDER TEST: MockRaven, the bounded tag-addressed path. ----
    const raven = new MockRaven();
    indexEvents(
      raven,
      minted.map((m) => m.event),
    );
    raven.resetQueryLog();

    const ownerCommitment = await pubkeyOwner(publicKey(SPEND));
    const candidates: TagCandidate[] = [
      ...ephs.map((eph) => ({
        tag: discoveryTag(publicKey(eph)),
        ownerCommitment,
        cekFor: async () => deriveCek(eph, COMPLIANCE_PK),
      })),
      {
        tag: discoveryTag(publicKey(inKey)),
        ownerCommitment: await pubkeyOwner(publicKey(inKey)),
        cekFor: async (record: HowlNoteRecord) =>
          unwrapCek(
            record.cekWrap,
            inKey,
            recoverEvenY(record.ephemeralPkX.toBigInt()),
          ),
      },
    ];
    const result = await syncViaDiscovery(raven, candidates);

    const found = result.notes.map((n) => n.leafIndex).sort((a, b) => a - b);
    expect(found).toEqual(oracle.sort((a, b) => a - b));
    expect(found).toHaveLength(5);
    // The stranger's note is in the table and was never returned to us.
    expect(found).not.toContain(5);
  });

  it("costs exactly two round trips no matter how deep the history", async () => {
    const inKey = evenYScalar(0x9000n);
    const raven = new MockRaven();
    const events: ChainNoteEvent[] = [];
    for (let i = 0; i < 40; i++) {
      events.push(
        (
          await mintIncoming(
            inKey,
            evenYScalar(0x30000n * BigInt(i + 1)),
            10n,
            i,
          )
        ).event,
      );
    }
    indexEvents(raven, events);
    raven.resetQueryLog();

    const ownerCommitment = await pubkeyOwner(publicKey(SPEND));
    await syncViaDiscovery(raven, [
      {
        tag: discoveryTag(publicKey(inKey)),
        ownerCommitment,
        cekFor: async (record: HowlNoteRecord) =>
          unwrapCek(
            record.cekWrap,
            inKey,
            recoverEvenY(record.ephemeralPkX.toBigInt()),
          ),
      },
    ]);

    // 40 notes under one tag, and still 2 round trips. This is the property a trial-decrypt pool cannot have.
    expect(raven.queryLog.roundTrips).toBe(2);
    expect(raven.queryLog.rowsRequested).toBe(40);
  });
});
