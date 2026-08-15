import { describe, expect, it } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import {
  deriveCek,
  demEncrypt,
  discoveryTag,
  leaf as computeLeaf,
  NOTE_VERSION,
  publicKey,
  pubkeyOwner,
  computePsi,
  decodeHowlNoteRecord,
  encodeHowlNoteRecord,
  RECORD_KIND_SELF,
} from "@hisoka/wallets";
import { MockRaven } from "../mockRaven.js";
import { indexEvents, toRecord, type ChainNoteEvent } from "../indexer.js";
import { syncViaDiscovery, type TagCandidate } from "../discoveryClient.js";

const ZERO = new Fr(0n);
const ASSET = new Fr(0xaaaan);
const COMPLIANCE_PK = publicKey(new Fr(0x1f3n));

function evenY(seed: bigint): Fr {
  let s = seed;
  while (publicKey(new Fr(s))[1] % 2n !== 0n) s += 1n;
  return new Fr(s);
}

async function mint(
  eph: Fr,
  owner: Fr,
  value: bigint,
  leafIndex: number,
): Promise<ChainNoteEvent> {
  const cek = deriveCek(eph, COMPLIANCE_PK);
  const psi = await computePsi(cek);
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
  const ct = await demEncrypt(cek, [
    NOTE_VERSION,
    ASSET,
    ZERO,
    ZERO,
    new Fr(value),
    owner,
    ZERO,
  ]);
  return {
    kind: "NEW_NOTE",
    leafIndex,
    commitment,
    ephemeralX: new Fr(publicKey(eph)[0]),
    packedCiphertext: ct,
  };
}

describe("the property that separates Howl from a trial-decrypt pool", () => {
  it("costs the same number of queries whether the pool holds 10 notes or 1000", async () => {
    const mine = [evenY(0x1000n), evenY(0x200000n)];
    const owner = await pubkeyOwner(publicKey(new Fr(0x2ab1n)));

    async function syncAgainstPoolOf(strangers: number) {
      const raven = new MockRaven();
      const events: ChainNoteEvent[] = [];
      let leafIndex = 0;
      for (const eph of mine) {
        events.push(await mint(eph, owner, 100n, leafIndex++));
      }
      // Everybody else's notes. A trial-decrypt wallet pays for every one of these.
      for (let i = 0; i < strangers; i++) {
        events.push(
          await mint(
            evenY(0x900000n * BigInt(i + 1)),
            new Fr(0xbeefn),
            1n,
            leafIndex++,
          ),
        );
      }
      indexEvents(raven, events);
      raven.resetQueryLog();

      const candidates: TagCandidate[] = mine.map((eph) => ({
        tag: discoveryTag(publicKey(eph)),
        ownerCommitment: owner,
        cekFor: async () => deriveCek(eph, COMPLIANCE_PK),
      }));
      const result = await syncViaDiscovery(raven, candidates);
      return {
        log: raven.queryLog,
        found: result.notes.length,
        pool: raven.noteCount,
      };
    }

    const small = await syncAgainstPoolOf(8);
    const large = await syncAgainstPoolOf(200);

    expect(small.found).toBe(2);
    expect(large.found).toBe(2);
    // The pool grew 20x. The cost of finding my own notes did not move at all.
    expect(large.pool).toBeGreaterThan(small.pool * 10);
    expect(large.log.rowsRequested).toBe(small.log.rowsRequested);
    expect(large.log.roundTrips).toBe(small.log.roundTrips);
  });

  it("emits a byte-uniform row shape for every self note, and never the owner in the clear", async () => {
    const owner = await pubkeyOwner(publicKey(new Fr(0x2ab1n)));
    const raven = new MockRaven();
    const events: ChainNoteEvent[] = [];
    for (let i = 0; i < 6; i++) {
      // Three notes are one wallet's, three are strangers'. Same owner is NOT observable.
      const isMine = i % 2 === 0;
      events.push(
        await mint(
          evenY(0x400000n * BigInt(i + 1)),
          isMine ? owner : new Fr(0xbeefn + BigInt(i)),
          10n,
          i,
        ),
      );
    }
    indexEvents(raven, events);

    // Every self row is byte-identical in shape: same length, same kind, zeroed eph and cekWrap.
    const shapes = events.map((e) => {
      const cell = encodeHowlNoteRecord(toRecord(e));
      const back = decodeHowlNoteRecord(cell);
      return {
        len: cell.length,
        kind: back.recordKind,
        ephZero: back.ephemeralPkX.isZero(),
        wrapZero: back.cekWrap.isZero(),
        words: back.ciphertextKept.length,
      };
    });
    for (const s of shapes) {
      expect(s).toEqual({
        len: 256,
        kind: RECORD_KIND_SELF,
        ephZero: true,
        wrapZero: true,
        words: 5,
      });
    }

    // The owner field never appears in the clear: it is the word the strip REMOVES, and what remains is
    // ciphertext under a key the observer does not hold.
    const raw = encodeHowlNoteRecord(toRecord(events[0]));
    expect(raw.includes(owner.toBuffer()[31])).toBeTypeOf("boolean");
    const ownerHex = owner.toString().slice(2);
    expect(Buffer.from(raw).toString("hex")).not.toContain(ownerHex);
  });

  // MOCK DIVERGENCE, stated so nobody reads this as faithful: a real cuckoo probe returns a ROW on a miss,
  // which is what makes a hit indistinguishable from a miss on the wire. MockRaven returns null instead, so
  // this can only assert that both probes cost the SAME, not that they are indistinguishable. Closing that
  // gap needs miss-row support in the mock.
  it("charges the same for a present tag and an absent one", async () => {
    const raven = new MockRaven();
    const owner = await pubkeyOwner(publicKey(new Fr(0x2ab1n)));
    const eph = evenY(0x1000n);
    indexEvents(raven, [await mint(eph, owner, 100n, 0)]);
    raven.resetQueryLog();

    const realTag = discoveryTag(publicKey(eph));
    const absentTag = discoveryTag(publicKey(evenY(0xabcdef00n)));
    const results = await raven.probeFirst([realTag, absentTag]);

    // Both probes cost the same. The design's privacy comes from the PIR layer; the SHAPE must not leak.
    expect(raven.queryLog.rowsRequested).toBe(2);
    expect(results).toHaveLength(2);
    expect(results[0].record).not.toBeNull();
    expect(results[1].occurrenceCount).toBe(0);
  });
});
