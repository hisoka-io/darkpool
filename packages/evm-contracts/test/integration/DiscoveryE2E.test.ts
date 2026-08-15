import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { Fr } from "@aztec/foundation/fields";
import {
  discoveryTag,
  publicKey,
  pubkeyOwner,
  recoverEvenY,
  unwrapCek,
  type HowlNoteRecord,
} from "@hisoka/wallets";
import {
  MockRaven,
  indexEvents,
  syncViaDiscovery,
  type ChainNoteEvent,
  type TagCandidate,
} from "@hisoka/howl-e2e";
import { deployDarkPoolFixture } from "../helpers/fixtures";
import { TestWallet } from "../helpers/TestWallet";
import type { DarkPool } from "../../typechain-types";

/**
 * Proves the property the pure-crypto suite cannot: the note a wallet discovers through a private
 * discovery service is the note the CIRCUIT minted and the CHAIN accepted.
 *
 * Every note here is created by a real proof against the deployed verifier. `ScanEngine` runs alongside as
 * the oracle only; it downloads every event, which is the O(pool) shape Howl exists to avoid, so it grades
 * the discovery path and is never the path under test.
 */

/** Reads the chain's own event log and produces exactly what a Raven indexer would consume. */
async function harvestEvents(
  darkPool: DarkPool,
  fromBlock: number,
): Promise<ChainNoteEvent[]> {
  const toFr = (v: bigint | string) => new Fr(BigInt(v));
  const out: ChainNoteEvent[] = [];

  const notes = await darkPool.queryFilter(
    darkPool.filters.NewNote(),
    fromBlock,
  );
  for (const log of notes) {
    out.push({
      kind: "NEW_NOTE",
      leafIndex: Number(log.args.leafIndex),
      commitment: toFr(log.args.commitment),
      ephemeralX: toFr(log.args.ephemeralPK_x),
      packedCiphertext: log.args.packedCiphertext.map((w: string) => toFr(w)),
    });
  }

  const memos = await darkPool.queryFilter(
    darkPool.filters.NewPrivateMemo(),
    fromBlock,
  );
  for (const log of memos) {
    out.push({
      kind: "NEW_MEMO",
      leafIndex: Number(log.args.leafIndex),
      commitment: toFr(log.args.commitment),
      tag: toFr(log.args.tag),
      ephemeralX: toFr(log.args.ephemeralPK_x),
      cekWrap: toFr(log.args.cekWrap),
      packedCiphertext: log.args.packedCiphertext.map((w: string) => toFr(w)),
    });
  }

  return out.sort((a, b) => a.leafIndex - b.leafIndex);
}

describe("Integration: discovery against a real chain and real proofs", function () {
  this.timeout(1_200_000);

  it("discovers exactly the notes the circuit minted, through a bounded tag lookup", async function () {
    const { darkPool, token, alice, bob } = await loadFixture(
      deployDarkPoolFixture,
    );
    const fromBlock = await ethers.provider.getBlockNumber();

    const aliceWallet = await TestWallet.create(alice, darkPool, token);
    const bobWallet = await TestWallet.create(bob, darkPool, token);

    // Real proof, real verifier, real chain. Two self notes for Alice.
    const d1 = await aliceWallet.deposit(ethers.parseEther("100"));
    const d2 = await aliceWallet.deposit(ethers.parseEther("40"));

    // A transfer gives Bob an INCOMING note and Alice a CHANGE note, so both families are covered.
    await bobWallet.syncTree(d1.commitment);
    await bobWallet.syncTree(d2.commitment);
    await aliceWallet.sync();
    const bobAddr = await bobWallet.getReceiveAddress();
    const trf = await aliceWallet.transfer(
      ethers.parseEther("30"),
      bobAddr.inPub,
    );
    await bobWallet.syncTree(trf.memoCommitment);
    await bobWallet.syncTree(trf.changeCommitment);

    // ---- ORACLE: ScanEngine, the O(pool) path. Grades the result, never produces it. ----
    await aliceWallet.sync();
    await bobWallet.sync();
    const oracleBob = bobWallet.getBalance();
    expect(oracleBob).to.equal(ethers.parseEther("30"));

    // ---- UNDER TEST: index the chain's own events, then discover by tag ----
    const raven = new MockRaven();
    indexEvents(raven, await harvestEvents(darkPool, fromBlock));
    raven.resetQueryLog();

    const bobOwner = await pubkeyOwner(publicKey(bobAddr.inKey));
    const candidates: TagCandidate[] = [
      {
        tag: discoveryTag(bobAddr.inPub),
        ownerCommitment: bobOwner,
        cekFor: async (record: HowlNoteRecord) =>
          unwrapCek(
            record.cekWrap,
            bobAddr.inKey,
            recoverEvenY(record.ephemeralPkX.toBigInt()),
          ),
      },
    ];

    const found = await syncViaDiscovery(raven, candidates);

    // The value Bob discovers by tag equals the value the circuit minted and the chain accepted.
    const discovered = found.notes.reduce(
      (sum, n) => sum + n.plaintext[4].toBigInt(),
      0n,
    );
    expect(discovered).to.equal(oracleBob);

    // And the leaf index it carries points at the commitment the pool actually stored.
    const memoLog = (
      await darkPool.queryFilter(darkPool.filters.NewPrivateMemo(), fromBlock)
    )[0];
    expect(found.notes[0].leafIndex).to.equal(Number(memoLog.args.leafIndex));

    // Bounded: one tag, one padded batch, never a scan of the pool. NOTE: rowsRequested tracks the
    // candidate list, which is hand-built here, so it is a sanity bound and NOT evidence of amortization.
    // The amortization claim lives in howl-e2e differential.test.ts, which asserts recovery of all 40.
    expect(raven.queryLog.roundTrips).to.be.at.most(2);
    // The table holds every note in the pool; Bob fetched a bounded slice of it.
    expect(raven.noteCount).to.be.greaterThan(raven.queryLog.rowsRequested);
  });

  it("denies a third party the notes, even holding the whole table", async function () {
    const { darkPool, token, alice, bob, charlie } = await loadFixture(
      deployDarkPoolFixture,
    );
    const fromBlock = await ethers.provider.getBlockNumber();

    const aliceWallet = await TestWallet.create(alice, darkPool, token);
    const bobWallet = await TestWallet.create(bob, darkPool, token);
    const charlieWallet = await TestWallet.create(charlie, darkPool, token);

    const dep = await aliceWallet.deposit(ethers.parseEther("100"));
    await bobWallet.syncTree(dep.commitment);
    await charlieWallet.syncTree(dep.commitment);
    await aliceWallet.sync();

    const bobAddr = await bobWallet.getReceiveAddress();
    const trf = await aliceWallet.transfer(
      ethers.parseEther("30"),
      bobAddr.inPub,
    );
    await bobWallet.syncTree(trf.memoCommitment);
    await bobWallet.syncTree(trf.changeCommitment);
    await charlieWallet.syncTree(trf.memoCommitment);
    await charlieWallet.syncTree(trf.changeCommitment);
    await bobWallet.sync();

    const raven = new MockRaven();
    indexEvents(raven, await harvestEvents(darkPool, fromBlock));

    // ADVERSARY: Charlie holds every row in the table and his own keys. He is entitled to nothing here.
    const charlieAddr = await charlieWallet.getReceiveAddress();
    const charlieOwner = await pubkeyOwner(publicKey(charlieAddr.inKey));
    raven.resetQueryLog();
    const stolen = await syncViaDiscovery(raven, [
      {
        tag: discoveryTag(charlieAddr.inPub),
        ownerCommitment: charlieOwner,
        cekFor: async (record: HowlNoteRecord) =>
          unwrapCek(
            record.cekWrap,
            charlieAddr.inKey,
            recoverEvenY(record.ephemeralPkX.toBigInt()),
          ),
      },
    ]);
    expect(stolen.notes.length).to.equal(0);
    expect(raven.noteCount).to.be.greaterThan(0);

    // ADVERSARY: Charlie probes BOB's tag directly. The row comes back; it is useless without Bob's key.
    raven.resetQueryLog();
    const bobTag = discoveryTag(bobAddr.inPub);
    const probed = await raven.probeFirst([bobTag]);
    expect(probed[0].record).to.not.equal(null);
    const forged = await syncViaDiscovery(raven, [
      {
        tag: bobTag,
        ownerCommitment: charlieOwner,
        cekFor: async (record: HowlNoteRecord) =>
          unwrapCek(
            record.cekWrap,
            charlieAddr.inKey,
            recoverEvenY(record.ephemeralPkX.toBigInt()),
          ),
      },
    ]);
    expect(forged.notes.length).to.equal(0);
    expect(forged.rejected).to.be.greaterThan(0);

    // And Bob, with his own key, opens the very same row.
    const bobOwner = await pubkeyOwner(publicKey(bobAddr.inKey));
    const honest = await syncViaDiscovery(raven, [
      {
        tag: bobTag,
        ownerCommitment: bobOwner,
        cekFor: async (record: HowlNoteRecord) =>
          unwrapCek(
            record.cekWrap,
            bobAddr.inKey,
            recoverEvenY(record.ephemeralPkX.toBigInt()),
          ),
      },
    ]);
    expect(honest.notes.length).to.equal(1);
    expect(honest.notes[0].plaintext[4].toBigInt()).to.equal(
      ethers.parseEther("30"),
    );
  });
});
