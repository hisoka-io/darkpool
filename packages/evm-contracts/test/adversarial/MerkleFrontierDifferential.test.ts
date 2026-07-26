import { expect } from "chai";
import { ethers } from "hardhat";
import { LeanIMT, toFr } from "@hisoka/wallets";
import {
  bitLength,
  makeRng,
  randomLeaves,
  deployTrio,
  insertAll,
  type MerkleHarness,
} from "../helpers/merkleTree";

// MerkleTreeLib.insert stops the frontier walk once the running index reaches 0; every write above that is
// dead. The mutation that corrupts the tree is breaking BEFORE the write at the `index == 0` level.

const ZERO32 = ethers.ZeroHash;
const DEEP = !!process.env.MERKLE_DEEP;
const SEQUENCES = Number(process.env.FUZZ_SEQUENCES ?? (DEEP ? 700 : 6));

/** Root equality for N inserts says nothing about insert N+1: the frontier is the state that carries. False on an upgraded proxy (stale writes). */
async function expectFrontierEquivalent(
  patched: MerkleHarness,
  reference: MerkleHarness,
  depth: number,
) {
  const next = Number(await patched.getNextLeafIndex());
  expect(await reference.getNextLeafIndex()).to.equal(BigInt(next));
  // A full tree never reaches index 0 inside the loop bound, so it has no levels above the top.
  const topLevel = Math.min(bitLength(next - 1), depth - 1);

  for (let level = 0; level <= topLevel; level++) {
    expect(
      await patched.sideNode(level),
      `frontier mismatch at live level ${level} (leaves=${next})`,
    ).to.equal(await reference.sideNode(level));
  }
  for (let level = topLevel + 1; level < depth; level++) {
    expect(
      await patched.sideNode(level),
      `level ${level} is above the tree top and must never have been written`,
    ).to.equal(ZERO32);
    expect(
      await reference.sideNode(level),
      `reference must carry a dead write at level ${level}`,
    ).to.not.equal(ZERO32);
  }
}

async function expectRootsIdentical(
  patched: MerkleHarness,
  reference: MerkleHarness,
) {
  const a = await patched.getRootHistory();
  const b = await reference.getRootHistory();
  expect(a.length).to.equal(b.length);
  for (let i = 0; i < a.length; i++) {
    expect(a[i], `root diverged at insert #${i + 1}`).to.equal(b[i]);
  }
}

describe("MerkleTreeLib: frontier differential vs the full 32-level walk", function () {
  this.timeout(600_000);

  describe("differential fuzz: root + frontier equivalence", function () {
    for (const depth of [4, 8, 32]) {
      it(`depth ${depth}: ${SEQUENCES} random sequences agree on every root and on the frontier`, async function () {
        const rng = makeRng(BigInt(0xda7a5eed + depth));

        for (let s = 0; s < SEQUENCES; s++) {
          const { patched, reference } = await deployTrio(depth);
          const maxLen = Math.min(2 ** depth, 40);
          const len = 1 + Number(rng() % BigInt(maxLen));
          const leaves = randomLeaves(rng, len);

          await insertAll(patched, leaves);
          await insertAll(reference, leaves);

          await expectRootsIdentical(patched, reference);
          await expectFrontierEquivalent(patched, reference, depth);
        }
      });
    }
  });

  describe("power-of-two boundaries: the write at the index==0 level is live", function () {
    // Leaf 2^k - 1 lands on index 0 at level k and stores the left-subtree root leaf 2^k reads as its sibling.
    const REAL_DEPTH = DEEP ? 8 : 6;

    it(`depth ${REAL_DEPTH}: every 2^k - 1 / 2^k crossing of a real ${2 ** REAL_DEPTH}-leaf history matches the full walk`, async function () {
      const depth = REAL_DEPTH;
      const { patched, reference } = await deployTrio(depth);
      const leaves = randomLeaves(makeRng(0xb0dac0den), 2 ** depth);

      await insertAll(patched, leaves);
      await insertAll(reference, leaves);

      await expectRootsIdentical(patched, reference);

      const history = await patched.getRootHistory();
      const refHistory = await reference.getRootHistory();
      for (let k = 0; k < depth; k++) {
        for (const leafIndex of [2 ** k - 1, 2 ** k]) {
          if (leafIndex >= leaves.length) continue;
          expect(
            history[leafIndex],
            `root diverged at power-of-two crossing leafIndex=${leafIndex} (2^${k})`,
          ).to.equal(refHistory[leafIndex]);
        }
      }
    });

    // The crossing depends only on the frontier at levels 0..k-1 and leafIndex, so both trees are warped there.
    const CROSSINGS = DEEP
      ? Array.from({ length: 31 }, (_, k) => k)
      : [0, 1, 2, 7, 15, 20, 30];

    it(`depth 32: crossings k = ${DEEP ? "0..30 (all)" : CROSSINGS.join(",")} agree with the full walk, and the mutant breaks every one`, async function () {
      const depth = 32;

      for (const k of CROSSINGS) {
        const { patched, reference, mutant } = await deployTrio(depth);
        const start = 2 ** k - 1;
        const leaves = randomLeaves(makeRng(0xc0551n + BigInt(k)), 2);

        for (const h of [patched, reference, mutant]) {
          await h.warpTo(start, k);
          await h.insertMany(leaves);
        }

        const ref = await reference.getRootHistory();
        const pat = await patched.getRootHistory();
        const mut = await mutant.getRootHistory();

        expect(
          pat[0],
          `root diverged AT the index==0 level, leafIndex=2^${k}-1`,
        ).to.equal(ref[0]);
        expect(
          pat[1],
          `root diverged crossing into leafIndex=2^${k}: the left sibling at level ${k} was lost`,
        ).to.equal(ref[1]);
        expect(
          await patched.sideNode(k),
          `the live frontier write at level ${k} did not happen`,
        ).to.equal(await reference.sideNode(k));

        expect(
          await mutant.sideNode(k),
          `mutant unexpectedly wrote level ${k}`,
        ).to.equal(ZERO32);
        expect(
          mut[1],
          `break-before-write did NOT corrupt the 2^${k} crossing: the boundary gate has no teeth`,
        ).to.not.equal(ref[1]);
      }
    });
  });

  describe("live-proxy upgrade: the new walk on old-library storage", function () {
    // An upgraded pool keeps the OLD library's stale non-zero writes above the top: only root parity holds.
    it("stale non-zero dead writes above the top do not change the root across a 2^k crossing", async function () {
      const depth = 32;

      for (const k of [1, 5, 12, 20]) {
        const { patched, reference } = await deployTrio(depth);
        const start = 2 ** k - 1;
        const leaves = randomLeaves(makeRng(0x0dd5107n + BigInt(k)), 2);

        for (const h of [patched, reference]) {
          await h.warpTo(start, depth);
          await h.insertMany(leaves);
        }

        const pat = await patched.getRootHistory();
        const ref = await reference.getRootHistory();
        expect(
          pat[0],
          `upgraded proxy: root diverged at leafIndex=2^${k}-1 on old-library storage`,
        ).to.equal(ref[0]);
        expect(
          pat[1],
          `upgraded proxy: root diverged crossing into leafIndex=2^${k} on old-library storage`,
        ).to.equal(ref[1]);
        expect(
          await patched.getCurrentRoot(),
          `upgraded proxy: latestRoot diverged at k=${k}`,
        ).to.equal(await reference.getCurrentRoot());
      }
    });
  });

  describe("mutation: breaking BEFORE the write must corrupt the tree", function () {
    it("break-before-write diverges from the full walk at the first 2^k crossing", async function () {
      const depth = 8;
      const { reference, mutant } = await deployTrio(depth);
      const leaves = randomLeaves(makeRng(0x4d07a17n), 32);

      await insertAll(reference, leaves);
      await insertAll(mutant, leaves);

      const refHistory = await reference.getRootHistory();
      const mutHistory = await mutant.getRootHistory();

      const firstDivergence = refHistory.findIndex(
        (r, i) => r !== mutHistory[i],
      );
      expect(
        firstDivergence,
        "the mutant produced identical roots: the boundary gate has no teeth",
      ).to.not.equal(-1);
      // Leaf 0 drops its level-0 write, so leaf 1 - the 2^0 crossing - already reads a zero left sibling.
      expect(
        firstDivergence,
        "the mutant must diverge at the first power-of-two crossing",
      ).to.equal(1);
    });
  });

  describe("tri-parity: Solidity frontier == TS LeanIMT", function () {
    it("depth 32: root byte-identical to the TS LeanIMT at every insert", async function () {
      const depth = 32;
      const { patched } = await deployTrio(depth);
      const ts = new LeanIMT(depth);
      const leaves = randomLeaves(makeRng(0x7217a217n), 40);

      await insertAll(patched, leaves);

      const history = await patched.getRootHistory();
      for (let i = 0; i < leaves.length; i++) {
        await ts.insert(toFr(BigInt(leaves[i])));
        expect(
          history[i],
          `Solidity/TS LeanIMT root mismatch after insert #${i + 1}`,
        ).to.equal(ts.getRoot().toString());
      }
    });
  });
});
