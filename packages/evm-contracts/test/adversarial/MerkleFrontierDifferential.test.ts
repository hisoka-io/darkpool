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

// The frontier walk in MerkleTreeLib.insert stops once the running index reaches 0. Every level above that is a
// rewrite of an unchanged node, and every such write except the first is overwritten by a later insert before it
// is ever read. This suite proves the stop changes no observable state: it differentially compares the shipped
// library against FullWalkMerkleTree (the unconditional 32-level walk it replaced) on roots AND on the frontier
// itself, and it pins the one mutation that would silently corrupt the tree - breaking BEFORE the write at the
// `index == 0` level, which drops the completed left-subtree root that leaf 2^L reads as its left sibling.
//
// MERKLE_DEEP=1 widens the fuzz and walks all 31 crossings; the always-on core keeps the same properties on a
// smaller sample so the single-process fast suite stays inside its memory budget.

const ZERO32 = ethers.ZeroHash;
const DEEP = !!process.env.MERKLE_DEEP;
const SEQUENCES = Number(process.env.FUZZ_SEQUENCES ?? (DEEP ? 700 : 6));

/**
 * The frontier - not the root - is the state that carries into the next insert, so equality of roots for N
 * inserts says nothing about insert N+1. At or below the tree top the two walks must agree slot for slot;
 * above it the shipped library must have written nothing at all while the reference wrote the root into every
 * remaining level. Asserting the second half is what proves the skipped writes were the dead ones.
 *
 * Only valid for a tree built entirely by the shipped library. An upgraded proxy carries stale non-zero dead
 * writes above the top from the old library, so the zero-above-top half is FALSE there - see the live-proxy
 * upgrade case below, which asserts root parity only.
 */
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
    // Depth 32 is production; the small depths force the tree top to be crossed many times per sequence.
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
    // Leaf 2^k - 1 reaches index 0 at level k and stores the completed left-subtree root; leaf 2^k shifts to
    // index 1 at level k and reads that exact slot as its left sibling. Skipping the write corrupts the tree
    // here and nowhere earlier, which is why every crossing is walked one leaf at a time.
    // A genuine full history (no warping) across every crossing the tree can hold. Each insert runs Poseidon2
    // under hardhat's tracing EVM, which is what drives this suite's memory, so the always-on tree is depth 6
    // (64 leaves) and MERKLE_DEEP widens it to depth 8. The deep crossings are covered exhaustively - and at
    // production depth 32 - by the warped case below, so nothing is lost by keeping this one small.
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

    // Reaching leafIndex 2^20 by inserting is infeasible, but the crossing only depends on the frontier at
    // levels 0..k-1 and on leafIndex - never on how the tree got there. So both trees are warped to an
    // IDENTICAL frontier at leafIndex 2^k - 1 and then driven across the boundary one leaf at a time. Leaf
    // 2^k - 1 hashes up k times and lands on index 0 at level k; leaf 2^k shifts to index 1 at level k and
    // reads that slot back. Levels above k are never read by either leaf, so seeding them is unnecessary.
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

        // Same inputs, break moved above the write: the crossing leaf must now read a zero left sibling.
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
    // A pool upgraded to this library keeps the frontier the OLD library left behind: every level above the
    // tree top holds a stale non-zero dead write, not a zero. That shape is unreachable by building a tree
    // with the new code, so nothing else in this suite covers it. Root parity is the property that matters;
    // frontier-is-zero-above-top is deliberately NOT asserted here because it is false in this shape.
    it("stale non-zero dead writes above the top do not change the root across a 2^k crossing", async function () {
      const depth = 32;

      for (const k of [1, 5, 12, 20]) {
        const { patched, reference } = await deployTrio(depth);
        const start = 2 ** k - 1;
        const leaves = randomLeaves(makeRng(0x0dd5107n + BigInt(k)), 2);

        // filledLevels = 32 is the pre-upgrade shape: the old walk wrote every level on every insert.
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
    // A gate that cannot fail is not a gate. BreakBeforeWriteMerkleTree is the shipped loop with the break
    // moved above the frontier write; it must diverge the first time the tree crosses a power of two.
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
