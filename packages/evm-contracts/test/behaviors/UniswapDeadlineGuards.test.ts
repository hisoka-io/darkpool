import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture, time } from "@nomicfoundation/hardhat-network-helpers";

// Enforcement tests for the intent deadline. UniswapIntentParity pins the deadline-bound HASH; that proves
// the binding is computed consistently across TS and Solidity, but proves nothing about whether the contract
// actually rejects a stale or over-long deadline, which is the entire point of the change.
//
// Both guards are the first two statements of executeSwap, ahead of the intent hash, the proof-recipient
// check and the DarkPool withdraw, so they are reachable with dummy proof bytes and need no fork.
// ZeroSlippageBound sits inside the handlers, downstream of a real withdraw, so a dummy proof cannot reach it.
// It is covered on the real money path in UniswapAdaptorSwap.test.ts, which also runs in test:fast.
const MAX_INTENT_LIFETIME = 3600;

async function deployAdaptor() {
  const poseidon2 = await (
    await ethers.getContractFactory("Poseidon2")
  ).deploy();
  const dummy = "0x0000000000000000000000000000000000000001";
  const adaptor = await (
    await ethers.getContractFactory("UniswapIntentHarness", {
      libraries: { Poseidon2: await poseidon2.getAddress() },
    })
  ).deploy(dummy, dummy);
  return { adaptor };
}

// publicInputs[1] is read as the proof recipient and [7] as the asset, so the array must be wide enough for
// the call to reach those reads at all. It never should: both deadline guards revert first.
const DUMMY_INPUTS: string[] = Array.from(
  { length: 13 },
  () => ethers.ZeroHash,
);
const DUMMY_PROOF = "0x00";
const DUMMY_PARAMS = ethers.AbiCoder.defaultAbiCoder().encode(
  [
    "tuple(address assetIn,address assetOut,uint24 fee,tuple(uint256 ownerX,uint256 ownerY) recipient,uint256 amountOutMin,uint256 salt)",
  ],
  [
    [
      "0x1111111111111111111111111111111111111111",
      "0x2222222222222222222222222222222222222222",
      3000,
      [111n, 222n],
      1000n,
      42n,
    ],
  ],
);

describe("UniswapAdaptor deadline enforcement", function () {
  it("rejects a deadline that has already passed", async function () {
    const { adaptor } = await loadFixture(deployAdaptor);
    const now = await time.latest();

    await expect(
      adaptor.executeSwap(DUMMY_PROOF, DUMMY_INPUTS, 0, DUMMY_PARAMS, now - 1),
    ).to.be.revertedWithCustomError(adaptor, "IntentExpired");
  });

  it("rejects a deadline beyond MAX_INTENT_LIFETIME", async function () {
    const { adaptor } = await loadFixture(deployAdaptor);
    const now = await time.latest();

    await expect(
      adaptor.executeSwap(
        DUMMY_PROOF,
        DUMMY_INPUTS,
        0,
        DUMMY_PARAMS,
        now + MAX_INTENT_LIFETIME + 60,
      ),
    ).to.be.revertedWithCustomError(adaptor, "DeadlineTooFar");
  });

  // Without this, a captured proof stays executable forever: it is the case the whole change exists to close.
  it("rejects a far-future deadline (the perpetual-option case)", async function () {
    const { adaptor } = await loadFixture(deployAdaptor);
    const now = await time.latest();

    await expect(
      adaptor.executeSwap(
        DUMMY_PROOF,
        DUMMY_INPUTS,
        0,
        DUMMY_PARAMS,
        now + 10 * 365 * 24 * 3600,
      ),
    ).to.be.revertedWithCustomError(adaptor, "DeadlineTooFar");
  });

  // A deadline inside the window must pass BOTH guards and fail later, at the proof-recipient check. That is
  // what proves the guards are bounds rather than a blanket reject.
  it("accepts a deadline inside the window and proceeds past both guards", async function () {
    const { adaptor } = await loadFixture(deployAdaptor);
    const now = await time.latest();

    await expect(
      adaptor.executeSwap(
        DUMMY_PROOF,
        DUMMY_INPUTS,
        0,
        DUMMY_PARAMS,
        now + MAX_INTENT_LIFETIME / 2,
      ),
    ).to.be.revertedWithCustomError(adaptor, "InvalidProofRecipient");
  });

  it("accepts the exact MAX_INTENT_LIFETIME boundary", async function () {
    const { adaptor } = await loadFixture(deployAdaptor);
    const now = await time.latest();

    // The next block advances the timestamp by 1, so now+MAX lands exactly on the boundary when mined.
    await expect(
      adaptor.executeSwap(
        DUMMY_PROOF,
        DUMMY_INPUTS,
        0,
        DUMMY_PARAMS,
        now + MAX_INTENT_LIFETIME,
      ),
    ).to.be.revertedWithCustomError(adaptor, "InvalidProofRecipient");
  });
});
