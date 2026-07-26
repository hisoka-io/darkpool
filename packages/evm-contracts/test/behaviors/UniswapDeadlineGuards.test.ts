import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture, time } from "@nomicfoundation/hardhat-network-helpers";

// Enforcement, not parity: UniswapIntentParity pins the deadline-bound HASH, not whether a stale or over-long deadline is rejected.
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
