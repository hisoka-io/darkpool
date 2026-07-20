import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import {
  deployUniswapFixture,
  setupAdaptorNote,
  buildAdaptorWithdraw,
  WETH_ADDRESS,
  USDC_ADDRESS,
} from "../../fixtures";
import { Fr } from "@hisoka/wallets";
import { hashUniswapIntent, SwapType } from "@hisoka/adaptors";
import { publicKey } from "@hisoka/wallets";

// Within MAX_INTENT_LIFETIME (1h) of the current block, so executeSwap accepts it.
const swapDeadline = async () =>
  BigInt((await ethers.provider.getBlock("latest"))!.timestamp) + 600n;

const EIS_TUPLE =
  "tuple(address assetIn, address assetOut, uint24 fee, tuple(uint256 ownerX, uint256 ownerY) recipient, uint256 amountOutMin, uint256 salt)";

function encodeEIS(p: {
  assetIn: string;
  assetOut: string;
  fee: number;
  recipient: { ownerX: bigint; ownerY: bigint };
  amountOutMin: bigint;
  salt: bigint;
}) {
  return new ethers.AbiCoder().encode(
    [EIS_TUPLE],
    [
      [
        p.assetIn,
        p.assetOut,
        p.fee,
        [p.recipient.ownerX, p.recipient.ownerY],
        p.amountOutMin,
        p.salt,
      ],
    ],
  );
}

// publicTransfer validates the escrow destination is on-curve. A placeholder point would be
// unclaimable in production, so these fixtures use real derived keys.
const OWNER = publicKey(new Fr(0xe55en));

describe("Uniswap Adaptor: Security & Validation", function () {
  this.timeout(0); // Forking

  async function fixture() {
    const data = await deployUniswapFixture();
    const note = await setupAdaptorNote(data);
    return { ...data, ...note };
  }

  const goodParams = {
    type: SwapType.ExactInputSingle,
    assetIn: WETH_ADDRESS,
    assetOut: USDC_ADDRESS,
    fee: 3000,
    recipient: { ownerX: OWNER[0], ownerY: OWNER[1] },
    amountOutMin: 1n,
    salt: 999n,
  };

  it("SECURITY: Should reject if Intent Params are modified (Hijack Attempt)", async function () {
    const deadline = await swapDeadline();
    const data = await loadFixture(fixture);
    const { uniswapAdaptor, alice } = data;

    // @ts-ignore adaptor intent params
    const intentHash: Fr = await hashUniswapIntent(goodParams, deadline);
    const { proofHex, pubHex } = await buildAdaptorWithdraw({
      built: data.built,
      spendScalar: data.spendScalar,
      tree: data.tree,
      amount: data.amount,
      recipient: await uniswapAdaptor.getAddress(),
      intentHash,
    });

    // Attacker swaps assetOut to DAI; the on-chain intent hash no longer matches the proof.
    const DAI_ADDRESS = "0x6B175474E89094C44Da98b954EedeAC495271d0F";
    const hijacked = { ...goodParams, assetOut: DAI_ADDRESS };

    await expect(
      uniswapAdaptor
        .connect(alice)
        .executeSwap(
          proofHex,
          pubHex,
          SwapType.ExactInputSingle,
          encodeEIS(hijacked),
          deadline,
        ),
    ).to.be.reverted;
  });

  it("SECURITY: Should reject if Proof Recipient is not the Adaptor", async function () {
    const deadline = await swapDeadline();
    const data = await loadFixture(fixture);
    const { uniswapAdaptor, alice } = data;

    // @ts-ignore
    const intentHash: Fr = await hashUniswapIntent(goodParams, deadline);
    const { proofHex, pubHex } = await buildAdaptorWithdraw({
      built: data.built,
      spendScalar: data.spendScalar,
      tree: data.tree,
      amount: data.amount,
      recipient: alice.address, // proof withdraws to Alice, not the adaptor
      intentHash,
    });

    await expect(
      uniswapAdaptor
        .connect(alice)
        .executeSwap(
          proofHex,
          pubHex,
          SwapType.ExactInputSingle,
          encodeEIS(goodParams),
          deadline,
        ),
    ).to.be.revertedWithCustomError(uniswapAdaptor, "InvalidProofRecipient");
  });

  it("FIX1: rejects swapping an asset other than the withdrawn asset", async function () {
    const deadline = await swapDeadline();
    const data = await loadFixture(fixture);
    const { uniswapAdaptor, alice } = data;
    const mismatch = {
      ...goodParams,
      assetIn: USDC_ADDRESS,
      assetOut: WETH_ADDRESS,
    };
    // @ts-ignore
    const intentHash: Fr = await hashUniswapIntent(mismatch, deadline);
    const { proofHex, pubHex } = await buildAdaptorWithdraw({
      built: data.built,
      spendScalar: data.spendScalar,
      tree: data.tree,
      amount: data.amount,
      recipient: await uniswapAdaptor.getAddress(),
      intentHash,
    });
    await expect(
      uniswapAdaptor
        .connect(alice)
        .executeSwap(
          proofHex,
          pubHex,
          SwapType.ExactInputSingle,
          encodeEIS(mismatch),
          deadline,
        ),
    ).to.be.revertedWithCustomError(uniswapAdaptor, "AssetMismatch");
  });

  it("FIX1: rejects a replayed proof after a completed atomic swap", async function () {
    const deadline = await swapDeadline();
    const data = await loadFixture(fixture);
    const { uniswapAdaptor, darkPool, alice } = data;
    // @ts-ignore
    const intentHash: Fr = await hashUniswapIntent(goodParams, deadline);
    const { proofHex, pubHex } = await buildAdaptorWithdraw({
      built: data.built,
      spendScalar: data.spendScalar,
      tree: data.tree,
      amount: data.amount,
      recipient: await uniswapAdaptor.getAddress(),
      intentHash,
    });
    await uniswapAdaptor
      .connect(alice)
      .executeSwap(
        proofHex,
        pubHex,
        SwapType.ExactInputSingle,
        encodeEIS(goodParams),
        deadline,
      );
    await expect(
      uniswapAdaptor
        .connect(alice)
        .executeSwap(
          proofHex,
          pubHex,
          SwapType.ExactInputSingle,
          encodeEIS(goodParams),
          deadline,
        ),
    ).to.be.revertedWithCustomError(darkPool, "NullifierAlreadySpent");
  });

  it("C-1: blocks a direct withdraw to a contract recipient from a non-recipient caller", async function () {
    const deadline = await swapDeadline();
    const data = await loadFixture(fixture);
    const { darkPool, attacker, uniswapAdaptor } = data;
    // @ts-ignore
    const intentHash: Fr = await hashUniswapIntent(goodParams, deadline);
    const { proofHex, pubHex } = await buildAdaptorWithdraw({
      built: data.built,
      spendScalar: data.spendScalar,
      tree: data.tree,
      amount: data.amount,
      recipient: await uniswapAdaptor.getAddress(),
      intentHash,
    });
    await expect(
      darkPool.connect(attacker).withdraw(proofHex, pubHex),
    ).to.be.revertedWithCustomError(darkPool, "OnlyRecipientMayPull");
  });
});
