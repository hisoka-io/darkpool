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
    recipient: { ownerX: 777n, ownerY: 888n },
    amountOutMin: 0n,
    salt: 999n,
  };

  it("SECURITY: Should reject if Intent Params are modified (Hijack Attempt)", async function () {
    const data = await loadFixture(fixture);
    const { uniswapAdaptor, alice } = data;

    // @ts-ignore adaptor intent params
    const intentHash: Fr = await hashUniswapIntent(goodParams);
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
        ),
    ).to.be.reverted;
  });

  it("SECURITY: Should reject if Proof Recipient is not the Adaptor", async function () {
    const data = await loadFixture(fixture);
    const { uniswapAdaptor, alice } = data;

    // @ts-ignore
    const intentHash: Fr = await hashUniswapIntent(goodParams);
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
        ),
    ).to.be.revertedWithCustomError(uniswapAdaptor, "InvalidProofRecipient");
  });

  it("FIX1: rejects swapping an asset other than the withdrawn asset", async function () {
    const data = await loadFixture(fixture);
    const { uniswapAdaptor, alice } = data;
    const mismatch = {
      ...goodParams,
      assetIn: USDC_ADDRESS,
      assetOut: WETH_ADDRESS,
    };
    // @ts-ignore
    const intentHash: Fr = await hashUniswapIntent(mismatch);
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
        ),
    ).to.be.revertedWithCustomError(uniswapAdaptor, "AssetMismatch");
  });

  it("FIX1: rejects a replayed proof after a completed atomic swap", async function () {
    const data = await loadFixture(fixture);
    const { uniswapAdaptor, darkPool, alice } = data;
    // @ts-ignore
    const intentHash: Fr = await hashUniswapIntent(goodParams);
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
      );
    await expect(
      uniswapAdaptor
        .connect(alice)
        .executeSwap(
          proofHex,
          pubHex,
          SwapType.ExactInputSingle,
          encodeEIS(goodParams),
        ),
    ).to.be.revertedWithCustomError(darkPool, "NullifierAlreadySpent");
  });

  it("C-1: blocks a direct withdraw to a contract recipient from a non-recipient caller", async function () {
    const data = await loadFixture(fixture);
    const { darkPool, attacker, uniswapAdaptor } = data;
    // @ts-ignore
    const intentHash: Fr = await hashUniswapIntent(goodParams);
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
