import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import {
  deployUniswapFixture,
  setupAdaptorNote,
  buildAdaptorWithdraw,
  fetchLivePrices,
  WETH_ADDRESS,
  USDC_ADDRESS,
  SWAP_ROUTER,
} from "../../fixtures";
import { Fr } from "@hisoka/wallets";
import { hashUniswapIntent, SwapType } from "@hisoka/adaptors";

describe("Uniswap Adaptor: Single Hop Integration", function () {
  this.timeout(0);

  let ethUsd: number;

  before(async function () {
    const prices = await fetchLivePrices();
    ethUsd = prices.ethUsd;
  });

  it("should execute ExactOutputSingle and REFUND excess input", async function () {
    const data = await loadFixture(deployUniswapFixture);
    const { uniswapAdaptor, darkPool, alice } = data;
    const setup = await setupAdaptorNote(data, "10"); // 10 WETH

    const TARGET_USDC = ethers.parseUnits("2000", 6);

    const params = {
      type: SwapType.ExactOutputSingle,
      assetIn: WETH_ADDRESS,
      assetOut: USDC_ADDRESS,
      fee: 3000,
      recipient: { ownerX: 888n, ownerY: 999n, claimerOwner: 1000n },
      amountOut: BigInt(TARGET_USDC),
      amountInMaximum: BigInt(setup.amount),
    };

    // @ts-ignore adaptor intent params
    const intentHash: Fr = await hashUniswapIntent(params);
    const { proofHex, pubHex } = await buildAdaptorWithdraw({
      built: setup.built,
      spendScalar: setup.spendScalar,
      tree: setup.tree,
      amount: setup.amount,
      recipient: await uniswapAdaptor.getAddress(),
      intentHash,
    });

    const encodedParams = new ethers.AbiCoder().encode(
      [
        "tuple(address assetIn, address assetOut, uint24 fee, tuple(uint256 ownerX, uint256 ownerY, uint256 claimerOwner) recipient, uint256 amountOut, uint256 amountInMaximum)",
      ],
      [
        [
          params.assetIn,
          params.assetOut,
          params.fee,
          [
            params.recipient.ownerX,
            params.recipient.ownerY,
            params.recipient.claimerOwner,
          ],
          params.amountOut,
          params.amountInMaximum,
        ],
      ],
    );

    const tx = await uniswapAdaptor
      .connect(alice)
      .executeSwap(proofHex, pubHex, SwapType.ExactOutputSingle, encodedParams);
    const receipt = await tx.wait();

    // Expect two NewPublicMemo events: target output + refund.
    const logs = receipt!.logs
      .map((l) => {
        try {
          return darkPool.interface.parseLog(l as never);
        } catch {
          return null;
        }
      })
      .filter((l) => l?.name === "NewPublicMemo");

    expect(logs.length).to.equal(2);

    const usdcLog = logs.find((l) => l?.args.asset === USDC_ADDRESS);
    expect(usdcLog).to.not.equal(undefined);
    expect(usdcLog?.args.value).to.equal(TARGET_USDC);

    const wethLog = logs.find((l) => l?.args.asset === WETH_ADDRESS);
    expect(wethLog).to.not.equal(undefined);
    const estimatedCost = 2000 / ethUsd;
    const minRefund = 10 - estimatedCost * 1.5;
    expect(wethLog?.args.value).to.be.gt(
      ethers.parseEther(minRefund.toFixed(4)),
    );

    const adaptorAddr = await uniswapAdaptor.getAddress();
    expect(await data.weth.allowance(adaptorAddr, SWAP_ROUTER)).to.equal(0n);
    expect(await data.usdc.balanceOf(adaptorAddr)).to.equal(0n);
    expect(await data.weth.balanceOf(adaptorAddr)).to.equal(0n);
  });
});
