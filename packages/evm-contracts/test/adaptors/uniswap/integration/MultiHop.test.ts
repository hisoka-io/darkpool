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
  DAI_ADDRESS,
  WBTC_ADDRESS,
  SWAP_ROUTER,
} from "../../fixtures";
import { Fr } from "@hisoka/wallets";
import { hashUniswapIntent, SwapType, encodePath } from "@hisoka/adaptors";
import { assert } from "console";

describe("Uniswap Adaptor: Multi-Hop Integration", function () {
  this.timeout(0); // Mainnet Forking

  let ethUsd: number;
  let btcUsd: number;

  before(async function () {
    const prices = await fetchLivePrices();
    ethUsd = prices.ethUsd;
    btcUsd = prices.btcUsd;
  });

  it("should swap WETH -> USDC -> DAI (Exact Input)", async function () {
    const data = await loadFixture(deployUniswapFixture);
    const { uniswapAdaptor, darkPool, alice } = data;
    const setup = await setupAdaptorNote(data, "1.0"); // 1 WETH

    const path = encodePath(
      [WETH_ADDRESS, USDC_ADDRESS, DAI_ADDRESS],
      [3000, 500],
    );
    const params = {
      type: SwapType.ExactInput,
      path,
      recipient: { ownerX: 111n, ownerY: 222n },
      amountOutMin: 0n,
      salt: 333n,
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
        "tuple(bytes path, tuple(uint256 ownerX, uint256 ownerY) recipient, uint256 amountOutMin, uint256 salt)",
      ],
      [
        [
          params.path,
          [params.recipient.ownerX, params.recipient.ownerY],
          params.amountOutMin,
          params.salt,
        ],
      ],
    );

    const tx = await uniswapAdaptor
      .connect(alice)
      .executeSwap(proofHex, pubHex, SwapType.ExactInput, encodedParams);
    const receipt = await tx.wait();

    const log = receipt!.logs
      .map((l) => {
        try {
          return darkPool.interface.parseLog(l as never);
        } catch {
          return null;
        }
      })
      .find((l) => l?.name === "NewPublicMemo");

    assert(log !== null);
    expect(log?.args.asset).to.equal(DAI_ADDRESS);
    const minDaiOutput = Math.floor(ethUsd * 0.5);
    expect(log?.args.value).to.be.gt(
      ethers.parseUnits(minDaiOutput.toString(), 18),
    );

    const adaptorAddr = await uniswapAdaptor.getAddress();
    const dai = await ethers.getContractAt("IERC20", DAI_ADDRESS);
    expect(await dai.balanceOf(adaptorAddr)).to.equal(0n);
  });

  it("should swap WETH -> USDC -> WBTC (Exact Output) with Refund", async function () {
    const data = await loadFixture(deployUniswapFixture);
    const { uniswapAdaptor, darkPool, alice } = data;
    const setup = await setupAdaptorNote(data, "10.0");

    const path = encodePath(
      [WBTC_ADDRESS, USDC_ADDRESS, WETH_ADDRESS],
      [500, 3000],
    );
    const TARGET_WBTC = ethers.parseUnits("0.1", 8);
    const params = {
      type: SwapType.ExactOutput,
      path,
      recipient: { ownerX: 333n, ownerY: 444n },
      amountOut: BigInt(TARGET_WBTC),
      amountInMaximum: BigInt(setup.amount),
      salt: 555n,
    };

    // @ts-ignore
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
        "tuple(bytes path, tuple(uint256 ownerX, uint256 ownerY) recipient, uint256 amountOut, uint256 amountInMaximum, uint256 salt)",
      ],
      [
        [
          params.path,
          [params.recipient.ownerX, params.recipient.ownerY],
          params.amountOut,
          params.amountInMaximum,
          params.salt,
        ],
      ],
    );

    const tx = await uniswapAdaptor
      .connect(alice)
      .executeSwap(proofHex, pubHex, SwapType.ExactOutput, encodedParams);
    const receipt = await tx.wait();

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

    const wbtcLog = logs.find((l) => l?.args.asset === WBTC_ADDRESS);
    expect(wbtcLog?.args.value).to.equal(TARGET_WBTC);

    const estimatedCostEth = (0.1 * btcUsd) / ethUsd;
    const minRefund = 10 - estimatedCostEth * 1.5;
    const wethLog = logs.find((l) => l?.args.asset === WETH_ADDRESS);
    assert(wethLog !== null);
    expect(wethLog?.args.value).to.be.gt(
      ethers.parseEther(minRefund.toFixed(4)),
    );

    const adaptorAddr = await uniswapAdaptor.getAddress();
    expect(await data.weth.allowance(adaptorAddr, SWAP_ROUTER)).to.equal(0n);
    const wbtc = await ethers.getContractAt("IERC20", WBTC_ADDRESS);
    expect(await wbtc.balanceOf(adaptorAddr)).to.equal(0n);
    expect(await data.weth.balanceOf(adaptorAddr)).to.equal(0n);
  });
});
