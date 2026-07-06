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
import { Fr, toFr } from "@hisoka/wallets";
import { hashUniswapIntent, SwapType, encodePath } from "@hisoka/adaptors";
import { RelayerMulticall__factory } from "../../../../typechain-types";

describe("Relayer Safe Settlement: Integration", function () {
  this.timeout(0); // Mainnet Forking

  it("should process Payment but shield Relayer from failed Swap", async function () {
    const data = await loadFixture(deployUniswapFixture);
    const { uniswapAdaptor, darkPool, weth, deployer } = data;

    const RelayerMulticallFactory = (await ethers.getContractFactory(
      "RelayerMulticall",
    )) as unknown as RelayerMulticall__factory;
    const relayerMulticall = await RelayerMulticallFactory.deploy();

    const relayer = deployer;

    const paymentSetup = await setupAdaptorNote(data, "1.0");
    const paymentProof = await buildAdaptorWithdraw({
      built: paymentSetup.built,
      spendScalar: paymentSetup.spendScalar,
      tree: paymentSetup.tree,
      amount: paymentSetup.amount,
      recipient: relayer.address,
      intentHash: toFr(0n),
    });

    const swapSetup = await setupAdaptorNote(data, "2.0");
    const path = encodePath([WETH_ADDRESS, USDC_ADDRESS], [500]);
    const params = {
      type: SwapType.ExactInput,
      path,
      recipient: { ownerX: 111n, ownerY: 222n },
      amountOutMin: ethers.parseUnits("1000000", 6),
      salt: 333n,
    };
    // @ts-ignore adaptor intent params
    const intentHash: Fr = await hashUniswapIntent(params);
    const swapProof = await buildAdaptorWithdraw({
      built: swapSetup.built,
      spendScalar: swapSetup.spendScalar,
      tree: swapSetup.tree,
      amount: swapSetup.amount,
      recipient: await uniswapAdaptor.getAddress(),
      intentHash,
    });

    const withdrawData = darkPool.interface.encodeFunctionData("withdraw", [
      paymentProof.proofHex,
      paymentProof.pubHex,
    ]);

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

    const swapData = uniswapAdaptor.interface.encodeFunctionData(
      "executeSwap",
      [
        swapProof.proofHex,
        swapProof.pubHex,
        SwapType.ExactInput,
        encodedParams,
      ],
    );

    const calls = [
      {
        target: await darkPool.getAddress(),
        data: withdrawData,
        value: 0n,
        requireSuccess: true,
      },
      {
        target: await uniswapAdaptor.getAddress(),
        data: swapData,
        value: 0n,
        requireSuccess: false,
      },
    ];

    const relayerBalanceBefore = await weth.balanceOf(relayer.address);

    const tx = await relayerMulticall.connect(relayer).multicall(calls, {
      maxFeePerGas: ethers.parseUnits("200", "gwei"),
      maxPriorityFeePerGas: ethers.parseUnits("5", "gwei"),
    });
    const receipt = await tx.wait();

    const executedEvents = await relayerMulticall.queryFilter(
      relayerMulticall.filters.CallExecuted(),
      receipt?.blockNumber,
    );
    const failedEvents = await relayerMulticall.queryFilter(
      relayerMulticall.filters.CallFailed(),
      receipt?.blockNumber,
    );

    expect(executedEvents.length).to.be.gte(2);
    expect(failedEvents.length).to.equal(1);
    expect(executedEvents[0].args.success).to.equal(true);
    expect(executedEvents[1].args.success).to.equal(false);

    const relayerBalanceAfter = await weth.balanceOf(relayer.address);
    expect(relayerBalanceAfter).to.equal(
      relayerBalanceBefore + ethers.parseEther("1.0"),
    );
  });
});
