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
import { newSeededTree } from "../../../helpers/fixtures";
import { Fr, toFr } from "@hisoka/wallets";
import { hashUniswapIntent, SwapType, encodePath } from "@hisoka/adaptors";
import { publicKey } from "@hisoka/wallets";

const swapDeadline = async () =>
  BigInt((await ethers.provider.getBlock("latest"))!.timestamp) + 600n;

const OWNER = publicKey(new Fr(0xd44dn));

describe("Relayer Safe Settlement: Integration", function () {
  this.timeout(0);

  it("should process Payment but shield Relayer from failed Swap", async function () {
    const data = await loadFixture(deployUniswapFixture);
    const { uniswapAdaptor, darkPool, weth, deployer } = data;

    const relayer = deployer;

    // Distinct ephemeral seeds: one seed at one leaf index yields one nullifier, and two notes sharing it
    // would make the second spend fail as a double spend instead of on the property under test.
    const paymentSetup = await setupAdaptorNote(data, "1.0", 11n);
    const swapSetup = await setupAdaptorNote(data, "2.0", 22n);

    const { chainId } = await ethers.provider.getNetwork();
    const tree = await newSeededTree(chainId);
    await tree.insert(paymentSetup.built.commitment);
    await tree.insert(swapSetup.built.commitment);

    const paymentProof = await buildAdaptorWithdraw({
      built: paymentSetup.built,
      spendScalar: paymentSetup.spendScalar,
      tree,
      amount: paymentSetup.amount,
      recipient: relayer.address,
      intentHash: toFr(0n),
      noteIndex: 1,
    });

    const path = encodePath([WETH_ADDRESS, USDC_ADDRESS], [500]);
    const params = {
      type: SwapType.ExactInput,
      path,
      recipient: { ownerX: OWNER[0], ownerY: OWNER[1] },
      amountOutMin: ethers.parseUnits("1000000", 6),
      salt: 333n,
    };
    const deadline = await swapDeadline();
    // @ts-ignore adaptor intent params
    const intentHash: Fr = await hashUniswapIntent(params, deadline);
    const swapProof = await buildAdaptorWithdraw({
      built: swapSetup.built,
      spendScalar: swapSetup.spendScalar,
      tree,
      amount: swapSetup.amount,
      recipient: await uniswapAdaptor.getAddress(),
      intentHash,
      noteIndex: 2,
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

    const relayerBalanceBefore = await weth.balanceOf(relayer.address);

    await (
      await darkPool
        .connect(relayer)
        .withdraw(paymentProof.proofHex, paymentProof.pubHex)
    ).wait();

    const relayerBalanceAfterPayment = await weth.balanceOf(relayer.address);
    expect(relayerBalanceAfterPayment).to.equal(
      relayerBalanceBefore + ethers.parseEther("1.0"),
    );

    // amountOutMin is unreachable, so the router's slippage guard must be what trips. Pinning it is what
    // separates a real swap failure from the note being unspendable for an unrelated reason.
    await expect(
      uniswapAdaptor
        .connect(relayer)
        .executeSwap(
          swapProof.proofHex,
          swapProof.pubHex,
          SwapType.ExactInput,
          encodedParams,
          deadline,
        ),
    ).to.be.revertedWith("Too little received");

    expect(await weth.balanceOf(relayer.address)).to.equal(
      relayerBalanceAfterPayment,
    );
    expect(await darkPool.isNullifierSpent(swapProof.pubHex[5])).to.equal(
      false,
    );
  });
});
