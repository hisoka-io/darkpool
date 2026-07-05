import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import {
  deployUniswapFixture,
  WETH_ADDRESS,
  USDC_ADDRESS,
  WBTC_ADDRESS,
} from "../../fixtures";
import {
  UniswapSwapParams,
  SwapType,
  hashUniswapIntent,
} from "@hisoka/adaptors";
import { addressToFr, publicKey, Fr } from "@hisoka/wallets";
import { ContractTransactionReceipt } from "ethers";
import { Point } from "@zk-kit/baby-jubjub";
import { DarkPool, IERC20, UniswapAdaptor } from "../../../../typechain-types";
import { TestWallet } from "../../../helpers/TestWallet";

class TraderAgent {
  private claimIdx = 0n;

  constructor(
    public wallet: TestWallet,
    public adaptor: UniswapAdaptor,
    public darkPool: DarkPool,
  ) {}

  get address() {
    return this.wallet.signer.address;
  }

  async swap(
    assetIn: string,
    assetOut: string,
    amountIn: bigint,
    fee: number = 3000,
  ) {
    // The swap output is a public memo owned by a fresh claim key the trader controls.
    const recipientSk = await this.wallet.account.getIncomingKey(
      this.claimIdx++,
    );
    const recipientPk = publicKey(recipientSk);

    const params: UniswapSwapParams = {
      type: SwapType.ExactInputSingle,
      assetIn,
      assetOut,
      fee,
      amountOutMin: 0n,
      recipient: {
        ownerX: recipientPk[0],
        ownerY: recipientPk[1],
        claimerOwner: 0n,
      },
    };

    const intentHash = await hashUniswapIntent(params);

    const proof = await this.wallet.withdraw(amountIn, {
      asset: assetIn,
      recipient: await this.adaptor.getAddress(),
      intentHash: new Fr(BigInt(intentHash.toString())),
    });

    const encodedParams = new ethers.AbiCoder().encode(
      [
        "tuple(address assetIn, address assetOut, uint24 fee, tuple(uint256 ownerX, uint256 ownerY, uint256 claimerOwner) recipient, uint256 amountOutMin)",
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
          params.amountOutMin,
        ],
      ],
    );

    const proofHex = "0x" + Buffer.from(proof.proof).toString("hex");
    const pubHex = proof.publicInputs.map(
      (i) => "0x" + BigInt(i).toString(16).padStart(64, "0"),
    );

    const tx = await this.adaptor
      .connect(this.wallet.signer as never)
      .executeSwap(proofHex, pubHex, SwapType.ExactInputSingle, encodedParams);
    const receipt = await tx.wait();

    await this.wallet.sync();

    return this.scanAndClaim(receipt, recipientSk, recipientPk);
  }

  private async scanAndClaim(
    receipt: ContractTransactionReceipt | null,
    recipientSk: Fr,
    recipientPk: Point<bigint>,
  ) {
    const logs = receipt!.logs
      .map((l) => {
        try {
          return this.darkPool.interface.parseLog(l as never);
        } catch {
          return null;
        }
      })
      .filter((l) => l?.name === "NewPublicMemo");

    const results: { asset: string; amount: bigint }[] = [];
    for (const log of logs) {
      const args = log!.args;
      // The public memo event carries no owner fields; the trader supplies its own claim pubkey.
      await this.wallet.claimPublic(
        {
          memoId: args.memoId,
          ownerX: recipientPk[0],
          ownerY: recipientPk[1],
          asset: args.asset,
          value: args.value,
          timelock: args.timelock,
          salt: args.salt,
        },
        recipientSk,
      );
      results.push({ asset: args.asset, amount: args.value });
    }
    await this.wallet.sync();
    return results;
  }
}

describe("Simulation: The DarkPool Trader (Multi-User DeFi)", function () {
  this.timeout(0); // Mainnet Fork

  it("should execute a complex economy: Swap -> Transfer -> Swap -> Withdraw", async function () {
    const {
      darkPool,
      uniswapAdaptor,
      weth,
      alice,
      attacker: bob,
      fromBlock,
    } = await loadFixture(deployUniswapFixture);

    const wAlice = await TestWallet.create(
      alice,
      darkPool,
      weth as never,
      fromBlock,
    );
    const wBob = await TestWallet.create(bob, darkPool, weth as never, fromBlock);

    const aliceAgent = new TraderAgent(wAlice, uniswapAdaptor, darkPool);
    const bobAgent = new TraderAgent(wBob, uniswapAdaptor, darkPool);

    const DEP_AMOUNT = ethers.parseEther("5");
    await wAlice.deposit(DEP_AMOUNT);
    await wAlice.sync();

    const SWAP_AMT = ethers.parseEther("2");
    const swap1Res = await aliceAgent.swap(WETH_ADDRESS, USDC_ADDRESS, SWAP_AMT);
    const usdcReceived = swap1Res[0].amount;

    await wBob.sync();
    expect(wAlice.getBalance(USDC_ADDRESS)).to.equal(usdcReceived);

    const bobAddr = await wBob.getReceiveAddress();
    await wAlice.transfer(usdcReceived, bobAddr.inPub, USDC_ADDRESS);
    await wBob.sync();

    expect(wBob.getBalance(USDC_ADDRESS)).to.equal(usdcReceived);
    const bobUsdcNote = wBob.utxoRepo
      .getUnspentNotes()
      .find((n) => n.note.assetId.equals(addressToFr(USDC_ADDRESS)))!;
    expect(bobUsdcNote.isIncoming).to.equal(true);

    const swap2Res = await bobAgent.swap(USDC_ADDRESS, WBTC_ADDRESS, usdcReceived);
    const wbtcReceived = swap2Res[0].amount;
    await wBob.sync();

    await wBob.withdraw(wbtcReceived, { asset: WBTC_ADDRESS });

    const wbtcContract = (await ethers.getContractAt(
      "IERC20",
      WBTC_ADDRESS,
    )) as unknown as IERC20;
    const bobWbtcBal = await wbtcContract.balanceOf(bob.address);
    expect(bobWbtcBal).to.equal(wbtcReceived);
  });
});
