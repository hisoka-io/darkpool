import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import {
  deployUniswapFixture,
  WETH_ADDRESS,
  USDC_ADDRESS,
  WBTC_ADDRESS,
  COMPLIANCE_PK,
} from "../../fixtures";
import {
  UniswapSwapParams,
  SwapType,
  hashUniswapIntent,
} from "@hisoka/adaptors";
import { addressToFr, toFr } from "@hisoka/wallets";
import { DarkPool, IERC20, UniswapAdaptor } from "../../../../typechain-types";
import { TestWallet } from "../../../helpers/TestWallet";

class TraderAgent {
  constructor(
    public wallet: TestWallet,
    public adaptor: UniswapAdaptor,
    public darkPool: DarkPool,
  ) { }

  get address() {
    return this.wallet.signer.address;
  }

  async swap(
    assetIn: string,
    assetOut: string,
    amountIn: bigint,
    fee: number = 3000,
  ) {
    const recipientPk =
      await this.wallet.account.getPublicIncomingViewingKey(0n);
    const recipientSk = await this.wallet.account.getIncomingViewingKey(0n);

    const params: UniswapSwapParams = {
      type: SwapType.ExactInputSingle,
      assetIn,
      assetOut,
      fee,
      amountOutMin: 0n,
      recipient: { ownerX: recipientPk[0], ownerY: recipientPk[1] },
    };

    const intentHash = await hashUniswapIntent(params);

    const proof = await this.wallet.withdraw(amountIn, {
      asset: assetIn,
      recipient: await this.adaptor.getAddress(),
      intentHash,
    });

    const abiCoder = new ethers.AbiCoder();
    const encodedParams = abiCoder.encode(
      [
        "tuple(address assetIn, address assetOut, uint24 fee, tuple(uint256 ownerX, uint256 ownerY) recipient, uint256 amountOutMin)",
      ],
      [
        [
          params.assetIn,
          params.assetOut,
          params.fee,
          [params.recipient.ownerX, params.recipient.ownerY],
          params.amountOutMin,
        ],
      ],
    );

    const proofHex = "0x" + Buffer.from(proof.proof).toString("hex");
    const pubHex = proof.publicInputs.map(
      (i) => "0x" + BigInt(i).toString(16).padStart(64, "0"),
    );

    const tx = await this.adaptor
      .connect(this.wallet.signer as any)
      .executeSwap(proofHex, pubHex, SwapType.ExactInputSingle, encodedParams);
    const receipt = await tx.wait();

    // Critical: Sync wallet to capture the Change Note (Leaf 1) from the Withdraw
    await this.wallet.sync();

    return await this.scanAndClaim(receipt, recipientSk);
  }

  private async scanAndClaim(receipt: any, recipientSk: any) {
    const logs = receipt!.logs
      .map((l: any) => {
        try {
          return this.darkPool.interface.parseLog(l);
        } catch {
          return null;
        }
      })
      .filter((l: any) => l?.name === "NewPublicMemo");

    const results = [];
    for (const log of logs) {
      const args = log.args;
      console.log(
        `      -> Found Memo: ${ethers.formatUnits(args.value, 6)} of ${args.asset}`,
      );

      await this.wallet.claimPublic(
        {
          memoId: args.memoId,
          ownerX: args.ownerX,
          ownerY: args.ownerY,
          asset: args.asset,
          value: args.value,
          timelock: args.timelock,
          salt: args.salt,
        },
        recipientSk,
      );

      results.push({ asset: args.asset, amount: args.value });
    }
    return results;
  }
}

describe("Simulation: The DarkPool Trader (Multi-User DeFi)", function () {
  this.timeout(0); // Mainnet Fork

  it("should execute a complex economy: Swap -> Transfer -> Swap -> Transfer", async function () {
    const {
      darkPool,
      uniswapAdaptor,
      weth,
      alice,
      attacker: bob,
      fromBlock,
    } = await loadFixture(deployUniswapFixture);

    // --- 0. SETUP AGENTS ---
    console.log("\n[0] Initializing Agents...");
    const wAlice = await TestWallet.create(alice, darkPool, weth as any, fromBlock);
    const wBob = await TestWallet.create(bob, darkPool, weth as any, fromBlock);

    const aliceAgent = new TraderAgent(wAlice, uniswapAdaptor, darkPool);
    const bobAgent = new TraderAgent(wBob, uniswapAdaptor, darkPool);

    const syncAll = async (c: any) => {
      const fr = toFr(c);
      await wAlice.syncTree(fr);
      await wBob.syncTree(fr);
    };

    // --- STEP 1: ALICE DEPOSITS WETH ---
    const DEP_AMOUNT = ethers.parseEther("5");
    console.log(`[1] Alice Deposits ${ethers.formatEther(DEP_AMOUNT)} WETH...`);

    const depRes = await wAlice.deposit(DEP_AMOUNT);
    await syncAll(depRes.commitment);

    // Alice must sync to find her own note
    await wAlice.sync();

    // --- STEP 2: ALICE SWAPS WETH -> USDC ---
    console.log("[2] Alice Swaps 2 WETH -> USDC...");
    const SWAP_AMT = ethers.parseEther("2");

    const swap1Res = await aliceAgent.swap(
      WETH_ADDRESS,
      USDC_ADDRESS,
      SWAP_AMT,
    );
    const usdcReceived = swap1Res[0].amount;

    // Sync Bob with intermediate state changes (Leaf 1: Change, Leaf 2: Claimed USDC)

    // Find the Change Note (Leaf 1)
    const aliceWithdrawChange = wAlice.notes.find((n) => n.leafIndex === 1);
    if (!aliceWithdrawChange)
      throw new Error("Alice missing withdraw change note (Leaf 1)");
    await wBob.syncTree(aliceWithdrawChange.commitment);

    // Find the Claimed USDC (Leaf 2)
    const aliceClaimedUSDC = wAlice.notes.find((n) => n.leafIndex === 2);
    if (!aliceClaimedUSDC)
      throw new Error("Alice missing claimed USDC note (Leaf 2)");
    await wBob.syncTree(aliceClaimedUSDC.commitment);

    expect(wAlice.getBalance(USDC_ADDRESS)).to.equal(usdcReceived);

    // --- STEP 3: ALICE TRANSFERS USDC TO BOB ---
    console.log(
      `[3] Alice Transfers ${ethers.formatUnits(usdcReceived, 6)} USDC to Bob...`,
    );

    await wBob.keyRepo.advanceIncomingKeys(1);
    const bobIvk = await wBob.account.getIncomingViewingKey(0n);
    const { generateDLEQProof } = await import("@hisoka/wallets");
    const bobAddr = await generateDLEQProof(bobIvk.toBigInt(), COMPLIANCE_PK);

    const trf1 = await wAlice.transfer(
      usdcReceived,
      bobAddr.B,
      bobAddr.P,
      bobAddr.pi,
      USDC_ADDRESS,
    );

    await syncAll(trf1.memoCommitment);
    await syncAll(trf1.changeCommitment);

    // Bob Receives
    const memoLeafIndex = 3; // 0=Dep, 1=Change, 2=Claim, 3=Memo
    await wBob.receiveTransfer(
      trf1.publicInputs,
      memoLeafIndex,
      bobIvk.toBigInt(),
    );

    expect(wBob.getBalance(USDC_ADDRESS)).to.equal(usdcReceived);

    const bobUsdcNote = wBob.notes.find((n) =>
      n.note.asset_id.equals(addressToFr(USDC_ADDRESS)),
    )!;
    expect(bobUsdcNote.isTransfer).to.equal(true);

    // --- STEP 4: BOB SWAPS USDC -> WBTC ---
    console.log("[4] Bob Swaps USDC -> WBTC...");

    const swap2Res = await bobAgent.swap(
      USDC_ADDRESS,
      WBTC_ADDRESS,
      usdcReceived,
    );
    const wbtcReceived = swap2Res[0].amount;

    // Sync Claim
    const bobLatestCommitment = wBob.notes[wBob.notes.length - 1].commitment;
    await wAlice.syncTree(bobLatestCommitment);

    console.log(
      `      -> Bob holds ${ethers.formatUnits(wbtcReceived, 8)} WBTC (Shielded)`,
    );

    // --- STEP 5: BOB WITHDRAWS WBTC ---
    console.log("[5] Bob Withdraws WBTC...");

    await wBob.withdraw(wbtcReceived, { asset: WBTC_ADDRESS });

    // Verify L1 Balance
    const wbtcContract = await ethers.getContractAt("IERC20", WBTC_ADDRESS) as unknown as IERC20;
    const bobWbtcBal = await wbtcContract.balanceOf(bob.address);

    expect(bobWbtcBal).to.equal(wbtcReceived);

    console.log("[OK] DARKPOOL TRADER SCENARIO COMPLETE");
  });
});
