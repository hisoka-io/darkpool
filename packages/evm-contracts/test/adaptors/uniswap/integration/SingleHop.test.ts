import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import {
  deployUniswapFixture,
  fetchLivePrices,
  WETH_ADDRESS,
  USDC_ADDRESS,
  COMPLIANCE_PK,
  SK_VIEW,
  NONCE,
} from "../../fixtures";
import {
  encryptNoteDeposit,
  deriveSharedSecret,
  NotePlaintext,
  toFr,
  addressToFr,
  LeanIMT,
  Poseidon,
} from "@hisoka/wallets";
import { proveWithdraw, WithdrawInputs } from "@hisoka/prover";
import { hashUniswapIntent, SwapType } from "@hisoka/adaptors";

describe("Uniswap Adaptor: Single Hop Integration", function () {
  this.timeout(0);

  let ethUsd: number;

  before(async function () {
    const prices = await fetchLivePrices();
    ethUsd = prices.ethUsd;
  });

  async function setupNote(data: any) {
    const amount = ethers.parseEther("10"); // 10 WETH
    const assetFr = addressToFr(WETH_ADDRESS);
    const note: NotePlaintext = {
      value: toFr(amount),
      asset_id: assetFr,
      secret: toFr(10n),
      nullifier: toFr(20n),
      timelock: toFr(0n),
      hashlock: toFr(0n),
    };
    const enc = await encryptNoteDeposit(SK_VIEW, NONCE, note, COMPLIANCE_PK);
    const depProof = await (
      await import("@hisoka/prover")
    ).proveDeposit({
      notePlaintext: note,
      ephemeralSk: enc.ephemeral_sk_used,
      compliancePk: COMPLIANCE_PK,
    });

    await data.weth
      .connect(data.alice)
      .approve(await data.darkPool.getAddress(), amount);
    await data.darkPool
      .connect(data.alice)
      .deposit(depProof.proof, depProof.publicInputs);

    const tree = new LeanIMT(32);
    const pub = depProof.publicInputs.map((s: string) => toFr(s));
    await tree.insert(await Poseidon.hash(pub.slice(6, 13)));

    return { note, enc, tree, amount };
  }

  it("should execute ExactOutputSingle and REFUND excess input", async function () {
    const data = await loadFixture(deployUniswapFixture);
    const { uniswapAdaptor, darkPool, alice } = data;
    const { note, enc, tree, amount } = await setupNote(data);

    // Goal: Buy exactly 2000 USDC
    const TARGET_USDC = ethers.parseUnits("2000", 6); // 2000 USDC
    // Input: We withdraw 10 WETH (Way too much)

    const params = {
      type: SwapType.ExactOutputSingle,
      assetIn: WETH_ADDRESS,
      assetOut: USDC_ADDRESS,
      fee: 3000,
      recipient: { ownerX: 888n, ownerY: 999n },
      amountOut: BigInt(TARGET_USDC),
      amountInMaximum: BigInt(amount), // Max we are willing to spend (entire note)
    };

    // @ts-ignore
    const intentHash = await hashUniswapIntent(params);

    const inputs: WithdrawInputs = {
      withdrawValue: toFr(amount),
      recipient: addressToFr(await uniswapAdaptor.getAddress()),
      merkleRoot: tree.getRoot(),
      currentTimestamp: Math.floor(Date.now() / 1000),
      intentHash: intentHash,
      compliancePk: COMPLIANCE_PK,
      oldNote: note,
      oldSharedSecret: await deriveSharedSecret(
        enc.ephemeral_sk_used,
        COMPLIANCE_PK,
      ),
      oldNoteIndex: 0,
      oldNotePath: Array(32).fill(toFr(0n)),
      hashlockPreimage: toFr(0n),
      changeNote: { ...note, value: toFr(0n) },
      changeEphemeralSk: toFr(999n),
    };
    const proof = await proveWithdraw(inputs);

    // Encode
    const abiCoder = new ethers.AbiCoder();
    const encodedParams = abiCoder.encode(
      [
        "tuple(address assetIn, address assetOut, uint24 fee, tuple(uint256 ownerX, uint256 ownerY) recipient, uint256 amountOut, uint256 amountInMaximum)",
      ],
      [
        [
          params.assetIn,
          params.assetOut,
          params.fee,
          [params.recipient.ownerX, params.recipient.ownerY],
          params.amountOut,
          params.amountInMaximum,
        ],
      ],
    );

    const proofHex = "0x" + Buffer.from(proof.proof).toString("hex");
    const pubHex = proof.publicInputs.map(
      (i) => "0x" + BigInt(i).toString(16).padStart(64, "0"),
    );

    // Execute
    const tx = await uniswapAdaptor
      .connect(alice)
      .executeSwap(proofHex, pubHex, SwapType.ExactOutputSingle, encodedParams);
    const receipt = await tx.wait();

    // --- VERIFICATION ---

    // We expect TWO NewPublicMemo events
    const logs = receipt!.logs
      .map((l) => {
        try {
          return darkPool.interface.parseLog(l as any);
        } catch {
          return null;
        }
      })
      .filter((l) => l?.name === "NewPublicMemo");

    expect(logs.length).to.equal(2);

    // 1. Find USDC Memo (Target)
    const usdcLog = logs.find((l) => l?.args.asset === USDC_ADDRESS);
    expect(usdcLog).to.not.equal(undefined);
    expect(usdcLog?.args.value).to.equal(TARGET_USDC);

    // 2. Find WETH Memo (Refund)
    const wethLog = logs.find((l) => l?.args.asset === WETH_ADDRESS);
    expect(wethLog).to.not.equal(undefined);
    // Refund = 10 ETH minus cost of 2000 USDC (price-dependent).
    // Dynamic threshold: cost = 2000/ethUsd, with 50% safety margin for slippage.
    const estimatedCost = 2000 / ethUsd;
    const minRefund = 10 - estimatedCost * 1.5;
    const refund = wethLog?.args.value;
    console.log(`   Refunded: ${ethers.formatEther(refund)} WETH (min threshold: ${minRefund.toFixed(2)} at ETH=$${ethUsd.toFixed(0)})`);
    expect(refund).to.be.gt(ethers.parseEther(minRefund.toFixed(4)));

    // 3. Check Ownership
    expect(usdcLog?.args.ownerX).to.equal(888n);
    expect(wethLog?.args.ownerX).to.equal(888n);
  });
});
