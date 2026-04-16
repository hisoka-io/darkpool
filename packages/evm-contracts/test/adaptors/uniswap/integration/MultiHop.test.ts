import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import {
  deployUniswapFixture,
  fetchLivePrices,
  WETH_ADDRESS,
  USDC_ADDRESS,
  DAI_ADDRESS,
  WBTC_ADDRESS,
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

  // Helper to bootstrap a note
  async function setupNote(data: any, amountEth: string) {
    const amount = ethers.parseEther(amountEth);
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

    await (await data.weth
      .connect(data.alice)
      .approve(await data.darkPool.getAddress(), amount)).wait();
    await data.darkPool
      .connect(data.alice)
      .deposit(depProof.proof, depProof.publicInputs);

    const tree = new LeanIMT(32);
    const pub = depProof.publicInputs.map((s: string) => toFr(s));
    await tree.insert(await Poseidon.hash(pub.slice(6, 13)));

    return { note, enc, tree, amount };
  }

  it("should swap WETH -> USDC -> DAI (Exact Input)", async function () {
    const data = await loadFixture(deployUniswapFixture);
    const { uniswapAdaptor, darkPool, alice } = data;
    const { note, enc, tree, amount } = await setupNote(data, "1.0"); // 1 WETH

    // Route: WETH (3000) -> USDC (500) -> DAI
    // Encoded: [WETH, 3000, USDC, 500, DAI]
    const path = encodePath(
      [WETH_ADDRESS, USDC_ADDRESS, DAI_ADDRESS],
      [3000, 500],
    );

    const params = {
      type: SwapType.ExactInput,
      path: path,
      recipient: { ownerX: 111n, ownerY: 222n },
      amountOutMin: 0n,
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

    // Execute
    const abiCoder = new ethers.AbiCoder();
    const encodedParams = abiCoder.encode(
      [
        "tuple(bytes path, tuple(uint256 ownerX, uint256 ownerY) recipient, uint256 amountOutMin)",
      ],
      [
        [
          params.path,
          [params.recipient.ownerX, params.recipient.ownerY],
          params.amountOutMin,
        ],
      ],
    );

    const proofHex = "0x" + Buffer.from(proof.proof).toString("hex");
    const pubHex = proof.publicInputs.map(
      (i) => "0x" + BigInt(i).toString(16).padStart(64, "0"),
    );

    const tx = await uniswapAdaptor
      .connect(alice)
      .executeSwap(proofHex, pubHex, SwapType.ExactInput, encodedParams);
    const receipt = await tx.wait();

    // Verify Return
    const log = receipt!.logs
      .map((l) => {
        try {
          return darkPool.interface.parseLog(l as any);
        } catch {
          return null;
        }
      })
      .find((l) => l?.name === "NewPublicMemo");

    assert(log !== null)
    // Should be DAI
    expect(log?.args.asset).to.equal(DAI_ADDRESS);
    // Dynamic threshold: 1 WETH should yield at least 50% of ETH/USD price in DAI (multi-hop slippage margin)
    const minDaiOutput = Math.floor(ethUsd * 0.5);
    expect(log?.args.value).to.be.gt(ethers.parseUnits(minDaiOutput.toString(), 18));
    console.log(
      `   Swapped 1 WETH -> DAI: ${ethers.formatUnits(log?.args.value, 18)} (min threshold: ${minDaiOutput} at ETH=$${ethUsd.toFixed(0)})`,
    );
  });

  it("should swap WETH -> USDC -> WBTC (Exact Output) with Refund", async function () {
    const data = await loadFixture(deployUniswapFixture);
    const { uniswapAdaptor, darkPool, alice } = data;
    // Withdraw 10 ETH to buy 0.1 WBTC (Excess input)
    const { note, enc, tree, amount } = await setupNote(data, "10.0");

    // Route: WBTC (500) -> USDC (3000) -> WETH
    // NOTE: Uniswap V3 ExactOutput path is REVERSED (TokenOut -> ... -> TokenIn)
    // [WBTC, 500, USDC, 3000, WETH]
    const path = encodePath(
      [WBTC_ADDRESS, USDC_ADDRESS, WETH_ADDRESS],
      [500, 3000],
    );

    const TARGET_WBTC = ethers.parseUnits("0.1", 8); // 0.1 WBTC

    const params = {
      type: SwapType.ExactOutput,
      path: path,
      recipient: { ownerX: 333n, ownerY: 444n },
      amountOut: BigInt(TARGET_WBTC),
      amountInMaximum: BigInt(amount),
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

    const abiCoder = new ethers.AbiCoder();
    const encodedParams = abiCoder.encode(
      [
        "tuple(bytes path, tuple(uint256 ownerX, uint256 ownerY) recipient, uint256 amountOut, uint256 amountInMaximum)",
      ],
      [
        [
          params.path,
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

    const tx = await uniswapAdaptor
      .connect(alice)
      .executeSwap(proofHex, pubHex, SwapType.ExactOutput, encodedParams);
    const receipt = await tx.wait();

    // Verify Returns (Should have 2 memos)
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

    // 1. WBTC Memo
    const wbtcLog = logs.find((l) => l?.args.asset === WBTC_ADDRESS);
    expect(wbtcLog?.args.value).to.equal(TARGET_WBTC);
    console.log(`   Received exact: 0.1 WBTC`);

    // 2. Refund Memo
    // Dynamic threshold: cost of 0.1 WBTC in ETH = 0.1 * btcUsd / ethUsd, with 50% slippage margin
    const estimatedCostEth = 0.1 * btcUsd / ethUsd;
    const minRefund = 10 - estimatedCostEth * 1.5;
    const wethLog = logs.find((l) => l?.args.asset === WETH_ADDRESS);
    assert(wethLog !== null)
    expect(wethLog?.args.value).to.be.gt(ethers.parseEther(minRefund.toFixed(4)));
    console.log(`   Refunded: ${ethers.formatEther(wethLog?.args.value)} WETH (min threshold: ${minRefund.toFixed(2)} at BTC=$${btcUsd.toFixed(0)}, ETH=$${ethUsd.toFixed(0)})`);
  });
});
