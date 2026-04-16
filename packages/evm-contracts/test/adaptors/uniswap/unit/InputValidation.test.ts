import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import {
  deployUniswapFixture,
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

describe("Uniswap Adaptor: Security & Validation", function () {
  this.timeout(0); // Forking

  async function fixture() {
    const data = await deployUniswapFixture();

    // 1. Deposit 10 WETH (Standard Setup)
    const amount = ethers.parseEther("10");
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

    // 2. Construct Tree
    const tree = new LeanIMT(32);
    const pub = depProof.publicInputs.map((s) => toFr(s));
    await tree.insert(await Poseidon.hash(pub.slice(6, 13)));

    return { ...data, tree, note, enc, amount };
  }

  it("SECURITY: Should reject if Intent Params are modified (Hijack Attempt)", async function () {
    const { uniswapAdaptor, alice, tree, note, enc, amount } =
      await loadFixture(fixture);

    // A. Alice generates proof for [WETH -> USDC]
    const validParams = {
      type: SwapType.ExactInputSingle,
      assetIn: WETH_ADDRESS,
      assetOut: USDC_ADDRESS,
      fee: 3000,
      recipient: { ownerX: 1n, ownerY: 2n },
      amountOutMin: 0n,
    };
    // @ts-ignore
    const intentHash = await hashUniswapIntent(validParams);

    // Generate Proof bound to `intentHash`
    const inputs: WithdrawInputs = {
      withdrawValue: toFr(amount),
      recipient: addressToFr(await uniswapAdaptor.getAddress()),
      merkleRoot: tree.getRoot(),
      currentTimestamp: Math.floor(Date.now() / 1000),
      intentHash: intentHash, // <--- BINDING
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

    // B. Attacker submits Alice's proof but changes AssetOut to DAI
    const DA_ADDRESS = "0x6B175474E89094C44Da98b954EedeAC495271d0F";
    const hijackedParams = { ...validParams, assetOut: DA_ADDRESS };

    // Encode params for contract
    const abiCoder = new ethers.AbiCoder();
    const encodedParams = abiCoder.encode(
      [
        "tuple(address assetIn, address assetOut, uint24 fee, tuple(uint256 ownerX, uint256 ownerY) recipient, uint256 amountOutMin)",
      ],
      [
        [
          hijackedParams.assetIn,
          hijackedParams.assetOut,
          hijackedParams.fee,
          [hijackedParams.recipient.ownerX, hijackedParams.recipient.ownerY],
          hijackedParams.amountOutMin,
        ],
      ],
    );

    const proofHex = "0x" + Buffer.from(proof.proof).toString("hex");
    const pubHex = proof.publicInputs.map(
      (i) => "0x" + BigInt(i).toString(16).padStart(64, "0"),
    );

    // Verification should fail because Contract calculates Hash(DAI) != Proof Hash(USDC)
    await expect(
      uniswapAdaptor
        .connect(alice)
        .executeSwap(
          proofHex,
          pubHex,
          SwapType.ExactInputSingle,
          encodedParams,
        ),
    ).to.be.reverted; // Reverts inside DarkPool verifier check
  });

  it("SECURITY: Should reject if Proof Recipient is not the Adaptor", async function () {
    const { uniswapAdaptor, alice, tree, note, enc, amount } =
      await loadFixture(fixture);

    // Alice tries to be sneaky: Generates proof withdrawing to HERSELF (Alice),
    // but submits it to the Adaptor.
    // Adaptor Logic: "I will only execute if *I* get the funds."

    const validParams = {
      type: SwapType.ExactInputSingle,
      assetIn: WETH_ADDRESS,
      assetOut: USDC_ADDRESS,
      fee: 3000,
      recipient: { ownerX: 1n, ownerY: 2n },
      amountOutMin: 0n,
    };
    // @ts-ignore
    const intentHash = await hashUniswapIntent(validParams);

    const inputs: WithdrawInputs = {
      withdrawValue: toFr(amount),
      recipient: addressToFr(alice.address), // <--- TARGET ALICE, NOT ADAPTOR
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
        "tuple(address assetIn, address assetOut, uint24 fee, tuple(uint256 ownerX, uint256 ownerY) recipient, uint256 amountOutMin)",
      ],
      [
        [
          validParams.assetIn,
          validParams.assetOut,
          validParams.fee,
          [validParams.recipient.ownerX, validParams.recipient.ownerY],
          validParams.amountOutMin,
        ],
      ],
    );

    const proofHex = "0x" + Buffer.from(proof.proof).toString("hex");
    const pubHex = proof.publicInputs.map(
      (i) => "0x" + BigInt(i).toString(16).padStart(64, "0"),
    );

    // Adaptor should check pubInputs[1] (Recipient) and revert before calling DarkPool
    await expect(
      uniswapAdaptor
        .connect(alice)
        .executeSwap(
          proofHex,
          pubHex,
          SwapType.ExactInputSingle,
          encodedParams,
        ),
    ).to.be.revertedWithCustomError(uniswapAdaptor, "InvalidProofRecipient");
  });
});
