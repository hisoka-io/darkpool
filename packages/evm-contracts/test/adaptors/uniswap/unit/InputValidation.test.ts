import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import {
  deployUniswapFixture,
  depositEphemeralParams,
  WETH_ADDRESS,
  USDC_ADDRESS,
  COMPLIANCE_PK,
} from "../../fixtures";
import {
  deriveSharedSecret,
  NotePlaintext,
  toFr,
  addressToFr,
  LeanIMT,
  Poseidon,
  Fr,
  Kdf,
  toBjjScalar,
  computeOwner,
} from "@hisoka/wallets";
import { Base8, mulPointEscalar } from "@zk-kit/baby-jubjub";
import { proveWithdraw, WithdrawInputs } from "@hisoka/prover";
import { hashUniswapIntent, SwapType } from "@hisoka/adaptors";

// Deterministic spending key for the hand-built deposit note: verify_spend
// asserts note.owner == Poseidon2(nk*G), so owner and nk must agree.
async function spendKeyMaterial(): Promise<{ nk: Fr; owner: Fr }> {
  const nk = toBjjScalar(await Kdf.derive("hisoka.test.nk", toFr(1n)));
  const owner = await computeOwner(mulPointEscalar(Base8, nk.toBigInt()));
  return { nk, owner };
}

describe("Uniswap Adaptor: Security & Validation", function () {
  this.timeout(0); // Forking

  async function fixture() {
    const data = await deployUniswapFixture();

    // Deposit 10 WETH
    const amount = ethers.parseEther("10");
    const assetFr = addressToFr(WETH_ADDRESS);
    const { nk, owner } = await spendKeyMaterial();
    const note: NotePlaintext = {
      value: toFr(amount),
      asset_id: assetFr,
      secret: toFr(10n),
      owner,
      timelock: toFr(0n),
      hashlock: toFr(0n),
    };

    const enc = await depositEphemeralParams();
    const depProof = await (
      await import("@hisoka/prover")
    ).proveDeposit({
      notePlaintext: note,
      ephemeralSk: enc.ephemeral_sk_used,
      compliancePk: COMPLIANCE_PK,
    });

    await (
      await data.weth
        .connect(data.alice)
        .approve(await data.darkPool.getAddress(), amount)
    ).wait();
    await data.darkPool
      .connect(data.alice)
      .deposit(depProof.proof, depProof.publicInputs);

    const tree = new LeanIMT(32);
    const pub = depProof.publicInputs.map((s) => toFr(s));
    await tree.insert(await Poseidon.hash(pub.slice(6, 13)));

    return { ...data, tree, note, enc, amount, nk };
  }

  it("SECURITY: Should reject if Intent Params are modified (Hijack Attempt)", async function () {
    const { uniswapAdaptor, alice, tree, note, enc, amount, nk } =
      await loadFixture(fixture);

    // A. Alice generates proof for [WETH -> USDC]
    const validParams = {
      type: SwapType.ExactInputSingle,
      assetIn: WETH_ADDRESS,
      assetOut: USDC_ADDRESS,
      fee: 3000,
      recipient: { ownerX: 1n, ownerY: 2n, claimerOwner: 3n },
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
      nk,
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

    const abiCoder = new ethers.AbiCoder();
    const encodedParams = abiCoder.encode(
      [
        "tuple(address assetIn, address assetOut, uint24 fee, tuple(uint256 ownerX, uint256 ownerY, uint256 claimerOwner) recipient, uint256 amountOutMin)",
      ],
      [
        [
          hijackedParams.assetIn,
          hijackedParams.assetOut,
          hijackedParams.fee,
          [
            hijackedParams.recipient.ownerX,
            hijackedParams.recipient.ownerY,
            hijackedParams.recipient.claimerOwner,
          ],
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
    const { uniswapAdaptor, alice, tree, note, enc, amount, nk } =
      await loadFixture(fixture);

    // Alice tries to be sneaky: Generates proof withdrawing to HERSELF (Alice),
    // but submits it to the Adaptor.
    // Adaptor Logic: "I will only execute if *I* get the funds."

    const validParams = {
      type: SwapType.ExactInputSingle,
      assetIn: WETH_ADDRESS,
      assetOut: USDC_ADDRESS,
      fee: 3000,
      recipient: { ownerX: 1n, ownerY: 2n, claimerOwner: 3n },
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
      nk,
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
        "tuple(address assetIn, address assetOut, uint24 fee, tuple(uint256 ownerX, uint256 ownerY, uint256 claimerOwner) recipient, uint256 amountOutMin)",
      ],
      [
        [
          validParams.assetIn,
          validParams.assetOut,
          validParams.fee,
          [
            validParams.recipient.ownerX,
            validParams.recipient.ownerY,
            validParams.recipient.claimerOwner,
          ],
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

  const EIS_TUPLE =
    "tuple(address assetIn, address assetOut, uint24 fee, tuple(uint256 ownerX, uint256 ownerY, uint256 claimerOwner) recipient, uint256 amountOutMin)";

  function encodeEIS(p: {
    assetIn: string;
    assetOut: string;
    fee: number;
    recipient: { ownerX: bigint; ownerY: bigint; claimerOwner: bigint };
    amountOutMin: bigint;
  }) {
    return new ethers.AbiCoder().encode(
      [EIS_TUPLE],
      [
        [
          p.assetIn,
          p.assetOut,
          p.fee,
          [p.recipient.ownerX, p.recipient.ownerY, p.recipient.claimerOwner],
          p.amountOutMin,
        ],
      ],
    );
  }

  async function buildWithdraw(
    data: any,
    tree: any,
    note: any,
    enc: any,
    amount: bigint,
    params: any,
  ) {
    // @ts-ignore
    const intentHash = await hashUniswapIntent(params);
    const { nk } = await spendKeyMaterial();
    const inputs: WithdrawInputs = {
      withdrawValue: toFr(amount),
      recipient: addressToFr(await data.uniswapAdaptor.getAddress()),
      merkleRoot: tree.getRoot(),
      currentTimestamp: Math.floor(Date.now() / 1000),
      intentHash,
      compliancePk: COMPLIANCE_PK,
      oldNote: note,
      oldSharedSecret: await deriveSharedSecret(
        enc.ephemeral_sk_used,
        COMPLIANCE_PK,
      ),
      nk,
      oldNoteIndex: 0,
      oldNotePath: Array(32).fill(toFr(0n)),
      hashlockPreimage: toFr(0n),
      changeNote: { ...note, value: toFr(0n) },
      changeEphemeralSk: toFr(999n),
    };
    const proof = await proveWithdraw(inputs);
    const proofHex = "0x" + Buffer.from(proof.proof).toString("hex");
    const pubHex = proof.publicInputs.map(
      (i) => "0x" + BigInt(i).toString(16).padStart(64, "0"),
    );
    return { proofHex, pubHex };
  }

  const goodParams = {
    type: SwapType.ExactInputSingle,
    assetIn: WETH_ADDRESS,
    assetOut: USDC_ADDRESS,
    fee: 3000,
    recipient: { ownerX: 777n, ownerY: 888n, claimerOwner: 999n },
    amountOutMin: 0n,
  };

  it("FIX1: rejects swapping an asset other than the withdrawn asset", async function () {
    const data = await loadFixture(fixture);
    const { uniswapAdaptor, alice } = data;
    const mismatch = {
      ...goodParams,
      assetIn: USDC_ADDRESS,
      assetOut: WETH_ADDRESS,
    };
    const { proofHex, pubHex } = await buildWithdraw(
      data,
      data.tree,
      data.note,
      data.enc,
      data.amount,
      mismatch,
    );
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
    const { proofHex, pubHex } = await buildWithdraw(
      data,
      data.tree,
      data.note,
      data.enc,
      data.amount,
      goodParams,
    );
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

  it("C-1: blocks a direct withdraw to the adaptor from a non-adaptor caller", async function () {
    const data = await loadFixture(fixture);
    const { darkPool, attacker, uniswapAdaptor } = data;
    const { proofHex, pubHex } = await buildWithdraw(
      data,
      data.tree,
      data.note,
      data.enc,
      data.amount,
      goodParams,
    );
    expect(
      await darkPool.isAdaptor(await uniswapAdaptor.getAddress()),
    ).to.equal(true);
    await expect(
      darkPool.connect(attacker).withdraw(proofHex, pubHex),
    ).to.be.revertedWithCustomError(darkPool, "OnlyAdaptorMayPull");
  });
});
