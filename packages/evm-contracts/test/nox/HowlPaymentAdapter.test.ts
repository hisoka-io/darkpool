import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture, time } from "@nomicfoundation/hardhat-network-helpers";
import {
  COMPLIANCE_PK,
  deployDarkPoolFixture,
  evenYEphemeral,
  makeDeposit,
  mintSelfNote,
  newSeededTree,
} from "../helpers/fixtures";
import {
  addressToFr,
  computeNullifier,
  Fr,
  packParents,
  toFr,
} from "@hisoka/wallets";
import {
  proveWithdraw,
  type ProofData,
  type WithdrawInputs,
} from "@hisoka/prover";

const QUOTE_TYPES = {
  ExecutionQuote: [
    { name: "quoteVersion", type: "uint8" },
    { name: "chainId", type: "uint256" },
    { name: "entryPoint", type: "address" },
    { name: "exitAddress", type: "address" },
    { name: "clientIntentId", type: "bytes32" },
    { name: "paymentAdapter", type: "address" },
    { name: "paymentId", type: "bytes32" },
    { name: "feeAsset", type: "address" },
    { name: "exitFee", type: "uint256" },
    { name: "networkFee", type: "uint256" },
    { name: "paymentGasLimit", type: "uint256" },
    { name: "actionTarget", type: "address" },
    { name: "actionCalldataHash", type: "bytes32" },
    { name: "actionGasLimit", type: "uint256" },
    { name: "trackedAssetsHash", type: "bytes32" },
    { name: "maximumTransactionGas", type: "uint256" },
    { name: "maximumFeePerGas", type: "uint256" },
    { name: "returnDataLimit", type: "uint256" },
    { name: "validAfterUnix", type: "uint64" },
    { name: "validUntilUnix", type: "uint64" },
    { name: "quoteNonce", type: "uint256" },
  ],
};

describe("HowlPaymentAdapter", function () {
  this.timeout(180_000);

  async function deployFixture() {
    const base = await deployDarkPoolFixture();
    const { darkPool, rewardPool, token, deployer, alice, relayer } = base;
    const asset = await token.getAddress();
    await rewardPool.classifyAsset(asset);

    const sandboxImplementation = await (
      await ethers.getContractFactory("NoxExecutionSandbox")
    ).deploy();
    const entryPoint = await (
      await ethers.getContractFactory("NoxEntryPoint")
    ).deploy(
      await rewardPool.getAddress(),
      await sandboxImplementation.getAddress(),
    );
    const adapter = await (
      await ethers.getContractFactory("HowlPaymentAdapter")
    ).deploy(await darkPool.getAddress(), await entryPoint.getAddress());
    const target = await (
      await ethers.getContractFactory("NoxActionTarget")
    ).deploy();
    await rewardPool.grantRole(
      await rewardPool.ENTRYPOINT_ROLE(),
      await entryPoint.getAddress(),
    );

    const feeNoteValue = ethers.parseEther("10");
    const exitFee = ethers.parseEther("3");
    const networkFee = ethers.parseEther("1");
    const totalFee = exitFee + networkFee;
    const deposit = await makeDeposit(darkPool, token, alice, feeNoteValue);
    const tree = await newSeededTree();
    await tree.insert(deposit.commitment);
    const paymentId = (
      await computeNullifier(deposit.built.note.psi, toFr(1n))
    ).toString();

    const actionData = target.interface.encodeFunctionData("setValue", [99]);
    const chainId = (await ethers.provider.getNetwork()).chainId;
    const now = BigInt(await time.latest());
    const quote = {
      quoteVersion: 1,
      chainId,
      entryPoint: await entryPoint.getAddress(),
      exitAddress: relayer.address,
      clientIntentId: ethers.id("howl-client-intent"),
      paymentAdapter: await adapter.getAddress(),
      paymentId,
      feeAsset: asset,
      exitFee,
      networkFee,
      paymentGasLimit: 4_000_000n,
      actionTarget: await target.getAddress(),
      actionCalldataHash: ethers.keccak256(actionData),
      actionGasLimit: 300_000n,
      trackedAssetsHash: ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(["address[]"], [[]]),
      ),
      maximumTransactionGas: 6_000_000n,
      maximumFeePerGas: ethers.parseUnits("100", "gwei"),
      returnDataLimit: 256n,
      validAfterUnix: now - 1n,
      validUntilUnix: now + 600n,
      quoteNonce: 1n,
    };
    const executionId = await entryPoint.executionId(quote);
    const intent = await adapter.paymentIntent(executionId);
    const expectedIntent =
      BigInt(
        ethers.keccak256(
          ethers.concat([
            ethers.toUtf8Bytes("hisoka.nox.howl-payment.v1"),
            executionId,
          ]),
        ),
      ) % Fr.MODULUS;
    expect(intent).to.equal(expectedIntent);
    const assetFr = addressToFr(asset);
    const proveFeeNoteWithdraw = async (
      value: bigint,
      recipient: string,
      intentHash: bigint,
      changeSeed: bigint,
    ) => {
      const changeEph = evenYEphemeral(changeSeed);
      const change = await mintSelfNote(
        changeEph,
        feeNoteValue - value,
        deposit.spendScalar,
        assetFr,
        packParents([{ leafIndex: 1 }, { leafIndex: 0 }]),
      );
      const inputs: WithdrawInputs = {
        withdrawValue: toFr(value),
        recipient: addressToFr(recipient),
        intentHash: toFr(intentHash),
        compliancePk: COMPLIANCE_PK,
        oldNote: deposit.built.note,
        spendScalar: deposit.spendScalar,
        oldNoteIndex: 1,
        oldNotePath: tree.getMerklePath(1),
        changeNote: change.note,
        changeEph,
      };
      return proveWithdraw(inputs);
    };
    const encodePayment = (proof: ProofData) =>
      ethers.AbiCoder.defaultAbiCoder().encode(
        ["bytes", "bytes32[]"],
        [proof.proof, proof.publicInputs],
      );
    const signQuote = async (signed: typeof quote) =>
      relayer.signTypedData(
        {
          name: "NoxEntryPoint",
          version: "1",
          chainId,
          verifyingContract: await entryPoint.getAddress(),
        },
        QUOTE_TYPES,
        signed,
      );
    const paymentData = encodePayment(
      await proveFeeNoteWithdraw(
        totalFee,
        await adapter.getAddress(),
        intent,
        9191n,
      ),
    );
    const signature = await signQuote(quote);

    return {
      ...base,
      deployer,
      relayer,
      adapter,
      entryPoint,
      target,
      asset,
      actionData,
      quote,
      signature,
      executionId,
      paymentData,
      totalFee,
      paymentId,
      proveFeeNoteWithdraw,
      encodePayment,
      signQuote,
    };
  }

  it("funds EntryPoint from an independent standard withdraw with positive change", async function () {
    const {
      entryPoint,
      relayer,
      quote,
      signature,
      actionData,
      paymentData,
      target,
      rewardPool,
      token,
      asset,
      paymentId,
      darkPool,
      adapter,
      totalFee,
    } = await loadFixture(deployFixture);

    const tx = await entryPoint
      .connect(relayer)
      .execute(quote, signature, actionData, [], paymentData, {
        gasLimit: quote.maximumTransactionGas,
      });

    await expect(tx).to.emit(entryPoint, "PaidExecutionSettled");
    expect(await target.value()).to.equal(99n);
    expect(await darkPool.isNullifierSpent(paymentId)).to.equal(true);
    expect(await rewardPool.totalCollected(asset)).to.equal(totalFee);
    expect(await adapter.expectedNullifier()).to.equal(ethers.ZeroHash);
    expect(await adapter.expectedIntent()).to.equal(0n);
    expect(await adapter.pulling()).to.equal(false);
    expect(await token.balanceOf(await adapter.getAddress())).to.equal(0n);
    expect(await darkPool.getNextLeafIndex()).to.equal(3n);
  });

  it("keeps the fee and reports a failed action when the action spends the fee note", async function () {
    const {
      entryPoint,
      relayer,
      alice,
      quote,
      adapter,
      darkPool,
      rewardPool,
      token,
      asset,
      paymentId,
      totalFee,
      proveFeeNoteWithdraw,
      encodePayment,
      signQuote,
    } = await loadFixture(deployFixture);

    const actionProof = await proveFeeNoteWithdraw(
      1n,
      alice.address,
      1n,
      9292n,
    );
    expect(actionProof.publicInputs[5]).to.equal(paymentId);
    const actionData = darkPool.interface.encodeFunctionData("withdraw", [
      actionProof.proof,
      actionProof.publicInputs,
    ]);
    const sameNoteQuote = {
      ...quote,
      clientIntentId: ethers.id("howl-action-spends-fee-note"),
      actionTarget: await darkPool.getAddress(),
      actionCalldataHash: ethers.keccak256(actionData),
      actionGasLimit: 2_000_000n,
      maximumTransactionGas: 8_000_000n,
    };
    const executionId = await entryPoint.executionId(sameNoteQuote);
    const paymentData = encodePayment(
      await proveFeeNoteWithdraw(
        totalFee,
        await adapter.getAddress(),
        await adapter.paymentIntent(executionId),
        9393n,
      ),
    );
    const aliceBefore = await token.balanceOf(alice.address);

    const tx = await entryPoint
      .connect(relayer)
      .execute(
        sameNoteQuote,
        await signQuote(sameNoteQuote),
        actionData,
        [],
        paymentData,
        { gasLimit: sameNoteQuote.maximumTransactionGas },
      );
    const receipt = await tx.wait();

    const settlement = receipt?.logs
      .map((log) => {
        try {
          return entryPoint.interface.parseLog(log);
        } catch {
          return null;
        }
      })
      .find((log) => log?.name === "PaidExecutionSettled");
    expect(settlement?.args.executionId).to.equal(executionId);
    expect(settlement?.args.actionSuccess).to.equal(false);
    expect(await rewardPool.totalCollected(asset)).to.equal(totalFee);
    expect(await darkPool.isNullifierSpent(paymentId)).to.equal(true);
    expect(await token.balanceOf(alice.address)).to.equal(aliceBefore);
    expect(await darkPool.getNextLeafIndex()).to.equal(3n);
  });

  it("rejects direct calls and payment data whose public bindings do not match", async function () {
    const {
      adapter,
      attacker,
      executionId,
      paymentId,
      asset,
      totalFee,
      paymentData,
    } = await loadFixture(deployFixture);
    await expect(
      adapter
        .connect(attacker)
        .pay(executionId, paymentId, asset, totalFee, paymentData),
    ).to.be.revertedWithCustomError(adapter, "NotEntryPoint");

    const [proof, publicInputs] = ethers.AbiCoder.defaultAbiCoder().decode(
      ["bytes", "bytes32[]"],
      paymentData,
    );
    const mutatedInputs = [...publicInputs];
    mutatedInputs[5] = ethers.id("wrong-payment");
    const mutatedData = ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes", "bytes32[]"],
      [proof, mutatedInputs],
    );
    const adapterSigner = await ethers.getImpersonatedSigner(
      await adapter.ENTRY_POINT(),
    );
    await ethers.provider.send("hardhat_setBalance", [
      await adapter.ENTRY_POINT(),
      "0x56BC75E2D63100000",
    ]);
    await expect(
      adapter
        .connect(adapterSigner)
        .pay(executionId, paymentId, asset, totalFee, mutatedData),
    ).to.be.revertedWithCustomError(adapter, "PaymentIdMismatch");
  });
});
