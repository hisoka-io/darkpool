import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture, time } from "@nomicfoundation/hardhat-network-helpers";
import { anyValue } from "@nomicfoundation/hardhat-chai-matchers/withArgs";
import {
  COMPLIANCE_PK,
  deployDarkPoolFixture,
  evenYEphemeral,
  makeDeposit,
  mintSelfNote,
  newSeededTree,
} from "../helpers/fixtures";
import {
  buildMultisigNote,
  depositMultisig,
  frostSign,
} from "../helpers/frostMultisig";
import {
  addressToFr,
  computeNullifier,
  Fr,
  packParents,
  toFr,
} from "@hisoka/wallets";
import * as frost from "@hisoka/wallets/frost";
import { frostAccountDkg } from "@hisoka/wallets/unsafe-sim";
import {
  proveWithdraw,
  proveWithdrawMultisig,
  type ProofData,
  type WithdrawInputs,
} from "@hisoka/prover";
import {
  HOWL_WITHDRAW_MULTISIG_PROFILE,
  HOWL_WITHDRAW_PROFILE,
  howlMultisigPaymentSource,
  howlWithdrawActionGasLimit,
} from "@hisoka/adaptors";

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
    ).deploy(await darkPool.getAddress(), await entryPoint.getAddress(), false);
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
    expect(await adapter.MULTISIG()).to.equal(false);
    const [proof] = ethers.AbiCoder.defaultAbiCoder().decode(
      ["bytes", "bytes32[]"],
      paymentData,
    );
    expect(ethers.dataLength(proof)).to.equal(HOWL_WITHDRAW_PROFILE.proofBytes);
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

/**
 * Asserts the call reverts in the proof verifier: the revert is not any adapter or DarkPool check other
 * than `InvalidProof`, so a verifier that returns false and one that reverts with its own error both count.
 */
async function expectProofRejected(
  call: Promise<unknown>,
  checks: readonly { parseError(data: string): { name: string } | null }[],
) {
  let data: string | undefined;
  try {
    await call;
  } catch (error) {
    data = (error as { data?: string }).data;
  }
  expect(data, "call must revert with revert data").to.be.a("string");
  for (const contract of checks) {
    const parsed = contract.parseError(data!);
    if (parsed !== null) expect(parsed.name).to.equal("InvalidProof");
  }
}

function intrinsicGas(data: string): bigint {
  let gas = 21_000n;
  for (const byte of ethers.getBytes(data)) gas += byte === 0 ? 4n : 16n;
  return gas;
}

describe("HowlPaymentAdapter on withdrawMultisig", function () {
  this.timeout(600_000);

  async function deployMultisigFixture() {
    const base = await deployDarkPoolFixture();
    const { darkPool, rewardPool, token, alice, bob, relayer } = base;
    const asset = await token.getAddress();
    const assetFr = addressToFr(asset);
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
    const adapterFactory =
      await ethers.getContractFactory("HowlPaymentAdapter");
    const standardAdapter = await adapterFactory.deploy(
      await darkPool.getAddress(),
      await entryPoint.getAddress(),
      false,
    );
    const multisigAdapter = await adapterFactory.deploy(
      await darkPool.getAddress(),
      await entryPoint.getAddress(),
      true,
    );
    const target = await (
      await ethers.getContractFactory("NoxActionTarget")
    ).deploy();
    await rewardPool.grantRole(
      await rewardPool.ENTRYPOINT_ROLE(),
      await entryPoint.getAddress(),
    );

    const feeNoteValue = ethers.parseEther("10");
    const totalFee = ethers.parseEther("4");
    const account = await frostAccountDkg(5, 3, 0x4e4f584d53n);
    const quorum = account.qual.slice(0, 3);
    const multisigNote = await depositMultisig(
      darkPool,
      token,
      alice,
      feeNoteValue,
      account.owner,
      assetFr,
      0x7a01n,
    );
    const standardNote = await makeDeposit(darkPool, token, bob, feeNoteValue);
    const tree = await newSeededTree();
    await tree.insert(multisigNote.commitment);
    await tree.insert(standardNote.commitment);
    const multisigPaymentId = (
      await computeNullifier(multisigNote.psi, toFr(1n))
    ).toString();
    const standardPaymentId = (
      await computeNullifier(standardNote.built.note.psi, toFr(2n))
    ).toString();

    const proveMultisigWithdraw = async (
      value: bigint,
      recipient: string,
      intentHash: bigint,
      changeSeed: bigint,
    ) => {
      const changeEph = evenYEphemeral(changeSeed);
      const change = await buildMultisigNote(
        changeEph,
        feeNoteValue - value,
        account.owner,
        assetFr,
        packParents([{ leafIndex: 1 }, { leafIndex: 0 }]),
      );
      const message = await frost.msgWithdraw({
        root: tree.getRoot().toBigInt(),
        nullifier: BigInt(multisigPaymentId),
        changeLeaf: change.commitment.toBigInt(),
        publicOut: value,
        asset: assetFr.toBigInt(),
        recipient: addressToFr(recipient).toBigInt(),
        intentHash,
      });
      const { R, z } = await frostSign(
        account.gpk,
        account.shares,
        quorum,
        message,
      );
      return proveWithdrawMultisig({
        withdrawValue: toFr(value),
        recipient: addressToFr(recipient),
        intentHash: toFr(intentHash),
        compliancePk: COMPLIANCE_PK,
        gpk: account.gpk,
        frostR: R,
        frostZ: toFr(z),
        oldNote: multisigNote.noteInput,
        oldNoteIndex: 1,
        oldNotePath: tree.getMerklePath(1),
        changeNote: change.noteInput,
        changeEph,
      });
    };
    const proveStandardWithdraw = async (
      value: bigint,
      recipient: string,
      intentHash: bigint,
      changeSeed: bigint,
    ) => {
      const changeEph = evenYEphemeral(changeSeed);
      const change = await mintSelfNote(
        changeEph,
        feeNoteValue - value,
        standardNote.spendScalar,
        assetFr,
        packParents([{ leafIndex: 2 }, { leafIndex: 0 }]),
      );
      return proveWithdraw({
        withdrawValue: toFr(value),
        recipient: addressToFr(recipient),
        intentHash: toFr(intentHash),
        compliancePk: COMPLIANCE_PK,
        oldNote: standardNote.built.note,
        spendScalar: standardNote.spendScalar,
        oldNoteIndex: 2,
        oldNotePath: tree.getMerklePath(2),
        changeNote: change.note,
        changeEph,
      });
    };

    const chainId = (await ethers.provider.getNetwork()).chainId;
    const actionData = target.interface.encodeFunctionData("setValue", [77]);
    const now = BigInt(await time.latest());
    const makeQuote = async (
      paymentAdapter: string,
      paymentId: string,
      clientIntent: string,
    ) => ({
      quoteVersion: 1,
      chainId,
      entryPoint: await entryPoint.getAddress(),
      exitAddress: relayer.address,
      clientIntentId: ethers.id(clientIntent),
      paymentAdapter,
      paymentId,
      feeAsset: asset,
      exitFee: ethers.parseEther("3"),
      networkFee: ethers.parseEther("1"),
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
    });
    type Quote = Awaited<ReturnType<typeof makeQuote>>;
    const signQuote = async (quote: Quote) =>
      relayer.signTypedData(
        {
          name: "NoxEntryPoint",
          version: "1",
          chainId,
          verifyingContract: await entryPoint.getAddress(),
        },
        QUOTE_TYPES,
        quote,
      );
    const encodePayment = (proof: ProofData) =>
      ethers.AbiCoder.defaultAbiCoder().encode(
        ["bytes", "bytes32[]"],
        [proof.proof, proof.publicInputs],
      );
    const entryPointSigner = await ethers.getImpersonatedSigner(
      await entryPoint.getAddress(),
    );
    await ethers.provider.send("hardhat_setBalance", [
      await entryPoint.getAddress(),
      "0x56BC75E2D63100000",
    ]);

    return {
      ...base,
      asset,
      entryPoint,
      entryPointSigner,
      standardAdapter,
      multisigAdapter,
      target,
      actionData,
      feeNoteValue,
      totalFee,
      multisigPaymentId,
      standardPaymentId,
      proveMultisigWithdraw,
      proveStandardWithdraw,
      makeQuote,
      signQuote,
      encodePayment,
    };
  }

  it("pays a Nox fee from a FROST note through NoxEntryPoint", async function () {
    const ctx = await loadFixture(deployMultisigFixture);
    const {
      entryPoint,
      relayer,
      multisigAdapter,
      standardAdapter,
      target,
      darkPool,
      rewardPool,
      token,
      asset,
      actionData,
      feeNoteValue,
      totalFee,
      multisigPaymentId,
      proveMultisigWithdraw,
    } = ctx;
    const adapterAddress = await multisigAdapter.getAddress();
    expect(await multisigAdapter.MULTISIG()).to.equal(true);
    expect(await standardAdapter.MULTISIG()).to.equal(false);

    const source = howlMultisigPaymentSource({
      adapter: adapterAddress,
      feeAsset: asset,
      feeNoteNullifier: multisigPaymentId,
      feeNoteValue,
      proveFeeWithdraw: (amount, recipient, intentHash) =>
        proveMultisigWithdraw(
          amount,
          recipient,
          intentHash.toBigInt(),
          0x7a10n,
        ),
    });
    const quote = {
      ...(await ctx.makeQuote(
        adapterAddress,
        multisigPaymentId,
        "multisig-fee",
      )),
      paymentGasLimit: source.gasLimit,
    };
    const executionId = await entryPoint.executionId(quote);
    const paymentData = ethers.hexlify(
      await source.buildPaymentData({
        executionId: ethers.getBytes(executionId),
        amount: totalFee,
        feeAsset: asset,
      }),
    );
    const [proof] = ethers.AbiCoder.defaultAbiCoder().decode(
      ["bytes", "bytes32[]"],
      paymentData,
    );
    expect(ethers.dataLength(proof)).to.equal(
      HOWL_WITHDRAW_MULTISIG_PROFILE.proofBytes,
    );
    expect(ethers.dataLength(paymentData)).to.equal(source.paymentDataLength);

    const tx = await entryPoint
      .connect(relayer)
      .execute(quote, await ctx.signQuote(quote), actionData, [], paymentData, {
        gasLimit: quote.maximumTransactionGas,
      });
    await expect(tx)
      .to.emit(entryPoint, "PaidExecutionSettled")
      .withArgs(
        executionId,
        multisigPaymentId,
        relayer.address,
        asset,
        quote.exitFee,
        quote.networkFee,
        await target.getAddress(),
        true,
        anyValue,
        anyValue,
      );
    expect(await target.value()).to.equal(77n);
    expect(await darkPool.isNullifierSpent(multisigPaymentId)).to.equal(true);
    expect(await rewardPool.totalCollected(asset)).to.equal(totalFee);
    expect(await multisigAdapter.pulling()).to.equal(false);
    expect(await multisigAdapter.expectedNullifier()).to.equal(ethers.ZeroHash);
    expect(await multisigAdapter.expectedIntent()).to.equal(0n);
    expect(await token.balanceOf(adapterAddress)).to.equal(0n);
    expect(await darkPool.getNextLeafIndex()).to.equal(4n);
  });

  it("fails the payment when a FROST proof reaches the standard instance", async function () {
    const ctx = await loadFixture(deployMultisigFixture);
    const {
      entryPoint,
      entryPointSigner,
      relayer,
      standardAdapter,
      darkPool,
      asset,
      actionData,
      totalFee,
      multisigPaymentId,
    } = ctx;
    const adapterAddress = await standardAdapter.getAddress();
    const quote = await ctx.makeQuote(
      adapterAddress,
      multisigPaymentId,
      "multisig-fee-wrong-instance",
    );
    const executionId = await entryPoint.executionId(quote);
    const paymentData = ctx.encodePayment(
      await ctx.proveMultisigWithdraw(
        totalFee,
        adapterAddress,
        await standardAdapter.paymentIntent(executionId),
        0x7a20n,
      ),
    );

    await expectProofRejected(
      standardAdapter
        .connect(entryPointSigner)
        .pay.staticCall(
          executionId,
          multisigPaymentId,
          asset,
          totalFee,
          paymentData,
        ),
      [standardAdapter.interface, darkPool.interface],
    );
    await expect(
      entryPoint
        .connect(relayer)
        .execute(
          quote,
          await ctx.signQuote(quote),
          actionData,
          [],
          paymentData,
          {
            gasLimit: quote.maximumTransactionGas,
          },
        ),
    ).to.be.revertedWithCustomError(entryPoint, "PaymentFailed");
    expect(await darkPool.isNullifierSpent(multisigPaymentId)).to.equal(false);
  });

  it("fails the payment when a standard proof reaches the multisig instance", async function () {
    const ctx = await loadFixture(deployMultisigFixture);
    const {
      entryPoint,
      entryPointSigner,
      relayer,
      multisigAdapter,
      darkPool,
      asset,
      actionData,
      totalFee,
      standardPaymentId,
    } = ctx;
    const adapterAddress = await multisigAdapter.getAddress();
    const quote = await ctx.makeQuote(
      adapterAddress,
      standardPaymentId,
      "standard-fee-wrong-instance",
    );
    const executionId = await entryPoint.executionId(quote);
    const paymentData = ctx.encodePayment(
      await ctx.proveStandardWithdraw(
        totalFee,
        adapterAddress,
        await multisigAdapter.paymentIntent(executionId),
        0x7a30n,
      ),
    );

    await expectProofRejected(
      multisigAdapter
        .connect(entryPointSigner)
        .pay.staticCall(
          executionId,
          standardPaymentId,
          asset,
          totalFee,
          paymentData,
        ),
      [multisigAdapter.interface, darkPool.interface],
    );
    await expect(
      entryPoint
        .connect(relayer)
        .execute(
          quote,
          await ctx.signQuote(quote),
          actionData,
          [],
          paymentData,
          {
            gasLimit: quote.maximumTransactionGas,
          },
        ),
    ).to.be.revertedWithCustomError(entryPoint, "PaymentFailed");
    expect(await darkPool.isNullifierSpent(standardPaymentId)).to.equal(false);
  });

  it("rejects a FROST proof signed for another recipient or another execution", async function () {
    const ctx = await loadFixture(deployMultisigFixture);
    const {
      entryPoint,
      entryPointSigner,
      multisigAdapter,
      standardAdapter,
      darkPool,
      asset,
      totalFee,
      multisigPaymentId,
    } = ctx;
    const adapterAddress = await multisigAdapter.getAddress();
    const quote = await ctx.makeQuote(
      adapterAddress,
      multisigPaymentId,
      "multisig-fee-bindings",
    );
    const executionId = await entryPoint.executionId(quote);
    const intent = await multisigAdapter.paymentIntent(executionId);
    const pay = (paymentData: string) =>
      multisigAdapter
        .connect(entryPointSigner)
        .pay.staticCall(
          executionId,
          multisigPaymentId,
          asset,
          totalFee,
          paymentData,
        );
    const checks = [multisigAdapter.interface, darkPool.interface];
    const rewrite = (proof: ProofData, index: number, word: bigint) => {
      const publicInputs = [...proof.publicInputs];
      publicInputs[index] = ethers.toBeHex(word, 32);
      return ctx.encodePayment({ ...proof, publicInputs });
    };

    const otherRecipient = await ctx.proveMultisigWithdraw(
      totalFee,
      await standardAdapter.getAddress(),
      intent,
      0x7a40n,
    );
    await expect(
      pay(ctx.encodePayment(otherRecipient)),
    ).to.be.revertedWithCustomError(multisigAdapter, "RecipientMismatch");
    await expectProofRejected(
      pay(rewrite(otherRecipient, 1, BigInt(adapterAddress))),
      checks,
    );

    const otherExecution = await ctx.proveMultisigWithdraw(
      totalFee,
      adapterAddress,
      await multisigAdapter.paymentIntent(ethers.id("another-execution")),
      0x7a50n,
    );
    await expect(
      pay(ctx.encodePayment(otherExecution)),
    ).to.be.revertedWithCustomError(multisigAdapter, "IntentMismatch");
    await expectProofRejected(pay(rewrite(otherExecution, 2, intent)), checks);
    expect(await darkPool.isNullifierSpent(multisigPaymentId)).to.equal(false);
  });

  it("stays inside the declared withdraw gas profiles", async function () {
    const ctx = await loadFixture(deployMultisigFixture);
    const {
      entryPointSigner,
      multisigAdapter,
      standardAdapter,
      darkPool,
      alice,
      asset,
      totalFee,
      multisigPaymentId,
      standardPaymentId,
    } = ctx;
    const executionId = ethers.id("gas-profile");
    const measure = async (
      request: { data: string },
      estimate: Promise<bigint>,
    ) => (await estimate) - intrinsicGas(request.data);

    const standardPay = await ctx.proveStandardWithdraw(
      totalFee,
      await standardAdapter.getAddress(),
      await standardAdapter.paymentIntent(executionId),
      0x7a60n,
    );
    const multisigPay = await ctx.proveMultisigWithdraw(
      totalFee,
      await multisigAdapter.getAddress(),
      await multisigAdapter.paymentIntent(executionId),
      0x7a61n,
    );
    const standardAction = await ctx.proveStandardWithdraw(
      totalFee,
      alice.address,
      0n,
      0x7a62n,
    );
    const multisigAction = await ctx.proveMultisigWithdraw(
      totalFee,
      alice.address,
      0n,
      0x7a63n,
    );
    const standardPayArgs = [
      executionId,
      standardPaymentId,
      asset,
      totalFee,
      ctx.encodePayment(standardPay),
    ] as const;
    const multisigPayArgs = [
      executionId,
      multisigPaymentId,
      asset,
      totalFee,
      ctx.encodePayment(multisigPay),
    ] as const;
    const standardPayGas = await measure(
      await standardAdapter.pay.populateTransaction(...standardPayArgs),
      standardAdapter
        .connect(entryPointSigner)
        .pay.estimateGas(...standardPayArgs),
    );
    const multisigPayGas = await measure(
      await multisigAdapter.pay.populateTransaction(...multisigPayArgs),
      multisigAdapter
        .connect(entryPointSigner)
        .pay.estimateGas(...multisigPayArgs),
    );
    const standardActionGas = await measure(
      await darkPool.withdraw.populateTransaction(
        standardAction.proof,
        standardAction.publicInputs,
      ),
      darkPool.withdraw.estimateGas(
        standardAction.proof,
        standardAction.publicInputs,
      ),
    );
    const multisigActionGas = await measure(
      await darkPool.withdrawMultisig.populateTransaction(
        multisigAction.proof,
        multisigAction.publicInputs,
      ),
      darkPool.withdrawMultisig.estimateGas(
        multisigAction.proof,
        multisigAction.publicInputs,
      ),
    );
    console.log(
      `      frame gas: pay standard=${standardPayGas} multisig=${multisigPayGas}; action standard=${standardActionGas} multisig=${multisigActionGas}`,
    );

    // Pay runs first in a paid execution, so its cold top-level frame matches the traced one. The action
    // frame here is cold too, while in a paid execution the payment has already warmed the pool, so only
    // its full limit applies.
    expect(standardPayGas).to.be.lessThanOrEqual(
      HOWL_WITHDRAW_PROFILE.payFrameGas,
    );
    expect(multisigPayGas).to.be.lessThanOrEqual(
      HOWL_WITHDRAW_MULTISIG_PROFILE.payFrameGas,
    );
    expect(standardActionGas).to.be.lessThanOrEqual(
      howlWithdrawActionGasLimit(HOWL_WITHDRAW_PROFILE),
    );
    expect(multisigActionGas).to.be.lessThanOrEqual(
      howlWithdrawActionGasLimit(HOWL_WITHDRAW_MULTISIG_PROFILE),
    );
    expect(
      HOWL_WITHDRAW_MULTISIG_PROFILE.payFrameGas -
        HOWL_WITHDRAW_PROFILE.payFrameGas,
    ).to.be.greaterThanOrEqual(multisigPayGas - standardPayGas);
    expect(
      HOWL_WITHDRAW_MULTISIG_PROFILE.withdrawFrameGas -
        HOWL_WITHDRAW_PROFILE.withdrawFrameGas,
    ).to.be.greaterThanOrEqual(multisigActionGas - standardActionGas);
  });
});
