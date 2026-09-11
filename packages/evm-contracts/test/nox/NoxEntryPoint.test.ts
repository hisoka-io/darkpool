import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import { loadFixture, time } from "@nomicfoundation/hardhat-network-helpers";

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

type Quote = {
  quoteVersion: number;
  chainId: bigint;
  entryPoint: string;
  exitAddress: string;
  clientIntentId: string;
  paymentAdapter: string;
  paymentId: string;
  feeAsset: string;
  exitFee: bigint;
  networkFee: bigint;
  paymentGasLimit: bigint;
  actionTarget: string;
  actionCalldataHash: string;
  actionGasLimit: bigint;
  trackedAssetsHash: string;
  maximumTransactionGas: bigint;
  maximumFeePerGas: bigint;
  returnDataLimit: bigint;
  validAfterUnix: bigint;
  validUntilUnix: bigint;
  quoteNonce: bigint;
};

function trackedAssetsHash(assets: readonly string[]): string {
  return ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(["address[]"], [assets]),
  );
}

describe("NoxEntryPoint", function () {
  async function deployFixture() {
    const [admin, exit, otherExit, attacker, recipient] =
      await ethers.getSigners();
    const chainId = (await ethers.provider.getNetwork()).chainId;

    const token = await (
      await ethers.getContractFactory("MockERC20")
    ).deploy("Fee", "FEE", 18);
    const registry = await (
      await ethers.getContractFactory("MockNoxRegistry")
    ).deploy();
    const pool = await upgrades.deployProxy(
      await ethers.getContractFactory("NoxRewardPool"),
      [
        [
          0,
          admin.address,
          await registry.getAddress(),
          admin.address,
          admin.address,
          admin.address,
        ],
      ],
      { kind: "uups" },
    );
    const tokenAddress = await token.getAddress();
    await pool.setAssetStatus(tokenAddress, true);
    await pool.classifyAsset(tokenAddress);

    const sandboxImplementation = await (
      await ethers.getContractFactory("NoxExecutionSandbox")
    ).deploy();
    const entryPoint = await (
      await ethers.getContractFactory("NoxEntryPoint")
    ).deploy(await pool.getAddress(), await sandboxImplementation.getAddress());
    await pool.grantRole(
      await pool.ENTRYPOINT_ROLE(),
      await entryPoint.getAddress(),
    );

    const adapter = await (
      await ethers.getContractFactory("MockNoxPaymentAdapter")
    ).deploy(await entryPoint.getAddress(), tokenAddress);
    const target = await (
      await ethers.getContractFactory("NoxActionTarget")
    ).deploy();
    await token.mint(await adapter.getAddress(), ethers.parseEther("1000"));

    const actionData = target.interface.encodeFunctionData("setValue", [77]);
    const now = BigInt(await time.latest());
    const baseQuote: Quote = {
      quoteVersion: 1,
      chainId,
      entryPoint: await entryPoint.getAddress(),
      exitAddress: exit.address,
      clientIntentId: ethers.id("client-intent-1"),
      paymentAdapter: await adapter.getAddress(),
      paymentId: ethers.id("payment-1"),
      feeAsset: tokenAddress,
      exitFee: ethers.parseEther("3"),
      networkFee: ethers.parseEther("1"),
      paymentGasLimit: 500_000n,
      actionTarget: await target.getAddress(),
      actionCalldataHash: ethers.keccak256(actionData),
      actionGasLimit: 300_000n,
      trackedAssetsHash: trackedAssetsHash([]),
      maximumTransactionGas: 1_500_000n,
      maximumFeePerGas: ethers.parseUnits("100", "gwei"),
      returnDataLimit: 256n,
      validAfterUnix: now - 1n,
      validUntilUnix: now + 600n,
      quoteNonce: 1n,
    };

    async function signQuote(quote: Quote) {
      return exit.signTypedData(
        {
          name: "NoxEntryPoint",
          version: "1",
          chainId,
          verifyingContract: await entryPoint.getAddress(),
        },
        QUOTE_TYPES,
        quote,
      );
    }

    async function execute(
      quote: Quote = baseQuote,
      signature?: string,
      calldata = actionData,
      trackedAssets: readonly string[] = [],
    ) {
      const gasLimit =
        quote.maximumTransactionGas > 5_000_000n
          ? 5_000_000n
          : quote.maximumTransactionGas;
      return entryPoint
        .connect(exit)
        .execute(
          quote,
          signature ?? (await signQuote(quote)),
          calldata,
          [...trackedAssets],
          "0x",
          { gasLimit },
        );
    }

    return {
      admin,
      exit,
      otherExit,
      attacker,
      recipient,
      token,
      pool,
      adapter,
      target,
      entryPoint,
      actionData,
      baseQuote,
      signQuote,
      execute,
    };
  }

  it("credits the selected exit and network pool, then executes the action", async function () {
    const { execute, target, pool, token, exit, baseQuote, entryPoint } =
      await loadFixture(deployFixture);

    const tx = await execute();
    const receipt = await tx.wait();
    const executionId = await entryPoint.executionId(baseQuote);
    expect(receipt!.gasUsed).to.be.lessThan(baseQuote.maximumTransactionGas);
    await expect(tx)
      .to.emit(entryPoint, "PaidExecutionSettled")
      .withArgs(
        executionId,
        baseQuote.paymentId,
        exit.address,
        await token.getAddress(),
        baseQuote.exitFee,
        baseQuote.networkFee,
        await target.getAddress(),
        true,
        32,
        ethers.keccak256(
          ethers.AbiCoder.defaultAbiCoder().encode(["uint256"], [77]),
        ),
      );
    expect(await target.value()).to.equal(77n);
    expect(
      await pool.claimableExit(exit.address, await token.getAddress()),
    ).to.equal(baseQuote.exitFee);
    expect(await pool.networkOutstanding(await token.getAddress())).to.equal(
      baseQuote.networkFee,
    );
    expect(await token.balanceOf(await entryPoint.getAddress())).to.equal(0n);
    expect(
      await token.allowance(
        await entryPoint.getAddress(),
        await pool.getAddress(),
      ),
    ).to.equal(0n);
  });

  it("rejects a quote submitted by an address other than the selected exit", async function () {
    const { entryPoint, otherExit, baseQuote, signQuote, actionData } =
      await loadFixture(deployFixture);
    await expect(
      entryPoint
        .connect(otherExit)
        .execute(baseQuote, await signQuote(baseQuote), actionData, [], "0x"),
    ).to.be.revertedWithCustomError(entryPoint, "WrongExit");
  });

  it("pins the Solidity execution identifier to the EIP-712 reference encoder", async function () {
    const { entryPoint, baseQuote } = await loadFixture(deployFixture);
    const expected = ethers.TypedDataEncoder.hash(
      {
        name: "NoxEntryPoint",
        version: "1",
        chainId: baseQuote.chainId,
        verifyingContract: await entryPoint.getAddress(),
      },
      QUOTE_TYPES,
      baseQuote,
    );
    expect(await entryPoint.executionId(baseQuote)).to.equal(expected);
  });

  it("normalizes malformed signatures to InvalidQuoteSigner", async function () {
    const { entryPoint, exit, baseQuote, actionData } =
      await loadFixture(deployFixture);
    await expect(
      entryPoint
        .connect(exit)
        .execute(baseQuote, "0x1234", actionData, [], "0x", {
          gasLimit: baseQuote.maximumTransactionGas,
        }),
    ).to.be.revertedWithCustomError(entryPoint, "InvalidQuoteSigner");
  });

  it("rejects fee and gas arithmetic overflow with typed errors", async function () {
    const { execute, baseQuote, signQuote, entryPoint } =
      await loadFixture(deployFixture);
    const feeOverflow = {
      ...baseQuote,
      exitFee: ethers.MaxUint256,
      networkFee: 1n,
    };
    await expect(
      execute(feeOverflow, await signQuote(feeOverflow)),
    ).to.be.revertedWithCustomError(entryPoint, "InvalidFee");

    const gasOverflow = {
      ...baseQuote,
      paymentGasLimit: ethers.MaxUint256,
      actionGasLimit: 1n,
      maximumTransactionGas: ethers.MaxUint256,
    };
    await expect(
      execute(gasOverflow, await signQuote(gasOverflow)),
    ).to.be.revertedWithCustomError(entryPoint, "InvalidGasBounds");
  });

  it("rejects wrong-chain and expired quotes", async function () {
    const { execute, baseQuote, signQuote, entryPoint } =
      await loadFixture(deployFixture);
    const wrongChain = { ...baseQuote, chainId: baseQuote.chainId + 1n };
    await expect(
      execute(wrongChain, await signQuote(wrongChain)),
    ).to.be.revertedWithCustomError(entryPoint, "WrongChain");

    const expired = { ...baseQuote, validUntilUnix: 1n };
    await expect(
      execute(expired, await signQuote(expired)),
    ).to.be.revertedWithCustomError(entryPoint, "QuoteExpired");
  });

  it("rejects action and tracked-asset mutation", async function () {
    const { execute, baseQuote, signQuote, entryPoint, target } =
      await loadFixture(deployFixture);
    const signature = await signQuote(baseQuote);
    const mutated = target.interface.encodeFunctionData("setValue", [78]);
    await expect(
      execute(baseQuote, signature, mutated),
    ).to.be.revertedWithCustomError(entryPoint, "ActionHashMismatch");
    await expect(
      execute(baseQuote, signature, undefined, [baseQuote.feeAsset]),
    ).to.be.revertedWithCustomError(entryPoint, "TrackedAssetsHashMismatch");
  });

  it("consumes execution, payment, and client-intent identifiers once", async function () {
    const { execute, baseQuote, signQuote, entryPoint } =
      await loadFixture(deployFixture);
    await execute();
    await expect(
      execute(baseQuote, await signQuote(baseQuote)),
    ).to.be.revertedWithCustomError(entryPoint, "ExecutionAlreadyConsumed");

    const paymentReplay = {
      ...baseQuote,
      clientIntentId: ethers.id("client-intent-2"),
      quoteNonce: 2n,
    };
    await expect(
      execute(paymentReplay, await signQuote(paymentReplay)),
    ).to.be.revertedWithCustomError(entryPoint, "PaymentAlreadyConsumed");
  });

  it("rejects fee underpayment before recording credit", async function () {
    const { adapter, execute, entryPoint, pool, token, exit } =
      await loadFixture(deployFixture);
    await adapter.setShortfall(1);
    await expect(execute()).to.be.revertedWithCustomError(
      entryPoint,
      "IncorrectPaymentAmount",
    );
    expect(
      await pool.claimableExit(exit.address, await token.getAddress()),
    ).to.equal(0n);
  });

  it("rejects insufficient outer gas before payment or credit", async function () {
    const { entryPoint, exit, baseQuote, signQuote, actionData, pool, token } =
      await loadFixture(deployFixture);
    await expect(
      entryPoint
        .connect(exit)
        .execute(baseQuote, await signQuote(baseQuote), actionData, [], "0x", {
          gasLimit: 900_000,
        }),
    ).to.be.revertedWithCustomError(entryPoint, "InsufficientExecutionGas");
    expect(
      await pool.claimableExit(exit.address, await token.getAddress()),
    ).to.equal(0n);
  });

  it("retains the fee and records bounded failure when the inner action reverts", async function () {
    const {
      target,
      baseQuote,
      signQuote,
      execute,
      entryPoint,
      pool,
      token,
      exit,
    } = await loadFixture(deployFixture);
    const failingData = target.interface.encodeFunctionData("fail", [
      "action failed",
    ]);
    const failingQuote = {
      ...baseQuote,
      clientIntentId: ethers.id("client-intent-fail"),
      paymentId: ethers.id("payment-fail"),
      actionCalldataHash: ethers.keccak256(failingData),
      quoteNonce: 9n,
    };
    const tx = await execute(
      failingQuote,
      await signQuote(failingQuote),
      failingData,
    );
    const receipt = await tx.wait();
    const parsed = receipt!.logs
      .map((log) => {
        try {
          return entryPoint.interface.parseLog(log);
        } catch {
          return null;
        }
      })
      .find((log) => log?.name === "PaidExecutionSettled");

    expect(parsed!.args.actionSuccess).to.equal(false);
    expect(parsed!.args.returnDataLength).to.be.greaterThan(0n);
    expect(
      await pool.claimableExit(exit.address, await token.getAddress()),
    ).to.equal(failingQuote.exitFee);
  });

  it("rolls payment and credit back when sandbox invariants fail", async function () {
    const { entryPoint, exit, baseQuote, signQuote, token, pool } =
      await loadFixture(deployFixture);
    const clientIntentId = ethers.id("client-intent-token-invariant");
    const trackedAssets = [await token.getAddress()];
    const actionData = token.interface.encodeFunctionData("mint", [
      await entryPoint.predictSandbox(clientIntentId),
      1n,
    ]);
    const quote = {
      ...baseQuote,
      clientIntentId,
      paymentId: ethers.id("payment-token-invariant"),
      actionTarget: await token.getAddress(),
      actionCalldataHash: ethers.keccak256(actionData),
      trackedAssetsHash: trackedAssetsHash(trackedAssets),
      quoteNonce: 10n,
    };
    const executionId = await entryPoint.executionId(quote);

    await expect(
      entryPoint
        .connect(exit)
        .execute(
          quote,
          await signQuote(quote),
          actionData,
          trackedAssets,
          "0x",
          { gasLimit: quote.maximumTransactionGas },
        ),
    ).to.be.revertedWithCustomError(entryPoint, "SandboxExecutionFailed");
    expect(await entryPoint.isExecutionConsumed(executionId)).to.equal(false);
    expect(
      await pool.claimableExit(exit.address, await token.getAddress()),
    ).to.equal(0n);
    expect(await token.balanceOf(await pool.getAddress())).to.equal(0n);
  });

  it("allows only an exit to claim its own credited balance", async function () {
    const { execute, pool, token, exit, attacker, recipient, baseQuote } =
      await loadFixture(deployFixture);
    await execute();
    const asset = await token.getAddress();

    await expect(
      pool.connect(attacker).claimExitCredit(asset, recipient.address, 1),
    ).to.be.revertedWithCustomError(pool, "InsufficientExitCredit");
    await expect(
      pool
        .connect(exit)
        .claimExitCredit(asset, recipient.address, baseQuote.exitFee),
    )
      .to.emit(pool, "ExitCreditClaimed")
      .withArgs(exit.address, recipient.address, asset, baseQuote.exitFee);
  });

  it("rejects constructor dependencies without deployed code", async function () {
    const [deployer] = await ethers.getSigners();
    const sandbox = await (
      await ethers.getContractFactory("NoxExecutionSandbox")
    ).deploy();
    const factory = await ethers.getContractFactory("NoxEntryPoint");

    await expect(
      factory.deploy(deployer.address, await sandbox.getAddress()),
    ).to.be.revertedWithCustomError(factory, "RewardPoolHasNoCode");
    await expect(
      factory.deploy(await sandbox.getAddress(), deployer.address),
    ).to.be.revertedWithCustomError(factory, "SandboxImplementationHasNoCode");
  });
});
