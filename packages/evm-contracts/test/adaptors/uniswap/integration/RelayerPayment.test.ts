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
  NotePlaintext,
  toFr,
  addressToFr,
  LeanIMT,
  Poseidon,
  deriveSharedSecret,
  Fr,
  Kdf,
  toBjjScalar,
  computeOwner,
} from "@hisoka/wallets";
import { Base8, mulPointEscalar } from "@zk-kit/baby-jubjub";
import { proveWithdraw, WithdrawInputs } from "@hisoka/prover";
import { hashUniswapIntent, SwapType, encodePath } from "@hisoka/adaptors";
import { RelayerMulticall__factory } from "../../../../typechain-types";

describe("Relayer Safe Settlement: Integration", function () {
  this.timeout(0); // Mainnet Forking

  async function setupNote(data: any, amountEth: string) {
    const amount = ethers.parseEther(amountEth);
    const assetFr = addressToFr(WETH_ADDRESS);
    // verify_spend asserts note.owner == Poseidon2(nk*G), so owner/nk must agree.
    const nk = toBjjScalar(await Kdf.derive("hisoka.test.nk", toFr(1n)));
    const owner = await computeOwner(mulPointEscalar(Base8, nk.toBigInt()));
    const note: NotePlaintext = {
      value: toFr(amount),
      asset_id: assetFr,
      secret: toFr(ethers.toBigInt(ethers.randomBytes(31))),
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
    const pub = depProof.publicInputs.map((s: string) => toFr(s));
    await tree.insert(await Poseidon.hash(pub.slice(6, 13)));

    return { note, enc, tree, amount, nk };
  }

  async function generateWithdrawProof(
    note: NotePlaintext,
    enc: any,
    tree: any,
    recipientAddr: string,
    nk: Fr,
    intentHash: bigint = 0n,
  ) {
    const inputs: WithdrawInputs = {
      withdrawValue: note.value,
      recipient: addressToFr(recipientAddr),
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
    return await proveWithdraw(inputs);
  }

  it("should process Payment but shield Relayer from failed Swap", async function () {
    const data = await loadFixture(deployUniswapFixture);
    const { uniswapAdaptor, darkPool, weth, deployer } = data;

    const RelayerMulticallFactory = (await ethers.getContractFactory(
      "RelayerMulticall",
    )) as unknown as RelayerMulticall__factory;
    const relayerMulticall = await RelayerMulticallFactory.deploy();

    const relayer = deployer; // the executor

    // --- 1. Prepare Payment (Withdraw 1 WETH to Relayer) ---
    const paymentSetup = await setupNote(data, "1.0");
    const paymentProof = await generateWithdrawProof(
      paymentSetup.note,
      paymentSetup.enc,
      paymentSetup.tree,
      relayer.address,
      paymentSetup.nk,
    );

    // --- 2. Prepare Swap (Withdraw 2 WETH to Adaptor -> Swap) ---
    const swapSetup = await setupNote(data, "2.0");

    // Intent with an IMPOSSIBLE amountOutMin so the swap reverts
    const path = encodePath([WETH_ADDRESS, USDC_ADDRESS], [500]); // WETH -> USDC
    const params = {
      type: SwapType.ExactInput,
      path: path,
      recipient: { ownerX: 111n, ownerY: 222n, claimerOwner: 333n },
      amountOutMin: ethers.parseUnits("1000000", 6), // Expect 1M USDC for 2 ETH (Impossible!)
    };
    // @ts-ignore
    const intentHash = await hashUniswapIntent(params);

    const swapProof = await generateWithdrawProof(
      swapSetup.note,
      swapSetup.enc,
      swapSetup.tree,
      await uniswapAdaptor.getAddress(),
      swapSetup.nk,
      intentHash,
    );

    // --- 3. Encode Calls ---

    // Call A: DarkPool.withdraw (Payment)
    const withdrawData = darkPool.interface.encodeFunctionData("withdraw", [
      "0x" + Buffer.from(paymentProof.proof).toString("hex"),
      paymentProof.publicInputs.map(
        (i) => "0x" + BigInt(i).toString(16).padStart(64, "0"),
      ),
    ]);

    // Call B: UniswapAdaptor.executeSwap (Swap)
    const abiCoder = new ethers.AbiCoder();
    const encodedParams = abiCoder.encode(
      [
        "tuple(bytes path, tuple(uint256 ownerX, uint256 ownerY, uint256 claimerOwner) recipient, uint256 amountOutMin)",
      ],
      [
        [
          params.path,
          [
            params.recipient.ownerX,
            params.recipient.ownerY,
            params.recipient.claimerOwner,
          ],
          params.amountOutMin,
        ],
      ],
    );

    const swapData = uniswapAdaptor.interface.encodeFunctionData(
      "executeSwap",
      [
        "0x" + Buffer.from(swapProof.proof).toString("hex"),
        swapProof.publicInputs.map(
          (i) => "0x" + BigInt(i).toString(16).padStart(64, "0"),
        ),
        SwapType.ExactInput,
        encodedParams,
      ],
    );

    const calls = [
      {
        target: await darkPool.getAddress(),
        data: withdrawData,
        value: 0n,
        requireSuccess: true, // Critical Payment
      },
      {
        target: await uniswapAdaptor.getAddress(),
        data: swapData,
        value: 0n,
        requireSuccess: false, // Action can fail
      },
    ];

    // --- 4. Execution & Verification ---

    const relayerBalanceBefore = await weth.balanceOf(relayer.address);

    // High gas overrides avoid mainnet-fork baseFee fluctuations
    const tx = await relayerMulticall.connect(relayer).multicall(calls, {
      maxFeePerGas: ethers.parseUnits("200", "gwei"),
      maxPriorityFeePerGas: ethers.parseUnits("5", "gwei"),
    });
    const receipt = await tx.wait();

    // Expect CallExecuted(0, true) for the payment and CallFailed(1) for the swap
    const executedFilter = relayerMulticall.filters.CallExecuted();
    const failedFilter = relayerMulticall.filters.CallFailed();

    const executedEvents = await relayerMulticall.queryFilter(
      executedFilter,
      receipt?.blockNumber,
    );
    const failedEvents = await relayerMulticall.queryFilter(
      failedFilter,
      receipt?.blockNumber,
    );

    expect(executedEvents.length).to.be.gte(2); // One for success, one for fail (emits Executed(false))
    expect(failedEvents.length).to.equal(1);

    expect(executedEvents[0].args.success).to.equal(true); // Payment Success
    expect(executedEvents[1].args.success).to.equal(false); // Swap Failed

    // Check Payment Received
    const relayerBalanceAfter = await weth.balanceOf(relayer.address);
    expect(relayerBalanceAfter).to.equal(
      relayerBalanceBefore + ethers.parseEther("1.0"),
    );

    console.log(
      "[OK] Relayer Shield Active: Payment collected, Swap reverted safely.",
    );
  });
});
