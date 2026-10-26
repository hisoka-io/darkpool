import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture, time } from "@nomicfoundation/hardhat-network-helpers";
import type { ContractTransactionResponse } from "ethers";
import { COMPLIANCE_PK } from "../helpers/fixtures";
import {
  BN254_FR,
  NO_BOUND,
  b32,
  deployController,
  deployGoldenSettlementFixture,
} from "../helpers/settlementFixtures";
import { KAGE_PROOF, KAGE_PUBLIC_INPUTS } from "../integration/kageGolden";
import {
  HOT_KEY,
  SETTLE_WINDOW,
  deployKageFixture,
  messageFor,
  signSettlement,
  type KageDeployment,
} from "./kageFixtures";
import type { KageSettlement } from "../../typechain-types";

// Standalone and env-gated: GAS_BENCH=1 npx hardhat test test/kage/KageSettlementGas.bench.ts
const run = process.env.GAS_BENCH ? describe : describe.skip;

const INTRINSIC = 21_000n;
// keccak256(abi.encode(uint256(keccak256("hisoka.darkpool.tree")) - 1)) & ~bytes32(uint256(0xff)); Tree members:
// +0 TREE_DEPTH, +1 sideNodes, +2 nextLeafIndex, +3 latestRoot, +4 isKnownRoot.
const TREE_LOCATION =
  0xbdd00c81e71bd165e3ff2099ca204334ffd58a8d7225a33b4761542b7a86e200n;
// Bits 10..19 set: 10 hashing levels for the first insert, near 2^20 leaves.
const MATURE_INDEX = 0b11111111110000000000n;

function calldataGas(data: string): bigint {
  const bytes = ethers.getBytes(data);
  let gas = 0n;
  for (const b of bytes) gas += b === 0 ? 4n : 16n;
  return gas;
}

async function measure(tx: Promise<ContractTransactionResponse>) {
  const sent = await tx;
  const receipt = await sent.wait();
  const total = receipt!.gasUsed;
  const calldata = calldataGas(sent.data);
  return { total, calldata, execution: total - INTRINSIC - calldata };
}

const mappingSlot = (key: bigint, base: bigint): string =>
  ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["uint256", "uint256"],
      [key, base],
    ),
  );

async function setWord(addr: string, slot: string | bigint, value: bigint) {
  await ethers.provider.send("hardhat_setStorageAt", [
    addr,
    typeof slot === "bigint" ? ethers.toBeHex(slot, 32) : slot,
    ethers.toBeHex(value, 32),
  ]);
}

/** A 42-word vector the stub verifier accepts: live compliance key, far-future ts, synthetic root and notes. */
function syntheticVector(root: bigint, salt: bigint): string[] {
  const pi = new Array<string>(42);
  pi[0] = b32(COMPLIANCE_PK[0]);
  pi[1] = b32(COMPLIANCE_PK[1]);
  pi[2] = KAGE_PUBLIC_INPUTS[2];
  pi[3] = b32((salt * 1_000_003n + 11n) % BN254_FR);
  pi[4] = b32((salt * 1_000_003n + 13n) % BN254_FR);
  pi[5] = b32(root);
  for (let i = 6; i < 42; i++) pi[i] = b32((salt << 8n) + BigInt(i));
  return pi;
}

/** A second KageSettlement on the same pool and registry, registered as Kage registers but with StubVerifier. */
async function stubKageModule(d: KageDeployment): Promise<KageSettlement> {
  const settlement = (await (
    await ethers.getContractFactory("KageSettlement")
  ).deploy(
    await d.darkPool.getAddress(),
    await d.registry.getAddress(),
  )) as unknown as KageSettlement;
  await d.darkPool
    .connect(d.upgrader)
    .registerSettlementModule(
      await settlement.getAddress(),
      await d.stub.getAddress(),
      2,
      4,
      0,
      0,
      NO_BOUND,
    );
  return settlement;
}

async function settleSwapVia(
  d: KageDeployment,
  settlement: KageSettlement,
  pi: string[],
) {
  const deadline = BigInt(await time.latest()) + SETTLE_WINDOW;
  const m = await messageFor(d, pi, deadline);
  m.verifyingContract = await settlement.getAddress();
  const sig = await signSettlement(HOT_KEY, m);
  return measure(
    settlement.settleSwap(d.solverId, deadline, sig, KAGE_PROOF, pi),
  );
}

async function markRootKnown(pool: string, root: bigint) {
  await setWord(pool, mappingSlot(root, TREE_LOCATION + 4n), 1n);
}

run("Benchmark: KageSettlement.settleSwap gas breakdown", function () {
  this.timeout(600_000);

  it("splits settleSwap into calldata, solver guard, hook body and verify, and measures a mature tree", async function () {
    const d = await loadFixture(deployKageFixture);
    const real = await settleSwapVia(d, d.settlement, KAGE_PUBLIC_INPUTS);

    const golden = await loadFixture(deployGoldenSettlementFixture);
    const harnessReal = await measure(
      golden.controller.settle(KAGE_PROOF, KAGE_PUBLIC_INPUTS),
    );

    const stubbed = await loadFixture(deployGoldenSettlementFixture);
    const stubController = await deployController(stubbed.darkPool);
    await stubbed.darkPool
      .connect(stubbed.upgrader)
      .registerSettlementModule(
        await stubController.getAddress(),
        await stubbed.stub.getAddress(),
        2,
        4,
        0,
        0,
        NO_BOUND,
      );
    const harnessStub = await measure(
      stubController.settle(KAGE_PROOF, KAGE_PUBLIC_INPUTS),
    );

    // Mature tree: the same stub-verified settleSwap on a pool whose frontier sits at MATURE_INDEX.
    const fresh = await loadFixture(deployKageFixture);
    const nearModule = await stubKageModule(fresh);
    const pool = await fresh.darkPool.getAddress();
    const nearRoot = 0x1234n;
    await markRootKnown(pool, nearRoot);
    const near = await settleSwapVia(
      fresh,
      nearModule,
      syntheticVector(nearRoot, 1n),
    );

    const deep = await loadFixture(deployKageFixture);
    const deepModule = await stubKageModule(deep);
    const deepPool = await deep.darkPool.getAddress();
    await setWord(deepPool, TREE_LOCATION + 2n, MATURE_INDEX);
    for (let level = 0n; level < 32n; level++) {
      await setWord(
        deepPool,
        mappingSlot(level, TREE_LOCATION + 1n),
        0x5000n + level,
      );
    }
    const deepRoot = 0x5678n;
    await markRootKnown(deepPool, deepRoot);
    const mature = await settleSwapVia(
      deep,
      deepModule,
      syntheticVector(deepRoot, 2n),
    );
    expect(await deep.darkPool.getNextLeafIndex()).to.equal(MATURE_INDEX + 4n);

    const guard = real.execution - harnessReal.execution;
    const verify = harnessReal.total - harnessStub.total;
    const hookBody = harnessStub.execution;
    const matureDelta = mature.total - near.total;
    const rows: [string, bigint][] = [
      ["settleSwap total (golden proof, 3-leaf tree)", real.total],
      ["  intrinsic", INTRINSIC],
      ["  calldata (proof, 42 PI, id, deadline, sig)", real.calldata],
      ["  execution", real.execution],
      ["harness settle total (same proof)", harnessReal.total],
      ["  harness calldata", harnessReal.calldata],
      ["solver guard (settleSwap exec - harness exec)", guard],
      ["verify (real minus stub verifier, same calldata)", verify],
      ["hook body + forward, stub verify (harness exec)", hookBody],
      ["stub settleSwap, near-empty tree", near.total],
      [`stub settleSwap, frontier at ${MATURE_INDEX}`, mature.total],
      ["mature-tree delta (4 inserts at depth)", matureDelta],
    ];
    console.log(
      "\n" +
        rows
          .map(([k, v]) => `| ${k.padEnd(50)} | ${v.toString().padStart(9)} |`)
          .join("\n"),
    );
    expect(guard > 0n && verify > 0n && hookBody > 0n).to.equal(true);
    expect(matureDelta > 0n).to.equal(true);
    expect(real.total).to.equal(INTRINSIC + real.calldata + real.execution);
  });
});
