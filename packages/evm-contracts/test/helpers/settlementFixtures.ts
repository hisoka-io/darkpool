import { ethers, upgrades } from "hardhat";
import type { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";
import {
  DarkPool,
  MockERC20,
  SettlementControllerHarness,
  StubVerifier,
} from "../../typechain-types";
import { COMPLIANCE_PK } from "./fixtures";
import { KAGE_LEAF_A, KAGE_LEAF_B } from "../integration/kageGolden";

export const NO_BOUND = 2n ** 32n - 1n;
export const BN254_FR =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
export const OUTPUT_WORDS = 9;

export const b32 = (v: bigint): string =>
  ethers.zeroPadValue(ethers.toBeHex(v), 32);

export interface StubbedPool {
  darkPool: DarkPool;
  stub: StubVerifier;
  token: MockERC20;
  admin: HardhatEthersSigner;
  pauser: HardhatEthersSigner;
  upgrader: HardhatEthersSigner;
  user: HardhatEthersSigner;
}

/** DarkPool with every circuit on an accept-all StubVerifier and the three roles on distinct signers. */
export async function deployStubbedPool(): Promise<StubbedPool> {
  const [admin, pauser, upgrader, user] = await ethers.getSigners();
  const pos = await (await ethers.getContractFactory("Poseidon2")).deploy();
  const stub = (await (
    await ethers.getContractFactory("StubVerifier")
  ).deploy()) as unknown as StubVerifier;
  const stubAddr = await stub.getAddress();
  const Factory = await ethers.getContractFactory("DarkPool", {
    libraries: { Poseidon2: await pos.getAddress() },
  });
  const darkPool = (await upgrades.deployProxy(
    Factory,
    [
      [
        ...Array<string>(10).fill(stubAddr),
        COMPLIANCE_PK[0],
        COMPLIANCE_PK[1],
        0,
        admin.address,
        pauser.address,
        upgrader.address,
      ],
    ],
    {
      kind: "uups",
      initializer: "initialize",
      unsafeAllow: ["external-library-linking"],
    },
  )) as unknown as DarkPool;
  const token = (await (
    await ethers.getContractFactory("MockERC20")
  ).deploy("Seed", "SEED", 18)) as unknown as MockERC20;
  await token.mint(admin.address, 10n ** 24n);
  await token.approve(await darkPool.getAddress(), ethers.MaxUint256);
  return { darkPool, stub, token, admin, pauser, upgrader, user };
}

export async function deployController(
  darkPool: DarkPool,
): Promise<SettlementControllerHarness> {
  return (await (
    await ethers.getContractFactory("SettlementControllerHarness")
  ).deploy(
    await darkPool.getAddress(),
  )) as unknown as SettlementControllerHarness;
}

/** Inserts `leaf` through a stub-verified deposit, which is how a fixture reaches a pinned tree. */
export async function stubDeposit(
  darkPool: DarkPool,
  token: MockERC20,
  leafHex: string,
): Promise<void> {
  const pi = new Array<string>(13).fill(b32(0n));
  pi[0] = b32(COMPLIANCE_PK[0]);
  pi[1] = b32(COMPLIANCE_PK[1]);
  pi[2] = leafHex;
  pi[4] = b32(1n);
  pi[5] = ethers.zeroPadValue(await token.getAddress(), 32);
  await darkPool.deposit("0x", pi);
}

export interface GoldenSettlement extends StubbedPool {
  controller: SettlementControllerHarness;
}

/**
 * The golden swap_settle proof was proven against [genesis(31337), leaf_A@1, leaf_B@2]; seeding those two leaves
 * makes its root known. The controller is registered with the real KageVerifier and the Kage layout (k=2, m=4,
 * e=0) under today's timestamp rule (5-minute floor, no ceiling).
 */
export async function deployGoldenSettlementFixture(): Promise<GoldenSettlement> {
  const pool = await deployStubbedPool();
  const kageVerifier = await (
    await ethers.getContractFactory(
      "contracts/verifiers/KageVerifier.sol:HonkVerifier",
    )
  ).deploy();
  const controller = await deployController(pool.darkPool);
  await pool.darkPool
    .connect(pool.upgrader)
    .registerSettlementModule(
      await controller.getAddress(),
      await kageVerifier.getAddress(),
      2,
      4,
      0,
      300,
      NO_BOUND,
    );
  await stubDeposit(pool.darkPool, pool.token, KAGE_LEAF_A);
  await stubDeposit(pool.darkPool, pool.token, KAGE_LEAF_B);
  return { ...pool, controller };
}
