import { ethers, upgrades } from "hardhat";
import type { Wallet } from "ethers";
import type { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";
import type {
  KageRegistry,
  KageSettlement,
  MockERC20,
} from "../../typechain-types";
import {
  NO_BOUND,
  deployStubbedPool,
  stubDeposit,
  type StubbedPool,
} from "../helpers/settlementFixtures";
import { KAGE_LEAF_A, KAGE_LEAF_B } from "../integration/kageGolden";

// The staking token is USDC-shaped (6 decimals): amounts are base units, never 18-decimal literals.
export const STAKE_DECIMALS = 6;
export const MIN_STAKE_FLOOR = ethers.parseUnits("1000", STAKE_DECIMALS);
export const MIN_STAKE = ethers.parseUnits("10000", STAKE_DECIMALS);
export const EXIT_DELAY = 7n * 24n * 3600n;
export const SETTLE_WINDOW = 600n;

// Fixed test-only hot keys, so a failing run reproduces byte for byte.
export const HOT_KEY = new ethers.Wallet(ethers.id("kage-test-solver-hot-key"));
export const ROTATED_KEY = new ethers.Wallet(
  ethers.id("kage-test-solver-rotated-key"),
);
export const STRANGER_KEY = new ethers.Wallet(
  ethers.id("kage-test-stranger-key"),
);

export const SETTLEMENT_TYPES = {
  KageSettlement: [
    { name: "pool", type: "address" },
    { name: "solverId", type: "uint256" },
    { name: "publicInputsHash", type: "bytes32" },
    { name: "deadline", type: "uint256" },
  ],
};

export interface SettlementMessage {
  chainId: bigint;
  verifyingContract: string;
  pool: string;
  solverId: bigint;
  deadline: bigint;
  publicInputs: readonly string[];
}

export function publicInputsHash(publicInputs: readonly string[]): string {
  return ethers.keccak256(ethers.concat([...publicInputs]));
}

export function settlementTypedData(m: SettlementMessage) {
  return {
    domain: {
      name: "HisokaKageSettlement",
      version: "1",
      chainId: m.chainId,
      verifyingContract: m.verifyingContract,
    },
    types: SETTLEMENT_TYPES,
    value: {
      pool: m.pool,
      solverId: m.solverId,
      publicInputsHash: publicInputsHash(m.publicInputs),
      deadline: m.deadline,
    },
  };
}

export function settlementDigestTs(m: SettlementMessage): string {
  const t = settlementTypedData(m);
  return ethers.TypedDataEncoder.hash(t.domain, t.types, t.value);
}

export async function signSettlement(
  key: Wallet,
  m: SettlementMessage,
): Promise<string> {
  const t = settlementTypedData(m);
  return key.signTypedData(t.domain, t.types, t.value);
}

export interface KageRegistryDeployment {
  registry: KageRegistry;
  stakeToken: MockERC20;
  admin: HardhatEthersSigner;
  slasher: HardhatEthersSigner;
  config: HardhatEthersSigner;
  upgrader: HardhatEthersSigner;
  solverOwner: HardhatEthersSigner;
  stranger: HardhatEthersSigner;
}

export async function deployKageRegistry(
  stakingToken?: string,
): Promise<KageRegistryDeployment> {
  const signers = await ethers.getSigners();
  const [admin, , upgrader, , slasher, config, solverOwner, stranger] = signers;
  const stakeToken = (await (
    await ethers.getContractFactory("MockERC20")
  ).deploy("USD Coin", "USDC", STAKE_DECIMALS)) as unknown as MockERC20;
  const registry = (await upgrades.deployProxy(
    await ethers.getContractFactory("KageRegistry"),
    [
      [
        0,
        admin.address,
        stakingToken ?? (await stakeToken.getAddress()),
        MIN_STAKE,
        MIN_STAKE_FLOOR,
        EXIT_DELAY,
        slasher.address,
        config.address,
        upgrader.address,
      ],
    ],
    { kind: "uups", initializer: "initialize" },
  )) as unknown as KageRegistry;
  return {
    registry,
    stakeToken,
    admin,
    slasher,
    config,
    upgrader,
    solverOwner,
    stranger,
  };
}

/** Mints `amount` to `owner`, approves exactly that, and registers a solver settling through `signer`. */
export async function registerSolver(
  registry: KageRegistry,
  token: MockERC20,
  owner: HardhatEthersSigner,
  signer: string,
  amount: bigint = MIN_STAKE,
): Promise<bigint> {
  await token.mint(owner.address, amount);
  await token.connect(owner).approve(await registry.getAddress(), amount);
  const id = await registry.connect(owner).register.staticCall(signer, amount);
  await registry.connect(owner).register(signer, amount);
  return id;
}

export interface KageDeployment
  extends StubbedPool, Omit<KageRegistryDeployment, "admin" | "upgrader"> {
  settlement: KageSettlement;
  kageVerifier: string;
  solverId: bigint;
  chainId: bigint;
}

/**
 * Production wiring on the golden tree: KageRegistry (USDC-shaped stake), KageSettlement, and the module registered
 * as Kage registers it, `(2, 4, 0, 0, NO_BOUND)`: no module words, settle no later than the proof's timestamp, no
 * ceiling. One solver (id 1) is registered with the fixed hot key.
 */
export async function deployKageFixture(): Promise<KageDeployment> {
  const pool = await deployStubbedPool();
  const reg = await deployKageRegistry();
  const verifier = await (
    await ethers.getContractFactory(
      "contracts/verifiers/KageVerifier.sol:HonkVerifier",
    )
  ).deploy();
  const settlement = (await (
    await ethers.getContractFactory("KageSettlement")
  ).deploy(
    await pool.darkPool.getAddress(),
    await reg.registry.getAddress(),
  )) as unknown as KageSettlement;
  await pool.darkPool
    .connect(pool.upgrader)
    .registerSettlementModule(
      await settlement.getAddress(),
      await verifier.getAddress(),
      2,
      4,
      0,
      0,
      NO_BOUND,
    );
  await stubDeposit(pool.darkPool, pool.token, KAGE_LEAF_A);
  await stubDeposit(pool.darkPool, pool.token, KAGE_LEAF_B);
  const solverId = await registerSolver(
    reg.registry,
    reg.stakeToken,
    reg.solverOwner,
    HOT_KEY.address,
  );
  const { chainId } = await ethers.provider.getNetwork();
  return {
    ...pool,
    ...reg,
    admin: pool.admin,
    upgrader: pool.upgrader,
    settlement,
    kageVerifier: await verifier.getAddress(),
    solverId,
    chainId,
  };
}

/** The settlement message for the fixture's own domain and pool. */
export async function messageFor(
  d: KageDeployment,
  publicInputs: readonly string[],
  deadline: bigint,
  solverId: bigint = d.solverId,
): Promise<SettlementMessage> {
  return {
    chainId: d.chainId,
    verifyingContract: await d.settlement.getAddress(),
    pool: await d.darkPool.getAddress(),
    solverId,
    deadline,
    publicInputs,
  };
}
