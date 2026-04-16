import { ethers } from "hardhat";
import { DarkPool, DarkPool__factory, MockERC20, MockERC20__factory } from "../../typechain-types";
import { proveDeposit, DepositInputs } from "@hisoka/prover";
import {
  toFr,
  addressToFr,
  Kdf,
  NotePlaintext,
  Poseidon,
} from "@hisoka/wallets";
import { Base8, mulPointEscalar, Point } from "@zk-kit/baby-jubjub";
import { ContractRunner } from "ethers";

// Constants
export const COMPLIANCE_SK = 987654321n;
export const COMPLIANCE_PK: Point<bigint> = mulPointEscalar(
  Base8,
  COMPLIANCE_SK,
);
export const SK_VIEW = toFr(123456789n);
export const NONCE = toFr(1n);

export async function deployDarkPoolFixture() {
  const [deployer, alice, bob, charlie, attacker, compliance, relayer] =
    await ethers.getSigners();

  // 1. Libs
  const Poseidon2Factory = await ethers.getContractFactory("Poseidon2");
  const poseidon2Lib = await Poseidon2Factory.deploy();

  // 2. Verifiers
  // 2. Verifiers
  // Helper to deploy verifier with linked library
  const deployVerifier = async (contractPath: string) => {
    const Verifier = await (
      await ethers.getContractFactory(`${contractPath}:HonkVerifier`)
    ).deploy();
    return Verifier;
  };

  const DepVerifier = await deployVerifier("contracts/verifiers/DepositVerifier.sol");
  const WdwVerifier = await deployVerifier("contracts/verifiers/WithdrawVerifier.sol");
  const TrfVerifier = await deployVerifier("contracts/verifiers/TransferVerifier.sol");
  const JoinVerifier = await deployVerifier("contracts/verifiers/JoinVerifier.sol");
  const SplitVerifier = await deployVerifier("contracts/verifiers/SplitVerifier.sol");
  const PublicClaimVerifier = await deployVerifier("contracts/verifiers/PublicClaimVerifier.sol");
  const GasVerifier = await deployVerifier("contracts/verifiers/GasPaymentVerifier.sol");

  const RewardPoolFactory = await ethers.getContractFactory("NoxRewardPool");
  const rewardPool = await RewardPoolFactory.deploy(deployer.address);

  // 3. Token
  const token = await (
    await ethers.getContractFactory("MockERC20") as unknown as MockERC20__factory
  ).deploy("Mock", "MCK", 18);
  await rewardPool.setAssetStatus(await token.getAddress(), true);
  // Fund users
  const initialBalance = ethers.parseEther("10000");
  await token.mint(alice.address, initialBalance);
  await token.mint(bob.address, initialBalance);
  await token.mint(charlie.address, initialBalance);
  await token.mint(attacker.address, initialBalance);

  // 4. DarkPool
  const DarkPoolFactory = await ethers.getContractFactory("DarkPool", {
    libraries: { Poseidon2: await poseidon2Lib.getAddress() },
  }) as unknown as DarkPool__factory;

  const darkPool = await DarkPoolFactory.deploy(
    await DepVerifier.getAddress(),
    await WdwVerifier.getAddress(),
    await TrfVerifier.getAddress(),
    await JoinVerifier.getAddress(),
    await SplitVerifier.getAddress(),
    await PublicClaimVerifier.getAddress(),
    await GasVerifier.getAddress(),
    await rewardPool.getAddress(),
    COMPLIANCE_PK[0],
    COMPLIANCE_PK[1],
    deployer.address,
  );

  return {
    darkPool,
    token,
    rewardPool, // Export for tests
    deployer,
    alice,
    bob,
    charlie,
    attacker,
    compliance,
    relayer
  };
}

// BJJ subgroup order - ephemeral keys must be reduced to this range
const BJJ_SUBGROUP_ORDER = 2736030358979909402780800718157159386076813972158567259200215660948447373041n;

// Helper: Make a standard deposit
export async function makeDeposit(
  darkPool: DarkPool,
  token: MockERC20,
  user: ContractRunner & { address: string },
  amount: bigint,
) {
  const assetFr = addressToFr(await token.getAddress());
  const depositPlain: NotePlaintext = {
    value: toFr(amount),
    asset_id: assetFr,
    secret: toFr(ethers.toBigInt(ethers.randomBytes(31))),
    nullifier: toFr(ethers.toBigInt(ethers.randomBytes(31))),
    timelock: toFr(0n),
    hashlock: toFr(0n),
  };
  // Unique ephemeral per deposit to avoid collisions in tests
  const randomNonce = toFr(ethers.toBigInt(ethers.randomBytes(31)));
  const ephemeralSkRaw = await Kdf.derive(
    "hisoka.ephemeral",
    SK_VIEW,
    randomNonce,
  );
  const ephemeralSk = toFr(ephemeralSkRaw.toBigInt() % BJJ_SUBGROUP_ORDER);

  const depInputs: DepositInputs = {
    notePlaintext: depositPlain,
    ephemeralSk: ephemeralSk,
    compliancePk: COMPLIANCE_PK,
  };

  const proof = await proveDeposit(depInputs);

  await token.connect(user).approve(await darkPool.getAddress(), amount);
  await darkPool.connect(user).deposit(proof.proof, proof.publicInputs);

  // Reconstruct commitment
  const pub = proof.publicInputs.map((s) => toFr(s));
  const packedCt = pub.slice(6, 13);
  const commitment = await Poseidon.hash(packedCt);

  return { depositPlain, ephemeralSk, commitment, proof };
}
