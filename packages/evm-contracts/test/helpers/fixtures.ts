import { ethers, upgrades } from "hardhat";
import { ContractRunner } from "ethers";
import {
  DarkPool,
  MockERC20,
  MockERC20__factory,
  NoxRewardPool,
} from "../../typechain-types";
import { proveDeposit, NoteInput } from "@hisoka/prover";
import {
  Fr,
  toFr,
  addressToFr,
  Kdf,
  toBjjScalar,
  deriveCek,
  wrapCek,
  computePsi,
  leaf,
  Note,
  pubkeyOwner,
  publicKey,
  isEvenY,
  LeanIMT,
  genesisLeaf as walletsGenesisLeaf,
  newSeededTree as walletsNewSeededTree,
  mintIncomingNote as walletsMintIncomingNote,
} from "@hisoka/wallets";
import { mintSelfNote as walletsMintSelfNote } from "@hisoka/wallets/unsafe-sim";
import type { MintedNote } from "@hisoka/wallets";
import type { DerivedEph } from "@hisoka/wallets";
import { Base8, mulPointEscalar, Point, subOrder } from "@zk-kit/baby-jubjub";

export const COMPLIANCE_SK = 987654321n;
export const COMPLIANCE_PK: Point<bigint> = mulPointEscalar(
  Base8,
  COMPLIANCE_SK,
);

// Hardhat's in-process network chain id; the DarkPool binds its tree genesis leaf to block.chainid.
export const HARDHAT_CHAIN_ID = 31337n;

/** The hardhat chain id default lives HERE, in the test fixture. `genesisLeaf` in @hisoka/wallets requires
 *  the argument, because a wrong chain id silently produces a tree the pool disagrees with. */
export async function genesisLeaf(
  chainId: bigint = HARDHAT_CHAIN_ID,
): Promise<Fr> {
  return walletsGenesisLeaf(chainId);
}

export async function newSeededTree(
  chainId: bigint = HARDHAT_CHAIN_ID,
): Promise<LeanIMT> {
  return walletsNewSeededTree(chainId);
}

const NOTE_VERSION = toFr(1n);
const NOTE_TYPE_MULTISIG = toFr(1n);
const ZERO = toFr(0n);

/** The promoted shape. Kept as a local alias so the ~8 existing referents do not all have to move. */
export type BuiltNote = MintedNote;

/**
 * Next even-y BabyJubJub subgroup scalar at or after `seed`: the tag eph_pub.x is only injective when y is
 * even.
 *
 * Returns `DerivedEph` because on-chain tests construct ephemerals from a seed rather than from a wallet
 * key schedule. This is THE test-fixture boundary and the only place that assertion is made: production
 * code must obtain a self-family ephemeral from the counter-backed derivation, because the discovery tag
 * is the ephemeral's own public x and a sampled scalar yields a note no scanner can find.
 */
export function evenYEphemeral(seed: bigint): DerivedEph {
  let s = ((seed % subOrder) + subOrder) % subOrder;
  if (s === 0n) s = 1n;
  for (let i = 0n; i < subOrder; i++) {
    if (isEvenY(mulPointEscalar(Base8, s))) return new Fr(s) as DerivedEph;
    s += 1n;
    if (s >= subOrder) s = 1n;
  }
  throw new Error("no even-y scalar in subgroup");
}

export function subgroupScalar(seed: bigint): Fr {
  let s = ((seed % subOrder) + subOrder) % subOrder;
  if (s === 0n) s = 1n;
  return new Fr(s) as DerivedEph;
}

/** Deterministic per-user spend scalar so a test deposit stays spendable: owner == Poseidon2(scalar*Base8). */
export async function userSpendScalar(address: string): Promise<Fr> {
  return toBjjScalar(
    await Kdf.derive("hisoka.test.spend", addressToFr(address)),
  );
}

/** Test-fixture wrappers: the promoted versions take the compliance key explicitly, tests always use ours. */
export async function mintSelfNote(
  eph: DerivedEph,
  value: bigint,
  spendScalar: Fr,
  assetFr: Fr,
  parents: Fr = ZERO,
): Promise<BuiltNote> {
  return walletsMintSelfNote(
    eph,
    value,
    spendScalar,
    assetFr,
    COMPLIANCE_PK,
    parents,
  );
}

export async function mintIncomingNote(
  eph: Fr,
  value: bigint,
  inPub: Point<bigint>,
  inKey: Fr,
  assetFr: Fr,
  parents: Fr = ZERO,
): Promise<BuiltNote> {
  return walletsMintIncomingNote(
    eph,
    value,
    inPub,
    inKey,
    assetFr,
    COMPLIANCE_PK,
    parents,
  );
}

/** A MULTISIG memo: owner binds the account gpk (spend authority) while discovery and decryption bind the view key V, which gpk's t-of-n scalar cannot do. */
export async function mintIncomingMultisigNote(
  eph: Fr,
  value: bigint,
  gpk: Point<bigint>,
  v: Fr,
  assetFr: Fr,
  parents: Fr = ZERO,
): Promise<BuiltNote> {
  const viewPub = publicKey(v);
  const owner = await pubkeyOwner(gpk);
  const cek = deriveCek(eph, COMPLIANCE_PK);
  const psi = await computePsi(cek);
  const plaintextNote: Note = {
    noteVersion: NOTE_VERSION,
    assetId: assetFr,
    noteType: NOTE_TYPE_MULTISIG,
    conditionsHash: ZERO,
    value,
    owner,
    psi,
    parents,
  };
  const commitment = await leaf(plaintextNote);
  const ephPub = publicKey(eph);
  return {
    note: {
      noteVersion: NOTE_VERSION,
      assetId: assetFr,
      noteType: NOTE_TYPE_MULTISIG,
      conditionsHash: ZERO,
      value: toFr(value),
      owner,
      psi,
      parents,
    },
    commitment,
    eph: eph as DerivedEph,
    ephPub,
    cek,
    psi,
    spendScalar: v,
    inPub: viewPub,
    cekWrap: await wrapCek(cek, eph, viewPub),
    tag: new Fr(viewPub[0]),
  };
}

export function noteToInput(note: Note): NoteInput {
  return {
    noteVersion: note.noteVersion,
    assetId: note.assetId,
    noteType: note.noteType,
    conditionsHash: note.conditionsHash,
    value: new Fr(note.value),
    owner: note.owner,
    psi: note.psi,
    parents: note.parents,
  };
}

export async function deployDarkPoolFixture() {
  const [deployer, alice, bob, charlie, attacker, compliance, relayer] =
    await ethers.getSigners();

  const Poseidon2Factory = await ethers.getContractFactory("Poseidon2");
  const poseidon2Lib = await Poseidon2Factory.deploy();

  // bb 5.0 --optimized verifiers are self-contained monolithic contracts that fit EIP-170 without a linked lib.
  const deployVerifier = async (contractPath: string) => {
    const Verifier = await (
      await ethers.getContractFactory(`${contractPath}:HonkVerifier`)
    ).deploy();
    return Verifier;
  };

  const DepVerifier = await deployVerifier(
    "contracts/verifiers/DepositVerifier.sol",
  );
  const WdwVerifier = await deployVerifier(
    "contracts/verifiers/WithdrawVerifier.sol",
  );
  const TrfVerifier = await deployVerifier(
    "contracts/verifiers/TransferVerifier.sol",
  );
  const JoinVerifier = await deployVerifier(
    "contracts/verifiers/JoinVerifier.sol",
  );
  const SplitVerifier = await deployVerifier(
    "contracts/verifiers/SplitVerifier.sol",
  );
  const PublicClaimVerifier = await deployVerifier(
    "contracts/verifiers/PublicClaimVerifier.sol",
  );
  const WdwMultisigVerifier = await deployVerifier(
    "contracts/verifiers/WithdrawMultisigVerifier.sol",
  );
  const TrfMultisigVerifier = await deployVerifier(
    "contracts/verifiers/TransferMultisigVerifier.sol",
  );
  const SplitMultisigVerifier = await deployVerifier(
    "contracts/verifiers/SplitMultisigVerifier.sol",
  );
  const JoinMultisigVerifier = await deployVerifier(
    "contracts/verifiers/JoinMultisigVerifier.sol",
  );
  const KageVerifier = await deployVerifier(
    "contracts/verifiers/KageVerifier.sol",
  );

  const MockRegistryFactory =
    await ethers.getContractFactory("MockNoxRegistry");
  const mockNoxRegistry = await MockRegistryFactory.deploy();

  const RewardPoolFactory = await ethers.getContractFactory("NoxRewardPool");
  const rewardPool = (await upgrades.deployProxy(
    RewardPoolFactory,
    [
      [
        0,
        deployer.address,
        await mockNoxRegistry.getAddress(),
        deployer.address,
        deployer.address,
        deployer.address,
      ],
    ],
    { kind: "uups" },
  )) as unknown as NoxRewardPool;
  await rewardPool.waitForDeployment();

  const token = await (
    (await ethers.getContractFactory(
      "MockERC20",
    )) as unknown as MockERC20__factory
  ).deploy("Mock", "MCK", 18);
  await rewardPool.setAssetStatus(await token.getAddress(), true);

  const initialBalance = ethers.parseEther("10000");
  await token.mint(alice.address, initialBalance);
  await token.mint(bob.address, initialBalance);
  await token.mint(charlie.address, initialBalance);
  await token.mint(attacker.address, initialBalance);

  const DarkPoolFactory = await ethers.getContractFactory("DarkPool", {
    libraries: { Poseidon2: await poseidon2Lib.getAddress() },
  });

  const darkPool = (await upgrades.deployProxy(
    DarkPoolFactory,
    [
      [
        await DepVerifier.getAddress(),
        await WdwVerifier.getAddress(),
        await TrfVerifier.getAddress(),
        await JoinVerifier.getAddress(),
        await SplitVerifier.getAddress(),
        await PublicClaimVerifier.getAddress(),
        await WdwMultisigVerifier.getAddress(),
        await TrfMultisigVerifier.getAddress(),
        await SplitMultisigVerifier.getAddress(),
        await JoinMultisigVerifier.getAddress(),
        await KageVerifier.getAddress(),
        COMPLIANCE_PK[0],
        COMPLIANCE_PK[1],
        0,
        deployer.address,
        deployer.address,
        deployer.address,
      ],
    ],
    { kind: "uups", unsafeAllow: ["external-library-linking"] },
  )) as unknown as DarkPool;
  await darkPool.waitForDeployment();

  return {
    darkPool,
    token,
    rewardPool,
    mockNoxRegistry,
    deployer,
    alice,
    bob,
    charlie,
    attacker,
    compliance,
    relayer,
  };
}

export async function makeDeposit(
  darkPool: DarkPool,
  token: MockERC20,
  user: ContractRunner & { address: string },
  amount: bigint,
  eph?: DerivedEph,
) {
  const assetFr = addressToFr(await token.getAddress());
  const spendScalar = await userSpendScalar(user.address);
  const ephemeral =
    eph ?? evenYEphemeral(ethers.toBigInt(ethers.randomBytes(16)));
  const built = await mintSelfNote(ephemeral, amount, spendScalar, assetFr);

  const proof = await proveDeposit({
    compliancePk: COMPLIANCE_PK,
    note: built.note,
    eph: ephemeral,
  });

  await token.connect(user).approve(await darkPool.getAddress(), amount);
  await darkPool.connect(user).deposit(proof.proof, proof.publicInputs);

  return { built, commitment: built.commitment, proof, spendScalar };
}
