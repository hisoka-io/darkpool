import { ethers, upgrades } from "hardhat";
import { ContractRunner, keccak256, toUtf8Bytes } from "ethers";
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
  toReducedFr,
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
  Poseidon,
} from "@hisoka/wallets";
import { Base8, mulPointEscalar, Point, subOrder } from "@zk-kit/baby-jubjub";

export const COMPLIANCE_SK = 987654321n;
export const COMPLIANCE_PK: Point<bigint> = mulPointEscalar(
  Base8,
  COMPLIANCE_SK,
);

// Hardhat's in-process network chain id; the DarkPool binds its tree genesis leaf to block.chainid.
export const HARDHAT_CHAIN_ID = 31337n;

/** Byte-identical to DarkPool._genesisLeaf(): Poseidon2(keccak256("hisoka.darkpool.genesis") reduced mod the
 *  BN254 scalar field, chainId). Seeds a test tree's reserved index-0 sentinel so its roots match the pool. */
export async function genesisLeaf(
  chainId: bigint = HARDHAT_CHAIN_ID,
): Promise<Fr> {
  const domainTag = BigInt(keccak256(toUtf8Bytes("hisoka.darkpool.genesis")));
  return Poseidon.hash([toReducedFr(domainTag), toFr(chainId)]);
}

/** A LeanIMT seeded with the chain-specific genesis leaf at index 0, mirroring the contract. Real notes begin
 *  at index 1, so a deposit's on-chain leaf index equals its index in this tree. */
export async function newSeededTree(
  chainId: bigint = HARDHAT_CHAIN_ID,
): Promise<LeanIMT> {
  const tree = new LeanIMT(32);
  await tree.insert(await genesisLeaf(chainId));
  return tree;
}

const NOTE_VERSION = toFr(1n);
const NOTE_TYPE_STANDARD = toFr(0n);
const ZERO = toFr(0n);

/** A note plus every field a test needs to submit it and later spend it. */
export interface BuiltNote {
  note: NoteInput;
  commitment: Fr;
  eph: Fr;
  ephPub: Point<bigint>;
  cek: Fr;
  psi: Fr;
  spendScalar: Fr;
  tag: Fr;
  inPub?: Point<bigint>;
  cekWrap?: Fr;
}

/** Next even-y BabyJubJub subgroup scalar at or after `seed`: a self note's discovery tag is eph_pub.x,
 * which is only injective when y is even (matches the in-circuit even-y assertion). */
export function evenYEphemeral(seed: bigint): Fr {
  let s = ((seed % subOrder) + subOrder) % subOrder;
  if (s === 0n) s = 1n;
  for (let i = 0n; i < subOrder; i++) {
    if (isEvenY(mulPointEscalar(Base8, s))) return new Fr(s);
    s += 1n;
    if (s >= subOrder) s = 1n;
  }
  throw new Error("no even-y scalar in subgroup");
}

/** A subgroup scalar with no even-y constraint (memo ephemerals need not be even-y; the memo tag is
 * the recipient's in_pub_j.x, not the ephemeral's). */
export function subgroupScalar(seed: bigint): Fr {
  let s = ((seed % subOrder) + subOrder) % subOrder;
  if (s === 0n) s = 1n;
  return new Fr(s);
}

/** Deterministic per-user spend scalar so a test deposit stays spendable: owner == Poseidon2(scalar*Base8). */
export async function userSpendScalar(address: string): Promise<Fr> {
  return toBjjScalar(
    await Kdf.derive("hisoka.test.spend", addressToFr(address)),
  );
}

async function finishNote(
  eph: Fr,
  value: bigint,
  owner: Fr,
  assetFr: Fr,
  spendScalar: Fr,
  parents: Fr,
): Promise<BuiltNote> {
  const cek = deriveCek(eph, COMPLIANCE_PK);
  const psi = await computePsi(cek);
  const plaintextNote: Note = {
    noteVersion: NOTE_VERSION,
    assetId: assetFr,
    noteType: NOTE_TYPE_STANDARD,
    conditionsHash: ZERO,
    value,
    owner,
    psi,
    parents,
  };
  const commitment = await leaf(plaintextNote);
  const ephPub = publicKey(eph);
  const note: NoteInput = {
    noteVersion: NOTE_VERSION,
    assetId: assetFr,
    noteType: NOTE_TYPE_STANDARD,
    conditionsHash: ZERO,
    value: toFr(value),
    owner,
    psi,
    parents,
  };
  return {
    note,
    commitment,
    eph,
    ephPub,
    cek,
    psi,
    spendScalar,
    tag: new Fr(ephPub[0]),
  };
}

/** Mint a self note (deposit / change / split-out / join-out / gas-change / claim-out): owner binds to
 * `spendScalar`, discovery tag is the even-y eph_pub.x. */
export async function mintSelfNote(
  eph: Fr,
  value: bigint,
  spendScalar: Fr,
  assetFr: Fr,
  parents: Fr = ZERO,
): Promise<BuiltNote> {
  const owner = await pubkeyOwner(publicKey(spendScalar));
  return finishNote(eph, value, owner, assetFr, spendScalar, parents);
}

/** Mint an incoming memo note to a recipient: owner binds to in_pub_j, cek_wrap wraps the content key to
 * the recipient, discovery tag is in_pub_j.x. `inKey` is only meaningful to the recipient (spend scalar). */
export async function mintIncomingNote(
  eph: Fr,
  value: bigint,
  inPub: Point<bigint>,
  inKey: Fr,
  assetFr: Fr,
  parents: Fr = ZERO,
): Promise<BuiltNote> {
  const owner = await pubkeyOwner(inPub);
  const built = await finishNote(eph, value, owner, assetFr, inKey, parents);
  built.inPub = inPub;
  built.cekWrap = await wrapCek(built.cek, eph, inPub);
  built.tag = new Fr(inPub[0]);
  return built;
}

/** Prover NoteInput view of a stored Note (value bigint -> Fr). */
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

  // The ZK-on Honk verifier externalizes ZKTranscriptLib to stay under EIP-170. The library body is
  // byte-identical across all 10 verifiers, so one deployment links into every verifier.
  const zkTranscriptLib = await (
    await ethers.getContractFactory(
      "contracts/verifiers/DepositVerifier.sol:ZKTranscriptLib",
    )
  ).deploy();
  const zkTranscriptAddr = await zkTranscriptLib.getAddress();

  const deployVerifier = async (contractPath: string) => {
    const Verifier = await (
      await ethers.getContractFactory(`${contractPath}:HonkVerifier`, {
        libraries: { [`${contractPath}:ZKTranscriptLib`]: zkTranscriptAddr },
      })
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

/** Deposit `amount` of `token` for `user` and return the minted self note (spendable via built.spendScalar). */
export async function makeDeposit(
  darkPool: DarkPool,
  token: MockERC20,
  user: ContractRunner & { address: string },
  amount: bigint,
  eph?: Fr,
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
