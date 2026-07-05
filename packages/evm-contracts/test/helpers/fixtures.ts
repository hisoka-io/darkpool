import { ethers } from "hardhat";
import { ContractRunner } from "ethers";
import {
  DarkPool,
  DarkPool__factory,
  MockERC20,
  MockERC20__factory,
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
  NoteV2,
  pubkeyOwner,
  publicKey,
  isEvenY,
} from "@hisoka/wallets";
import { Base8, mulPointEscalar, Point, subOrder } from "@zk-kit/baby-jubjub";

export const COMPLIANCE_SK = 987654321n;
export const COMPLIANCE_PK: Point<bigint> = mulPointEscalar(
  Base8,
  COMPLIANCE_SK,
);

const NOTE_VERSION = toFr(1n);
const NOTE_TYPE_STANDARD = toFr(0n);
const ZERO = toFr(0n);

/** A note-format v2 note plus every field a test needs to submit it and later spend it. */
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
  return toBjjScalar(await Kdf.derive("hisoka.test.spend", addressToFr(address)));
}

async function finishNote(
  eph: Fr,
  value: bigint,
  owner: Fr,
  assetFr: Fr,
  spendScalar: Fr,
): Promise<BuiltNote> {
  const cek = deriveCek(eph, COMPLIANCE_PK);
  const psi = await computePsi(cek);
  const noteV2: NoteV2 = {
    noteVersion: NOTE_VERSION,
    assetId: assetFr,
    noteType: NOTE_TYPE_STANDARD,
    conditionsHash: ZERO,
    value,
    owner,
    psi,
    parents: ZERO,
  };
  const commitment = await leaf(noteV2);
  const ephPub = publicKey(eph);
  const note: NoteInput = {
    noteVersion: NOTE_VERSION,
    assetId: assetFr,
    noteType: NOTE_TYPE_STANDARD,
    conditionsHash: ZERO,
    value: toFr(value),
    owner,
    psi,
    parents: ZERO,
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
): Promise<BuiltNote> {
  const owner = await pubkeyOwner(publicKey(spendScalar));
  return finishNote(eph, value, owner, assetFr, spendScalar);
}

/** Mint an incoming memo note to a recipient: owner binds to in_pub_j, cek_wrap wraps the content key to
 * the recipient, discovery tag is in_pub_j.x. `inKey` is only meaningful to the recipient (spend scalar). */
export async function mintIncomingNote(
  eph: Fr,
  value: bigint,
  inPub: Point<bigint>,
  inKey: Fr,
  assetFr: Fr,
): Promise<BuiltNote> {
  const owner = await pubkeyOwner(inPub);
  const built = await finishNote(eph, value, owner, assetFr, inKey);
  built.inPub = inPub;
  built.cekWrap = await wrapCek(built.cek, eph, inPub);
  built.tag = new Fr(inPub[0]);
  return built;
}

/** Prover NoteInput view of a stored NoteV2 (value bigint -> Fr). */
export function noteToInput(note: NoteV2): NoteInput {
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
  const GasVerifier = await deployVerifier(
    "contracts/verifiers/GasPaymentVerifier.sol",
  );

  const MockRegistryFactory =
    await ethers.getContractFactory("MockNoxRegistry");
  const mockNoxRegistry = await MockRegistryFactory.deploy();
  const RewardPoolFactory = await ethers.getContractFactory("NoxRewardPool");
  const rewardPool = await RewardPoolFactory.deploy(
    deployer.address,
    await mockNoxRegistry.getAddress(),
  );

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

  const DarkPoolFactory = (await ethers.getContractFactory("DarkPool", {
    libraries: { Poseidon2: await poseidon2Lib.getAddress() },
  })) as unknown as DarkPool__factory;

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
