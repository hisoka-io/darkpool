import { expect } from "chai";
import { readFileSync } from "fs";
import { resolve } from "path";
import { ethers, network, upgrades } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import type {
  ContractTransactionResponse,
  Interface,
  Log,
  LogDescription,
  TransactionReceipt,
} from "ethers";
import { Base8, mulPointEscalar } from "@zk-kit/baby-jubjub";
import {
  DarkPool__factory,
  IWithdrawRecipient__factory,
  type DarkPool,
  type MockERC20,
  type SettlementControllerHarness,
} from "../../typechain-types";
import {
  COMPLIANCE_PK,
  COMPLIANCE_SK,
  deployDarkPoolFixture,
  evenYEphemeral,
  makeDeposit,
  mintIncomingNote,
  mintSelfNote,
  newSeededTree,
} from "../helpers/fixtures";
import {
  NO_BOUND,
  deployGoldenSettlementFixture,
} from "../helpers/settlementFixtures";
import { revertData } from "../helpers/revertData";
import { KAGE_PROOF, KAGE_PUBLIC_INPUTS } from "../integration/kageGolden";
import { governanceDelays } from "../../scripts/deploy";
import {
  CIPHERTEXT_KEPT_INDICES,
  ENC_DOMAIN,
  Fr,
  HOWL_NOTE_LAYOUT_VERSION,
  LeanIMT,
  PARENTS_HIDDEN,
  PSI_DOMAIN,
  Poseidon,
  RECORD_KIND_SELF,
  TREE_DEPTH,
  addressToFr,
  computeNullifier,
  computePsi,
  demDecrypt,
  demEncrypt,
  genesisLeaf,
  isEvenY,
  leaf,
  packParents,
  pubkeyOwner,
  publicKey,
  publicMemoId,
  reconstructCiphertext,
  recoverEvenY,
  toFr,
  unwrapCek,
} from "@hisoka/wallets";
import { proveTransfer } from "@hisoka/prover";

// Everything a deployed pool's readers (wallets, discovery, adaptors, indexers) decode for the life of the proxy.
// A reader cannot be redeployed with the pool, so a change to any value below strands notes or log consumers
// with no ABI-level warning. Values are literals, never recomputed from the contract under test.

const BN254_FR =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const [CX, CY] = COMPLIANCE_PK;
const POOL_ABI: Interface = DarkPool__factory.createInterface();

type Param = readonly [name: string, type: string, indexed: boolean];
interface FrozenEvent {
  readonly signature: string;
  readonly topic0: string;
  readonly params: readonly Param[];
  readonly topics: number;
  readonly dataBytes: number;
}

const FROZEN_EVENTS: Readonly<Record<string, FrozenEvent>> = {
  NewNote: {
    signature: "NewNote(uint256,bytes32,uint256,bytes32[7])",
    topic0:
      "0xf908f59e72bf09167999004bbfe849fd507952d06581f7e70134588458700854",
    params: [
      ["leafIndex", "uint256", true],
      ["commitment", "bytes32", true],
      ["ephemeralPK_x", "uint256", false],
      ["packedCiphertext", "bytes32[7]", false],
    ],
    topics: 3,
    dataBytes: 256,
  },
  NewPrivateMemo: {
    signature:
      "NewPrivateMemo(uint256,bytes32,uint256,uint256,uint256,bytes32[7])",
    topic0:
      "0x7a202c1f6029a8f736ab7bb5da53a4930c10ccb35effa9881ece389ad9bd2544",
    params: [
      ["leafIndex", "uint256", true],
      ["commitment", "bytes32", true],
      ["tag", "uint256", true],
      ["ephemeralPK_x", "uint256", false],
      ["cekWrap", "uint256", false],
      ["packedCiphertext", "bytes32[7]", false],
    ],
    topics: 4,
    dataBytes: 288,
  },
  LeafInserted: {
    signature: "LeafInserted(uint256,bytes32,bytes32)",
    topic0:
      "0x2d3c13ae449947e04070bf2ac89327dc1fc56f31042172f3c9fdceb8f51c90e6",
    params: [
      ["leafIndex", "uint256", true],
      ["leaf", "bytes32", false],
      ["newRoot", "bytes32", false],
    ],
    topics: 2,
    dataBytes: 64,
  },
  RootSaved: {
    signature: "RootSaved(bytes32)",
    topic0:
      "0xa55369296f4adc70a8d99192608e0c4d18f10f343890264bc50b59981afdec51",
    params: [["root", "bytes32", true]],
    topics: 2,
    dataBytes: 0,
  },
  GenesisSeeded: {
    signature: "GenesisSeeded(uint256,bytes32)",
    topic0:
      "0x707c829c9689eb6b774ddf7479ad4c494581c7b5b36237f80738895c016166d9",
    params: [
      ["chainId", "uint256", true],
      ["genesisLeaf", "bytes32", false],
    ],
    topics: 2,
    dataBytes: 32,
  },
  NullifierSpent: {
    signature: "NullifierSpent(bytes32)",
    topic0:
      "0x2d8b76eb247945151bd870d531c84c5420f53e3cb9c0ab3b350f46bb09362096",
    params: [["nullifierHash", "bytes32", true]],
    topics: 2,
    dataBytes: 0,
  },
  ComplianceKeyRotated: {
    signature: "ComplianceKeyRotated(uint256,uint256,uint256,uint256)",
    topic0:
      "0xa9279e08847efe2bd488e211363a7bc5fd413e506b6a325134cec43f64946007",
    params: [
      ["oldVersion", "uint256", false],
      ["newVersion", "uint256", false],
      ["newX", "uint256", false],
      ["newY", "uint256", false],
    ],
    topics: 1,
    dataBytes: 128,
  },
  NewPublicMemo: {
    signature: "NewPublicMemo(bytes32,address,uint256,uint256,uint256)",
    topic0:
      "0x55ab54025db51da4c6f9511101ebf0e0f60cf2171427b607a142348656fe8898",
    params: [
      ["memoId", "bytes32", true],
      ["asset", "address", false],
      ["value", "uint256", false],
      ["timelock", "uint256", false],
      ["salt", "uint256", false],
    ],
    topics: 2,
    dataBytes: 128,
  },
  PublicMemoSpent: {
    signature: "PublicMemoSpent(bytes32)",
    topic0:
      "0x142b563796c862a1fb294596318cb4ce9492eed8f1b25bbf2ea2aa96d9f05bb3",
    params: [["memoId", "bytes32", true]],
    topics: 2,
    dataBytes: 0,
  },
  Withdrawal: {
    signature: "Withdrawal(bytes32,address,address)",
    topic0:
      "0x5d5a620a50bf9a970a972a9a4b82f1247b0a2902b92f8bfedfc88b284b043d55",
    params: [
      ["nullifierHash", "bytes32", true],
      ["recipient", "address", true],
      ["relayer", "address", false],
    ],
    topics: 3,
    dataBytes: 32,
  },
  Deposited: {
    signature: "Deposited(address,address,uint256)",
    topic0:
      "0x8752a472e571a816aea92eec8dae9baf628e840f4929fbcc2d155e6233ff68a7",
    params: [
      ["depositor", "address", true],
      ["asset", "address", true],
      ["value", "uint256", false],
    ],
    topics: 3,
    dataBytes: 32,
  },
  VerifierUpdated: {
    signature: "VerifierUpdated(uint256,address,address)",
    topic0:
      "0xc70de5941dadb2f76c3ca7256288c2ffc2c8ae6a3546b864767bf8bd552c51e6",
    params: [
      ["circuitId", "uint256", true],
      ["previousVerifier", "address", false],
      ["verifier", "address", false],
    ],
    topics: 2,
    dataBytes: 64,
  },
  Upgraded: {
    signature: "Upgraded(address)",
    topic0:
      "0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b",
    params: [["implementation", "address", true]],
    topics: 2,
    dataBytes: 0,
  },
  ModuleRegistered: {
    signature:
      "ModuleRegistered(address,address,uint8,uint8,uint8,uint32,uint32)",
    topic0:
      "0x5c47f58019b9098d4c20d89e980c53226528fa93211367760b9f96e88a566716",
    params: [
      ["controller", "address", true],
      ["verifier", "address", false],
      ["nullifierCount", "uint8", false],
      ["outputCount", "uint8", false],
      ["extraCount", "uint8", false],
      ["maxPast", "uint32", false],
      ["maxFuture", "uint32", false],
    ],
    topics: 2,
    dataBytes: 192,
  },
  ModuleVerifierUpdated: {
    signature: "ModuleVerifierUpdated(address,address)",
    topic0:
      "0xcb9f3a2d335c5789eba95d79cb4f8c77b5f9970a9a61fe06f2e7f00fd1662566",
    params: [
      ["controller", "address", true],
      ["verifier", "address", false],
    ],
    topics: 2,
    dataBytes: 32,
  },
  ModuleEnabled: {
    signature: "ModuleEnabled(address)",
    topic0:
      "0x7a77214430737f5a548efc743650795815091c4d522683f9665bdc753bdb8c16",
    params: [["controller", "address", true]],
    topics: 2,
    dataBytes: 0,
  },
  ModuleDisabled: {
    signature: "ModuleDisabled(address,address)",
    topic0:
      "0x857479d213c45c7f46523c3e64420c84d4dd0b6ec4d904484a2657a08ac6928c",
    params: [
      ["controller", "address", true],
      ["by", "address", false],
    ],
    topics: 2,
    dataBytes: 32,
  },
  ModuleSettled: {
    signature: "ModuleSettled(address,uint256,uint256)",
    topic0:
      "0x7947628c9927bb6a3255c925a7345a5b521f6caabbf137ad92cc9f126ace0ab5",
    params: [
      ["controller", "address", true],
      ["firstLeafIndex", "uint256", false],
      ["outputCount", "uint256", false],
    ],
    topics: 2,
    dataBytes: 64,
  },
};

// Inherited OpenZeppelin events; their layouts are OZ's and are not part of the pool's own surface.
const INHERITED_EVENTS = [
  "DefaultAdminDelayChangeCanceled",
  "DefaultAdminDelayChangeScheduled",
  "DefaultAdminTransferCanceled",
  "DefaultAdminTransferScheduled",
  "Initialized",
  "Paused",
  "RoleAdminChanged",
  "RoleGranted",
  "RoleRevoked",
  "Unpaused",
];

// Emitted by the Kage module contract inside a settle transaction, never by the pool.
const KAGE_SWAP_SETTLED_TOPIC0 =
  "0x5163ad1140bd384841080765da70d1379076d2cf40ce4228747391bae754ec7e";

const FROZEN_VIEWS: readonly (readonly [string, string, readonly string[]])[] =
  [
    ["getNextLeafIndex()", "0x50e9b925", ["uint256"]],
    ["getCurrentRoot()", "0x8270482d", ["bytes32"]],
    ["isKnownRoot(bytes32)", "0x6d9833e3", ["bool"]],
    ["isNullifierSpent(bytes32)", "0xd5a4e325", ["bool"]],
    ["complianceKey()", "0x3c07a672", ["uint256", "uint256", "uint256"]],
    ["isValidPublicMemo(bytes32)", "0xa9c7c11b", ["bool"]],
    ["isPublicMemoSpent(bytes32)", "0xec3a2609", ["bool"]],
    ["verifier(uint256)", "0x8d129178", ["address"]],
  ];

const FROZEN_ENTRYPOINTS: readonly (readonly [string, string])[] = [
  ["deposit(bytes,bytes32[])", "0x1338df64"],
  ["withdraw(bytes,bytes32[])", "0x67843a5b"],
  ["withdrawMultisig(bytes,bytes32[])", "0x46f9d744"],
  ["privateTransfer(bytes,bytes32[])", "0x18a43314"],
  ["transferMultisig(bytes,bytes32[])", "0x9f2c1c02"],
  ["join(bytes,bytes32[])", "0x8c776c70"],
  ["joinMultisig(bytes,bytes32[])", "0x84564271"],
  ["split(bytes,bytes32[])", "0x805648ee"],
  ["splitMultisig(bytes,bytes32[])", "0x8bbcbcf0"],
  ["publicClaim(bytes,bytes32[])", "0x4981154e"],
  ["settle(bytes,bytes32[])", "0x30333269"],
  [
    "publicTransfer(uint256,uint256,address,uint256,uint256,uint256)",
    "0xa38fc159",
  ],
  ["proxiableUUID()", "0x52d1902d"],
  ["upgradeToAndCall(address,bytes)", "0x4f1ef286"],
];

type ProofEntry =
  | "deposit"
  | "withdraw"
  | "withdrawMultisig"
  | "privateTransfer"
  | "transferMultisig"
  | "join"
  | "joinMultisig"
  | "split"
  | "splitMultisig"
  | "publicClaim"
  | "settle";

// Every state-changing external function, classified. A new one fails the completeness test until it is
// placed here: a new inserting entrypoint must be a deliberate change to the tree's writers.
const INSERTING: readonly ProofEntry[] = [
  "deposit",
  "withdraw",
  "withdrawMultisig",
  "privateTransfer",
  "transferMultisig",
  "join",
  "joinMultisig",
  "split",
  "splitMultisig",
  "publicClaim",
  "settle",
];
const GUARDED_NON_INSERTING = ["publicTransfer"];
const GOVERNANCE = [
  "acceptDefaultAdminTransfer",
  "beginDefaultAdminTransfer",
  "cancelDefaultAdminTransfer",
  "changeDefaultAdminDelay",
  "disableModule",
  "enableModule",
  "grantRole",
  "pause",
  "registerSettlementModule",
  "renounceRole",
  "revokeRole",
  "rollbackDefaultAdminDelay",
  "rotateComplianceKey",
  "setModuleVerifier",
  "setVerifier",
  "unpause",
  "upgradeToAndCall",
];
const INITIALIZER = ["initialize"];

const CIRCUITS: readonly {
  readonly id: number;
  readonly entry: Exclude<ProofEntry, "settle">;
  readonly inputs: number;
}[] = [
  { id: 0, entry: "deposit", inputs: 13 },
  { id: 1, entry: "withdraw", inputs: 17 },
  { id: 2, entry: "privateTransfer", inputs: 24 },
  { id: 3, entry: "join", inputs: 14 },
  { id: 4, entry: "split", inputs: 22 },
  { id: 5, entry: "publicClaim", inputs: 13 },
  { id: 6, entry: "withdrawMultisig", inputs: 17 },
  { id: 7, entry: "transferMultisig", inputs: 24 },
  { id: 8, entry: "splitMultisig", inputs: 22 },
  { id: 9, entry: "joinMultisig", inputs: 14 },
];
const CIRCUIT_COUNT = 10;

const NAMESPACES: Readonly<Record<string, string>> = {
  "hisoka.darkpool.tree":
    "0xbdd00c81e71bd165e3ff2099ca204334ffd58a8d7225a33b4761542b7a86e200",
  "hisoka.darkpool.nullifiers":
    "0xcb1d3464d85c75a880c4f95a3cfd4a5cd80b39c53862d4987d9ec14bb8af6700",
  "hisoka.darkpool.memos":
    "0x79ab9646d487c514cf680928de0290895c9ad6720afd1f87136f293781b7ea00",
  "hisoka.darkpool.verifiers":
    "0x204927e2223572a19571462c2dfb374afbbdb39e695632d6477721409dfb0b00",
  "hisoka.darkpool.compliance":
    "0x4c6336ddd730b3b6886dcf6c397e5676dac845842540c4592f4e52cea8e9ae00",
  "hisoka.darkpool.settlement":
    "0x75aee5824eaef0474f0a9f0cefdca7b78967e2ca8426d4fe1fe0dd6f6af34700",
  "openzeppelin.storage.ReentrancyGuard":
    "0x9b779b17422d0df92223018b32b4d1fa46e071723d6817e2486d003becc55f00",
};

const GENESIS_DOMAIN_RAW =
  "0x6f589cff5af0e1f1a8c131de44ae33b9d15c1fc027f61483523c246d368cc35d";
const GENESIS_DOMAIN_REDUCED =
  "0x0e900019988da19e3820a67141ab82ff80f44f2f34833360ca783945568cc35b";
const GENESIS: Readonly<Record<string, string>> = {
  "31337": "0x12f144d31019d46ff993f3fe3b8a001a0d606ea4b1140525ed615a4402066372",
  "421614":
    "0x27e6bc112a1c2e3ac8ea6a82b2522a3222d82f40839dd22fe95995e0cd8c4c41",
  "1": "0x194a2f3436b7ba4de9a9fac375d33f871ba6fffd66080280d5c523de754c8176",
};

// Roots of the chain-31337 tree after leaves 1..5 follow genesis (TS LeanIMT, depth 32).
const ROOTS_AFTER_LEAVES_1_TO_5 = [
  "0x142e0d5149c9fc30c4ed24df58fb1f8436dd7301cd8d36e76a186ea6ef0ae336",
  "0x004bbcaadb7ce7e07fcf2a42eb684676e2e31b087d4d1be9de35b548d70d0960",
  "0x2657da26d13a754a0536bfa915d5f5fe6357c146ca5dd584a27b526ca56327b8",
  "0x1a932f8b522ab3b775775649ba36153345c5925898080899644d0a3946a3baf3",
  "0x25634a4969d5037e1bfce8a4295ce02e77dcb5cd344c684ce9516c2771031090",
];

const ROOT_HISTORY_INSERTS = 300;

const ERC1967_IMPLEMENTATION_SLOT =
  "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
const REENTRANT_CALL_SELECTOR = "0x3ee5aeb5";
const ACCEPT_WITHDRAW_SELECTOR = "0x35307b63";

const w = (v: bigint): string => ethers.zeroPadValue(ethers.toBeHex(v), 32);
const addrWord = (a: string): string => ethers.zeroPadValue(a, 32);
const erc7201 = (ns: string): string =>
  ethers.toBeHex(
    BigInt(
      ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["uint256"],
          [BigInt(ethers.id(ns)) - 1n],
        ),
      ),
    ) & ~0xffn,
    32,
  );
const mappingSlot = (keyType: string, key: unknown, base: string): string =>
  ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode([keyType, "uint256"], [key, base]),
  );
const offsetSlot = (base: string, by: bigint): string =>
  ethers.toBeHex(BigInt(base) + by, 32);

async function storageWord(addr: string, slot: string): Promise<bigint> {
  return BigInt(await ethers.provider.getStorage(addr, slot));
}

async function setCode(addr: string, code: string): Promise<void> {
  await network.provider.send("hardhat_setCode", [addr, code]);
}

async function mined(
  tx: Promise<ContractTransactionResponse>,
): Promise<TransactionReceipt> {
  const receipt = await (await tx).wait();
  if (receipt === null) throw new Error("transaction was not mined");
  return receipt;
}

async function deployPinnedPool() {
  const [admin, pauser, upgrader, user, outsider] = await ethers.getSigners();
  const poseidon = await (
    await ethers.getContractFactory("Poseidon2")
  ).deploy();
  const poseidonAddr = await poseidon.getAddress();
  const stubFactory = await ethers.getContractFactory("StubVerifier");
  const stubs: string[] = [];
  for (let i = 0; i < CIRCUIT_COUNT; i++) {
    stubs.push(await (await stubFactory.deploy()).getAddress());
  }
  const rejecting = await (
    await (await ethers.getContractFactory("FalseVerifier")).deploy()
  ).getAddress();
  const factory = await ethers.getContractFactory("DarkPool", {
    libraries: { Poseidon2: poseidonAddr },
  });
  const proxy = await upgrades.deployProxy(
    factory,
    [[...stubs, CX, CY, 0, admin.address, pauser.address, upgrader.address]],
    {
      kind: "uups",
      initializer: "initialize",
      unsafeAllow: ["external-library-linking"],
    },
  );
  await proxy.waitForDeployment();
  const deployTx = proxy.deploymentTransaction();
  if (deployTx === null) throw new Error("proxy deployment has no transaction");
  const initReceipt = await deployTx.wait();
  if (initReceipt === null) throw new Error("proxy deployment was not mined");
  const poolAddr = await proxy.getAddress();
  const pool = DarkPool__factory.connect(poolAddr, user);

  const token = (await (
    await ethers.getContractFactory("MockERC20")
  ).deploy("Pin", "PIN", 18)) as unknown as MockERC20;
  await token.mint(user.address, 10n ** 30n);
  await token.connect(user).approve(poolAddr, ethers.MaxUint256);

  const controller = (await (
    await ethers.getContractFactory("SettlementControllerHarness")
  ).deploy(poolAddr)) as unknown as SettlementControllerHarness;
  const moduleVerifier = await (await stubFactory.deploy()).getAddress();
  await mined(
    pool
      .connect(upgrader)
      .registerSettlementModule(
        await controller.getAddress(),
        moduleVerifier,
        2,
        4,
        0,
        NO_BOUND,
        NO_BOUND,
      ),
  );

  return {
    pool,
    poolAddr,
    implAddr: await upgrades.erc1967.getImplementationAddress(poolAddr),
    poseidonAddr,
    stubs,
    rejecting,
    moduleVerifier,
    token,
    controller,
    admin,
    pauser,
    upgrader,
    user,
    outsider,
    initReceipt,
  };
}

type PinnedPool = Awaited<ReturnType<typeof deployPinnedPool>>;

interface Insert {
  readonly leaf: number;
  readonly eph: number;
  readonly ct: number;
  readonly memo: boolean;
}
interface Vector {
  readonly entry: ProofEntry;
  readonly pi: string[];
  readonly inserts: readonly Insert[];
  readonly nullifiers: readonly number[];
}

const note = (leafPos: number, ephPos: number, ctPos: number): Insert => ({
  leaf: leafPos,
  eph: ephPos,
  ct: ctPos,
  memo: false,
});

// Shape-valid public inputs under an accept-all verifier: every word distinct and canonical, so a copy from
// the wrong offset shows up as a wrong value rather than an equal one.
let wordCounter = 0x1000n;
function fresh(n: number): string[] {
  return Array.from({ length: n }, () => w(wordCounter++));
}

interface VectorContext {
  readonly root: string;
  readonly asset: string;
  readonly recipient: string;
  readonly memoId?: string;
  readonly timestamp: bigint;
}

function vectorFor(entry: ProofEntry, ctx: VectorContext): Vector {
  switch (entry) {
    case "deposit": {
      const pi = fresh(13);
      pi[0] = w(CX);
      pi[1] = w(CY);
      pi[4] = w(1n);
      pi[5] = addrWord(ctx.asset);
      return { entry, pi, inserts: [note(2, 3, 6)], nullifiers: [] };
    }
    case "withdraw":
    case "withdrawMultisig": {
      const pi = fresh(17);
      pi[0] = w(0n);
      pi[1] = addrWord(ctx.recipient);
      pi[3] = w(CX);
      pi[4] = w(CY);
      pi[6] = ctx.root;
      pi[7] = addrWord(ctx.asset);
      return { entry, pi, inserts: [note(8, 9, 10)], nullifiers: [5] };
    }
    case "privateTransfer":
    case "transferMultisig": {
      const pi = fresh(24);
      pi[0] = w(CX);
      pi[1] = w(CY);
      pi[3] = ctx.root;
      return {
        entry,
        pi,
        inserts: [{ leaf: 4, eph: 5, ct: 8, memo: true }, note(15, 16, 17)],
        nullifiers: [2],
      };
    }
    case "join":
    case "joinMultisig": {
      const pi = fresh(14);
      pi[0] = w(CX);
      pi[1] = w(CY);
      pi[4] = ctx.root;
      return { entry, pi, inserts: [note(5, 6, 7)], nullifiers: [2, 3] };
    }
    case "split":
    case "splitMultisig": {
      const pi = fresh(22);
      pi[0] = w(CX);
      pi[1] = w(CY);
      pi[3] = ctx.root;
      return {
        entry,
        pi,
        inserts: [note(4, 5, 6), note(13, 14, 15)],
        nullifiers: [2],
      };
    }
    case "publicClaim": {
      if (ctx.memoId === undefined)
        throw new Error("publicClaim vector needs a posted memo id");
      const pi = fresh(13);
      pi[0] = ctx.memoId;
      pi[1] = w(CX);
      pi[2] = w(CY);
      pi[3] = w(ctx.timestamp);
      return { entry, pi, inserts: [note(4, 5, 6)], nullifiers: [] };
    }
    case "settle": {
      const pi = fresh(42);
      pi[0] = w(CX);
      pi[1] = w(CY);
      pi[2] = w(ctx.timestamp);
      pi[5] = ctx.root;
      return {
        entry,
        pi,
        inserts: [6, 15, 24, 33].map((b) => note(b, b + 1, b + 2)),
        nullifiers: [3, 4],
      };
    }
  }
}

async function postMemo(f: PinnedPool, salt: bigint): Promise<string> {
  const [ox, oy] = mulPointEscalar(Base8, 7n);
  const receipt = await mined(
    f.pool.publicTransfer(ox, oy, await f.token.getAddress(), 5n, 0n, salt),
  );
  const posted = parsePool(f.pool, receipt.logs).find(
    (p) => p.name === "NewPublicMemo",
  );
  if (posted === undefined) throw new Error("publicTransfer posted no memo");
  return posted.args.memoId as string;
}

async function lastSpentNullifier(f: PinnedPool): Promise<string> {
  const spent = await f.pool.queryFilter(f.pool.filters.NullifierSpent());
  if (spent.length === 0) throw new Error("no nullifier spent yet");
  return spent[spent.length - 1].args.nullifierHash;
}

async function contextFor(f: PinnedPool, entry: ProofEntry) {
  const latest = await ethers.provider.getBlock("latest");
  if (latest === null) throw new Error("no latest block");
  return {
    root: await f.pool.getCurrentRoot(),
    asset: await f.token.getAddress(),
    recipient: f.outsider.address,
    memoId:
      entry === "publicClaim" ? await postMemo(f, wordCounter++) : undefined,
    timestamp: BigInt(latest.timestamp),
  };
}

function send(f: PinnedPool, v: Vector): Promise<ContractTransactionResponse> {
  const pool = f.pool;
  switch (v.entry) {
    case "deposit":
      return pool.deposit("0x", v.pi);
    case "withdraw":
      return pool.withdraw("0x", v.pi);
    case "withdrawMultisig":
      return pool.withdrawMultisig("0x", v.pi);
    case "privateTransfer":
      return pool.privateTransfer("0x", v.pi);
    case "transferMultisig":
      return pool.transferMultisig("0x", v.pi);
    case "join":
      return pool.join("0x", v.pi);
    case "joinMultisig":
      return pool.joinMultisig("0x", v.pi);
    case "split":
      return pool.split("0x", v.pi);
    case "splitMultisig":
      return pool.splitMultisig("0x", v.pi);
    case "publicClaim":
      return pool.publicClaim("0x", v.pi);
    case "settle":
      return f.controller.settle("0x", v.pi);
  }
}

function parsePool(pool: DarkPool, logs: readonly Log[]): LogDescription[] {
  const poolAddr = pool.target as string;
  return logs
    .filter((l) => l.address === poolAddr)
    .map((l) => {
      const parsed = pool.interface.parseLog(l);
      if (parsed === null)
        throw new Error(`unparseable pool log topic0 ${l.topics[0]}`);
      return parsed;
    });
}

function expectFrozenShape(l: Log): void {
  const entry = Object.entries(FROZEN_EVENTS).find(
    ([, e]) => e.topic0 === l.topics[0],
  );
  if (entry === undefined) return;
  const [name, e] = entry;
  expect(l.topics.length, `${name} topic count`).to.equal(e.topics);
  expect(ethers.dataLength(l.data), `${name} data bytes`).to.equal(e.dataBytes);
}

const TRIPLE_NOTE = ["RootSaved", "LeafInserted", "NewNote"];
const TRIPLE_MEMO = ["RootSaved", "LeafInserted", "NewPrivateMemo"];
const EXPECTED_LOGS: Readonly<Record<ProofEntry, readonly string[]>> = {
  deposit: ["Deposited", ...TRIPLE_NOTE],
  withdraw: ["NullifierSpent", ...TRIPLE_NOTE, "Withdrawal"],
  withdrawMultisig: ["NullifierSpent", ...TRIPLE_NOTE, "Withdrawal"],
  privateTransfer: ["NullifierSpent", ...TRIPLE_MEMO, ...TRIPLE_NOTE],
  transferMultisig: ["NullifierSpent", ...TRIPLE_MEMO, ...TRIPLE_NOTE],
  join: ["NullifierSpent", "NullifierSpent", ...TRIPLE_NOTE],
  joinMultisig: ["NullifierSpent", "NullifierSpent", ...TRIPLE_NOTE],
  split: ["NullifierSpent", ...TRIPLE_NOTE, ...TRIPLE_NOTE],
  splitMultisig: ["NullifierSpent", ...TRIPLE_NOTE, ...TRIPLE_NOTE],
  publicClaim: ["PublicMemoSpent", ...TRIPLE_NOTE],
  settle: [
    "NullifierSpent",
    "NullifierSpent",
    ...TRIPLE_NOTE,
    ...TRIPLE_NOTE,
    ...TRIPLE_NOTE,
    ...TRIPLE_NOTE,
    "ModuleSettled",
  ],
};

/** Runs one stub-verified entrypoint and pins its log group: order, adjacency, and the values each log carries. */
async function runAndPinLogs(f: PinnedPool, entry: ProofEntry): Promise<void> {
  const v = vectorFor(entry, await contextFor(f, entry));
  const firstIndex = await f.pool.getNextLeafIndex();
  const receipt = await mined(send(f, v));
  const raw = receipt.logs.filter((l) => l.address === f.poolAddr);
  raw.forEach(expectFrozenShape);
  const parsed = parsePool(f.pool, receipt.logs);
  expect(
    parsed.map((p) => p.name),
    `${entry} log order`,
  ).to.deep.equal(EXPECTED_LOGS[entry]);

  const spent = parsed.filter((p) => p.name === "NullifierSpent");
  expect(spent.map((p) => p.args.nullifierHash)).to.deep.equal(
    v.nullifiers.map((i) => v.pi[i]),
  );

  const starts = parsed.flatMap((p, i) => (p.name === "RootSaved" ? [i] : []));
  expect(starts.length, `${entry} insert count`).to.equal(v.inserts.length);
  v.inserts.forEach((ins, j) => {
    const at = starts[j];
    const [saved, inserted, minted] = [
      parsed[at],
      parsed[at + 1],
      parsed[at + 2],
    ];
    expect(raw[at + 1].index, "LeafInserted follows RootSaved").to.equal(
      raw[at].index + 1,
    );
    expect(raw[at + 2].index, "note event follows LeafInserted").to.equal(
      raw[at].index + 2,
    );
    const leafIndex = firstIndex + BigInt(j);
    expect(inserted.args.leafIndex).to.equal(leafIndex);
    expect(inserted.args.leaf).to.equal(v.pi[ins.leaf]);
    expect(inserted.args.newRoot).to.equal(saved.args.root);
    expect(minted.args.leafIndex).to.equal(leafIndex);
    expect(minted.args.commitment).to.equal(v.pi[ins.leaf]);
    if (ins.memo) {
      expect(minted.args.ephemeralPK_x).to.equal(BigInt(v.pi[ins.leaf + 1]));
      expect(minted.args.tag).to.equal(BigInt(v.pi[ins.leaf + 2]));
      expect(minted.args.cekWrap).to.equal(BigInt(v.pi[ins.leaf + 3]));
      expect([...minted.args.packedCiphertext]).to.deep.equal(
        v.pi.slice(ins.leaf + 4, ins.leaf + 11),
      );
    } else {
      expect(minted.args.ephemeralPK_x).to.equal(BigInt(v.pi[ins.eph]));
      expect([...minted.args.packedCiphertext]).to.deep.equal(
        v.pi.slice(ins.ct, ins.ct + 7),
      );
    }
  });
  const lastRoot = parsed[starts[starts.length - 1]].args.root as string;
  expect(await f.pool.getCurrentRoot()).to.equal(lastRoot);
  if (entry === "settle") {
    const settled = parsed[parsed.length - 1];
    expect(settled.args.controller).to.equal(await f.controller.getAddress());
    expect(settled.args.firstLeafIndex).to.equal(firstIndex);
    expect(settled.args.outputCount).to.equal(BigInt(v.inserts.length));
  }
}

// Runtime bytecode of a token whose every call except balanceOf re-enters `target` with `inner` and reverts
// with the inner call's revert data, or with INNER_SUCCEEDED if the inner call did not revert.
const INNER_SUCCEEDED = "0x7dad6ab5";
function reentrantTokenCode(target: string, inner: string): string {
  const payload = ethers.getBytes(inner);
  const len = payload.length.toString(16).padStart(4, "0");
  const prefix = [
    "600035", // calldataload(0)
    "60e01c", // >> 224
    "6370a08231", // balanceOf selector
    "14", // eq
    "610057", // push balanceOf branch
    "57", // jumpi
    `61${len}`,
    "610062", // payload offset
    "6000",
    "39", // codecopy(0, payload, len)
    "6000",
    "6000",
    `61${len}`,
    "6000",
    "6000",
    `73${target.slice(2).toLowerCase()}`,
    "5a",
    "f1", // call(gas, target, 0, 0, len, 0, 0)
    "3d60006000" + "3e", // returndatacopy(0, 0, returndatasize)
    "610049",
    "57", // jumpi to success branch
    "3d6000fd", // revert(0, returndatasize)
    "5b", // 0x49: inner call succeeded
    `63${INNER_SUCCEEDED.slice(2)}`,
    "600052",
    "6004601cfd",
    "5b", // 0x57: balanceOf returns 0
    "6000600052",
    "60206000f3",
  ].join("");
  if (prefix.length / 2 !== 0x62)
    throw new Error(`reentrant token prefix is ${prefix.length / 2} bytes`);
  return "0x" + prefix + ethers.hexlify(payload).slice(2);
}

const REENTRANT_TOKEN = "0x00000000000000000000000000000000000e7700";

async function outerDepositOfReentrantToken(
  f: PinnedPool,
): Promise<ContractTransactionResponse> {
  const outer = vectorFor("deposit", {
    root: await f.pool.getCurrentRoot(),
    asset: REENTRANT_TOKEN,
    recipient: f.outsider.address,
    timestamp: 0n,
  });
  return f.pool.deposit("0x", outer.pi);
}

async function innerCalldata(
  f: PinnedPool,
  entry: ProofEntry | "publicTransfer",
): Promise<string> {
  const iface: Interface = f.pool.interface;
  if (entry === "publicTransfer") {
    const [ox, oy] = mulPointEscalar(Base8, 7n);
    return iface.encodeFunctionData("publicTransfer", [
      ox,
      oy,
      await f.token.getAddress(),
      1n,
      0n,
      wordCounter++,
    ]);
  }
  const v = vectorFor(entry, await contextFor(f, entry));
  return iface.encodeFunctionData(entry, ["0x", v.pi]);
}

// @hisoka/wallet-runtime is an ES module and this suite loads under CommonJS, so its frozen ABI table is read
// from source. Every token inside the two literals must be accounted for, so a computed entry fails loudly.
function runtimeAbiTables(): {
  fragments: string[];
  topics: Record<string, string>;
} {
  const src = readFileSync(
    resolve(__dirname, "../../../wallet-runtime/src/abi.ts"),
    "utf8",
  );
  const fragBlock = src.match(
    /export const DARK_POOL_FRAGMENTS = \[([\s\S]*?)\] as const;/,
  );
  const topicBlock = src.match(
    /export const EVENT_TOPICS = \{([\s\S]*?)\} as const;/,
  );
  if (fragBlock === null || topicBlock === null)
    throw new Error(
      "wallet-runtime abi.ts no longer declares its tables as literals",
    );
  const fragRe = /"([^"]+)"/g;
  const topicRe = /(\w+):\s*"(0x[0-9a-f]{64})"/g;
  for (const [block, re] of [
    [fragBlock[1], fragRe],
    [topicBlock[1], topicRe],
  ] as const) {
    const rest = block.replace(re, "").replace(/[\s,]/g, "");
    if (rest !== "")
      throw new Error(`unparsed token in wallet-runtime abi.ts table: ${rest}`);
  }
  return {
    fragments: [...fragBlock[1].matchAll(fragRe)].map((m) => m[1]),
    topics: Object.fromEntries(
      [...topicBlock[1].matchAll(topicRe)].map((m) => [m[1], m[2]]),
    ),
  };
}

describe("Freeze list: values every pool reader depends on", function () {
  describe("event signatures, topic0 and indexed layout", function () {
    for (const [name, e] of Object.entries(FROZEN_EVENTS)) {
      it(`${name}: topic0, parameter layout`, async function () {
        expect(ethers.id(e.signature), "keccak256(signature)").to.equal(
          e.topic0,
        );
        const ev = POOL_ABI.getEvent(name);
        if (ev === null) throw new Error(`${name} missing from DarkPool ABI`);
        expect(ev.topicHash).to.equal(e.topic0);
        expect(ev.inputs.map((i) => [i.name, i.type, i.indexed])).to.deep.equal(
          e.params.map((p) => [...p]),
        );
      });
    }

    it("the pool declares no event outside the frozen list and the inherited OpenZeppelin events", function () {
      const declared: string[] = [];
      POOL_ABI.forEachEvent((ev) => declared.push(ev.name));
      expect(declared.sort()).to.deep.equal(
        [...Object.keys(FROZEN_EVENTS), ...INHERITED_EVENTS].sort(),
      );
    });

    it("every frozen event is emitted by the proxy with its frozen topic count and data size", async function () {
      const f = await loadFixture(deployPinnedPool);
      const controllerAddr = await f.controller.getAddress();
      const governance = f.pool.connect(f.upgrader);
      await mined(governance.setModuleVerifier(controllerAddr, f.stubs[0]));
      await mined(f.pool.connect(f.pauser).disableModule(controllerAddr));
      await mined(f.pool.connect(f.admin).enableModule(controllerAddr));
      await mined(governance.setVerifier(0, f.stubs[1]));
      const [nx, ny] = mulPointEscalar(Base8, 5n);
      await mined(governance.rotateComplianceKey(nx, ny));
      await mined(governance.rotateComplianceKey(CX, CY));
      for (const entry of INSERTING) {
        await mined(send(f, vectorFor(entry, await contextFor(f, entry))));
      }
      const v2 = await (
        await ethers.getContractFactory("DarkPoolV2Mock", {
          libraries: { Poseidon2: f.poseidonAddr },
        })
      ).deploy();
      await mined(governance.upgradeToAndCall(await v2.getAddress(), "0x"));
      await mined(governance.upgradeToAndCall(f.implAddr, "0x"));
      const logs = await ethers.provider.getLogs({
        fromBlock: f.initReceipt.blockNumber,
        toBlock: "latest",
      });

      const seen = new Set<string>();
      for (const l of logs) {
        const hit = Object.entries(FROZEN_EVENTS).find(
          ([, e]) => e.topic0 === l.topics[0],
        );
        if (hit === undefined) continue;
        expect(l.address, `${hit[0]} emitter`).to.equal(f.poolAddr);
        expectFrozenShape(l);
        seen.add(hit[0]);
      }
      expect([...seen].sort()).to.deep.equal(Object.keys(FROZEN_EVENTS).sort());
    });
  });

  describe("view functions, entrypoint selectors and return types", function () {
    for (const [sig, selector, outputs] of FROZEN_VIEWS) {
      it(`${sig} is ${selector} returning (${outputs.join(",")})`, function () {
        const fn = POOL_ABI.getFunction(sig);
        if (fn === null) throw new Error(`${sig} missing from DarkPool ABI`);
        expect(fn.selector).to.equal(selector);
        expect(fn.stateMutability).to.equal("view");
        expect(fn.outputs.map((o) => o.type)).to.deep.equal([...outputs]);
      });
    }

    for (const [sig, selector] of FROZEN_ENTRYPOINTS) {
      it(`${sig} is ${selector}`, function () {
        expect(ethers.id(sig).slice(0, 10)).to.equal(selector);
        const fn = POOL_ABI.getFunction(sig);
        if (fn === null) throw new Error(`${sig} missing from DarkPool ABI`);
        expect(fn.selector).to.equal(selector);
      });
    }

    // Distinct from the ModuleDisabled event: a module controller decodes this revert when its module is off.
    it("a disabled module's settle reverts with ModuleNotActive(address) 0x377e7f86", async function () {
      const err = POOL_ABI.getError("ModuleNotActive");
      if (err === null)
        throw new Error("ModuleNotActive missing from DarkPool ABI");
      expect(err.format("sighash")).to.equal("ModuleNotActive(address)");
      expect(err.selector).to.equal("0x377e7f86");
      expect(POOL_ABI.getEvent("ModuleDisabled")?.format("sighash")).to.equal(
        "ModuleDisabled(address,address)",
      );

      const f = await loadFixture(deployPinnedPool);
      const controllerAddr = await f.controller.getAddress();
      await mined(f.pool.connect(f.pauser).disableModule(controllerAddr));
      const v = vectorFor("settle", await contextFor(f, "settle"));
      const leavesBefore = await f.pool.getNextLeafIndex();
      const revert = await revertData(send(f, v));
      expect(revert).to.equal(
        "0x377e7f86" + addrWord(controllerAddr).slice(2).toLowerCase(),
      );
      expect(await f.pool.getNextLeafIndex()).to.equal(leavesBefore);
    });

    it("a fresh pool reads: one leaf (genesis), genesis root known, compliance version 1, ids 0..9 bound", async function () {
      const f = await loadFixture(deployPinnedPool);
      expect(await f.pool.getNextLeafIndex()).to.equal(1n);
      expect(await f.pool.getCurrentRoot()).to.equal(GENESIS["31337"]);
      expect(await f.pool.isKnownRoot(GENESIS["31337"])).to.equal(true);
      expect([...(await f.pool.complianceKey())]).to.deep.equal([CX, CY, 1n]);
      for (let id = 0; id < CIRCUIT_COUNT; id++) {
        expect(await f.pool.verifier(id)).to.equal(f.stubs[id]);
      }
      expect(await f.pool.verifier(CIRCUIT_COUNT)).to.equal(ethers.ZeroAddress);
    });

    it("a claimed public memo stays valid and reads spent", async function () {
      const f = await loadFixture(deployPinnedPool);
      const ctx = await contextFor(f, "publicClaim");
      const memoId = ctx.memoId!;
      expect(await f.pool.isValidPublicMemo(memoId)).to.equal(true);
      expect(await f.pool.isPublicMemoSpent(memoId)).to.equal(false);
      await mined(send(f, vectorFor("publicClaim", ctx)));
      expect(await f.pool.isValidPublicMemo(memoId)).to.equal(true);
      expect(await f.pool.isPublicMemoSpent(memoId)).to.equal(true);
    });
  });

  describe("ciphertext layout: bytes32[7] words and the meaning of words 0 and 5", function () {
    async function realDepositAndTransfer() {
      const f = await deployDarkPoolFixture();
      const poolAddr = await f.darkPool.getAddress();
      const assetFr = addressToFr(await f.token.getAddress());

      const depositEph = evenYEphemeral(0x5eed01n);
      const dep = await makeDeposit(
        f.darkPool,
        f.token,
        f.alice,
        100n,
        depositEph,
      );
      const depBlock = await ethers.provider.getBlockNumber();
      const depositLogs = await ethers.provider.getLogs({
        address: poolAddr,
        fromBlock: depBlock,
        toBlock: depBlock,
      });

      const tree = await newSeededTree();
      await tree.insert(dep.commitment);
      const bobInKey = evenYEphemeral(555n);
      const bobInPub = publicKey(bobInKey);
      const memo = await mintIncomingNote(
        evenYEphemeral(12345n),
        40n,
        bobInPub,
        bobInKey,
        assetFr,
        PARENTS_HIDDEN,
      );
      const changeParents = packParents([{ leafIndex: 1 }, { leafIndex: 0 }]);
      const change = await mintSelfNote(
        evenYEphemeral(67890n),
        60n,
        dep.spendScalar,
        assetFr,
        changeParents,
      );
      const proof = await proveTransfer({
        compliancePk: COMPLIANCE_PK,
        recipientInPub: bobInPub,
        oldNote: dep.built.note,
        spendScalar: dep.spendScalar,
        oldNoteIndex: 1,
        oldNotePath: tree.getMerklePath(1),
        memoNote: memo.note,
        memoEph: memo.eph,
        changeNote: change.note,
        changeEph: change.eph,
      });
      const transferReceipt = await mined(
        f.darkPool
          .connect(f.alice)
          .privateTransfer(proof.proof, proof.publicInputs),
      );
      return {
        ...f,
        assetFr,
        dep,
        depositEph,
        depositLogs,
        bobInKey,
        bobInPub,
        memo,
        change,
        changeParents,
        transferReceipt,
      };
    }

    const complianceCek = (ephX: bigint): Fr =>
      new Fr(mulPointEscalar(recoverEvenY(ephX), COMPLIANCE_SK)[0]);
    const words = (ct: readonly string[]): Fr[] =>
      ct.map((h) => new Fr(BigInt(h)));

    it("a real deposit's NewNote decrypts to [version 1, asset, type, conditions, value, owner, parents] and recommits to its leaf", async function () {
      const r = await loadFixture(realDepositAndTransfer);
      const parsed = parsePool(r.darkPool, r.depositLogs);
      const minted = parsed.find((p) => p.name === "NewNote");
      if (minted === undefined) throw new Error("deposit minted no NewNote");
      const ct = words(minted.args.packedCiphertext as string[]);
      const cek = complianceCek(minted.args.ephemeralPK_x as bigint);
      const pt = await demDecrypt(cek, ct);
      const owner = await pubkeyOwner(publicKey(r.dep.spendScalar));

      expect(pt[0].toBigInt(), "word 0 is note_version").to.equal(1n);
      expect(pt[1].toBigInt(), "word 1 is asset_id").to.equal(
        r.assetFr.toBigInt(),
      );
      expect(pt[2].toBigInt(), "word 2 is note_type STANDARD").to.equal(0n);
      expect(pt[3].toBigInt(), "word 3 is conditions_hash").to.equal(0n);
      expect(pt[4].toBigInt(), "word 4 is value").to.equal(100n);
      expect(pt[5].toBigInt(), "word 5 is owner").to.equal(owner.toBigInt());
      expect(pt[6].toBigInt(), "word 6 is parents").to.equal(0n);

      const recommitted = await leaf({
        noteVersion: pt[0],
        assetId: pt[1],
        noteType: pt[2],
        conditionsHash: pt[3],
        value: pt[4].toBigInt(),
        owner: pt[5],
        psi: await computePsi(cek),
        parents: pt[6],
      });
      expect(recommitted.toString()).to.equal(minted.args.commitment);
    });

    it("discovery strips words 0 and 5 and rebuilds them from the version constant and the owner", async function () {
      const r = await loadFixture(realDepositAndTransfer);
      expect([...CIPHERTEXT_KEPT_INDICES]).to.deep.equal([1, 2, 3, 4, 6]);
      const minted = parsePool(r.darkPool, r.depositLogs).find(
        (p) => p.name === "NewNote",
      );
      if (minted === undefined) throw new Error("deposit minted no NewNote");
      const ct = words(minted.args.packedCiphertext as string[]);
      const cek = complianceCek(minted.args.ephemeralPK_x as bigint);
      const rebuilt = await reconstructCiphertext(
        {
          layoutVersion: HOWL_NOTE_LAYOUT_VERSION,
          recordKind: RECORD_KIND_SELF,
          leafIndex: 1,
          commitmentPrefix: ethers
            .getBytes(minted.args.commitment)
            .slice(0, 16),
          ephemeralPkX: new Fr(0n),
          cekWrap: new Fr(0n),
          ciphertextKept: [1, 2, 3, 4, 6].map((i) => ct[i]),
        },
        cek,
        await pubkeyOwner(publicKey(r.dep.spendScalar)),
      );
      expect(rebuilt.map((x) => x.toString())).to.deep.equal(
        ct.map((x) => x.toString()),
      );
    });

    it("the DEM pad is Poseidon2([cek, keccak256('hisoka.enc.v1') mod p, k], 3), added on encrypt (Noir KAT)", async function () {
      const encDomain =
        "0x1a0ef2d9219ffd1fa6aaa00b33818a7f5503303777b95cfcc6bb7653189dfca3";
      expect(w(BigInt(ethers.id("hisoka.enc.v1")) % BN254_FR)).to.equal(
        encDomain,
      );
      expect(w(ENC_DOMAIN)).to.equal(encDomain);
      const cek = new Fr(
        0x1fbbfa289c50b7ded032c85e5faa8b3790afc2fd059fd3d299294ff879a08bdan,
      );
      const plaintext = [
        1n,
        0x1234567890123456789012345678901234567890n,
        0n,
        0n,
        100n,
        0x2874ae964d8b283e2f521a7f14125fc92747bb9770139b8d4b70ee09e2d83785n,
        0n,
      ].map(toFr);
      const ct = await demEncrypt(cek, plaintext);
      expect(ct.map((x) => x.toString())).to.deep.equal([
        "0x2731638e2a7a9820452856622ce83bb4ed875a995d5f28e09a9e2813d1472f67",
        "0x17537f0cfa734af08271f104fe3a6b59c655a70ef150119205af625ab451b413",
        "0x214d78fb170e5a1de97ded5727a834f29b94f4ed0d3ca29b36aa98b597051302",
        "0x109dbab21c201fdac2cd7e0f59efdc423f18de696a918357c9fedea65869ff8e",
        "0x2065a8ce6a9cdce89ca92cad5e9bc7a80f2413b893219f03e27365ebead75032",
        "0x0124088cefa5b815b5213279cd8c7a7eef948183c37291e8740c9deccc202418",
        "0x2971fe65daaac4e80629e73dfbd54bf6a38f9748d9728257ffefdc8b97686211",
      ]);
      const pad0 = await Poseidon.hash([cek, toFr(ENC_DOMAIN), toFr(0n)]);
      expect(ct[0].toString()).to.equal(plaintext[0].add(pad0).toString());
    });

    describe("discovery tags", function () {
      it("a deposit's ephemeralPK_x is the x of eph * Base8 and recovers to the even-y point", async function () {
        const r = await loadFixture(realDepositAndTransfer);
        const minted = parsePool(r.darkPool, r.depositLogs).find(
          (p) => p.name === "NewNote",
        );
        if (minted === undefined) throw new Error("deposit minted no NewNote");
        const ephPub = publicKey(r.depositEph);
        expect(minted.args.ephemeralPK_x).to.equal(ephPub[0]);
        const recovered = recoverEvenY(minted.args.ephemeralPK_x as bigint);
        expect(isEvenY(recovered)).to.equal(true);
        expect(recovered).to.deep.equal(ephPub);
      });

      it("a transfer memo's tag is the recipient view key x, its ephemeralPK_x the memo eph x, and the recipient unwraps cekWrap", async function () {
        const r = await loadFixture(realDepositAndTransfer);
        const parsed = parsePool(r.darkPool, r.transferReceipt.logs);
        const memoLog = parsed.find((p) => p.name === "NewPrivateMemo");
        const changeLog = parsed.find((p) => p.name === "NewNote");
        if (memoLog === undefined || changeLog === undefined)
          throw new Error("transfer did not mint a memo and a change note");

        expect(memoLog.args.tag).to.equal(r.bobInPub[0]);
        expect(recoverEvenY(memoLog.args.tag as bigint)).to.deep.equal(
          r.bobInPub,
        );
        const memoEphPub = publicKey(r.memo.eph);
        expect(memoLog.args.ephemeralPK_x).to.equal(memoEphPub[0]);
        expect(
          isEvenY(recoverEvenY(memoLog.args.ephemeralPK_x as bigint)),
        ).to.equal(true);
        if (r.memo.cekWrap === undefined)
          throw new Error("an incoming memo carries a cekWrap");
        expect(memoLog.args.cekWrap).to.equal(r.memo.cekWrap.toBigInt());

        const bobCek = await unwrapCek(
          new Fr(memoLog.args.cekWrap as bigint),
          r.bobInKey,
          recoverEvenY(memoLog.args.ephemeralPK_x as bigint),
        );
        expect(bobCek.toString()).to.equal(r.memo.cek.toString());
        expect(
          complianceCek(memoLog.args.ephemeralPK_x as bigint).toString(),
        ).to.equal(bobCek.toString());
        const memoPt = await demDecrypt(
          bobCek,
          words(memoLog.args.packedCiphertext as string[]),
        );
        expect(memoPt[0].toBigInt()).to.equal(1n);
        expect(memoPt[4].toBigInt()).to.equal(40n);
        expect(memoPt[5].toString()).to.equal(
          (await pubkeyOwner(r.bobInPub)).toString(),
        );
        expect(memoPt[6].toString()).to.equal(PARENTS_HIDDEN.toString());

        const changeCek = complianceCek(changeLog.args.ephemeralPK_x as bigint);
        const changePt = await demDecrypt(
          changeCek,
          words(changeLog.args.packedCiphertext as string[]),
        );
        expect(changePt[4].toBigInt()).to.equal(60n);
        expect(changePt[5].toString()).to.equal(
          (await pubkeyOwner(publicKey(r.dep.spendScalar))).toString(),
        );
        expect(changePt[6].toString()).to.equal(r.changeParents.toString());
      });
    });
  });

  describe("genesis leaf and the chain-id derivation", function () {
    it("domain tag is keccak256('hisoka.darkpool.genesis') reduced mod p, and the raw hash exceeds p", function () {
      expect(ethers.id("hisoka.darkpool.genesis")).to.equal(GENESIS_DOMAIN_RAW);
      expect(BigInt(GENESIS_DOMAIN_RAW) >= BN254_FR).to.equal(true);
      expect(w(BigInt(GENESIS_DOMAIN_RAW) % BN254_FR)).to.equal(
        GENESIS_DOMAIN_REDUCED,
      );
    });

    it("TS genesisLeaf(chainId) matches the pinned leaves for 31337, 421614 and 1", async function () {
      for (const [chainId, expected] of Object.entries(GENESIS)) {
        expect((await genesisLeaf(BigInt(chainId))).toString()).to.equal(
          expected,
        );
        expect(
          (
            await Poseidon.hash([
              new Fr(BigInt(GENESIS_DOMAIN_REDUCED)),
              toFr(BigInt(chainId)),
            ])
          ).toString(),
        ).to.equal(expected);
      }
    });

    it("initialize seeds genesis exactly once as RootSaved, LeafInserted(0), GenesisSeeded(31337) in adjacent logs", async function () {
      const f = await loadFixture(deployPinnedPool);
      expect((await ethers.provider.getNetwork()).chainId).to.equal(31337n);
      const raw = f.initReceipt.logs.filter((l) => l.address === f.poolAddr);
      const names = parsePool(f.pool, raw).map((p) => p.name);
      expect(names.slice(-5)).to.deep.equal([
        "ComplianceKeyRotated",
        "RootSaved",
        "LeafInserted",
        "GenesisSeeded",
        "Initialized",
      ]);
      for (const once of ["RootSaved", "LeafInserted", "GenesisSeeded"]) {
        expect(names.filter((n) => n === once).length, once).to.equal(1);
      }
      const at = names.indexOf("RootSaved");
      expect(raw[at + 1].index).to.equal(raw[at].index + 1);
      expect(raw[at + 2].index).to.equal(raw[at].index + 2);
      const g = GENESIS["31337"];
      expect(raw[at].topics[1]).to.equal(g);
      expect(raw[at + 1].topics[1]).to.equal(w(0n));
      expect(raw[at + 1].data).to.equal(ethers.concat([g, g]));
      expect(raw[at + 2].topics[1]).to.equal(w(31337n));
      expect(raw[at + 2].data).to.equal(g);
      expect(await f.pool.getCurrentRoot()).to.equal(g);
    });
  });

  describe("one insert = three adjacent logs; nonReentrant on every inserting entrypoint", function () {
    for (const entry of INSERTING) {
      it(`${entry}: ${EXPECTED_LOGS[entry].join(", ")}`, async function () {
        const f = await loadFixture(deployPinnedPool);
        await runAndPinLogs(f, entry);
      });
    }

    it("the reentrancy probe reaches the pool: an inner view call succeeds", async function () {
      const f = await loadFixture(deployPinnedPool);
      await setCode(
        REENTRANT_TOKEN,
        reentrantTokenCode(
          f.poolAddr,
          f.pool.interface.encodeFunctionData("getNextLeafIndex"),
        ),
      );
      expect(await revertData(outerDepositOfReentrantToken(f))).to.equal(
        INNER_SUCCEEDED,
      );
    });

    for (const entry of [...INSERTING, ...GUARDED_NON_INSERTING] as (
      | ProofEntry
      | "publicTransfer"
    )[]) {
      it(`${entry} re-entered during a deposit's token pull reverts ReentrancyGuardReentrantCall`, async function () {
        const f = await loadFixture(deployPinnedPool);
        await setCode(
          REENTRANT_TOKEN,
          reentrantTokenCode(f.poolAddr, await innerCalldata(f, entry)),
        );
        expect(await revertData(outerDepositOfReentrantToken(f))).to.equal(
          REENTRANT_CALL_SELECTOR,
        );
        expect(
          f.pool.interface.getError("ReentrancyGuardReentrantCall")?.selector,
        ).to.equal(REENTRANT_CALL_SELECTOR);
      });
    }

    it("every state-changing function is classified as inserting, guarded, governance or initializer", function () {
      const declared: string[] = [];
      POOL_ABI.forEachFunction((fn) => {
        if (fn.stateMutability !== "view" && fn.stateMutability !== "pure")
          declared.push(fn.name);
      });
      expect(declared.sort()).to.deep.equal(
        [
          ...INSERTING,
          ...GUARDED_NON_INSERTING,
          ...GOVERNANCE,
          ...INITIALIZER,
        ].sort(),
      );
    });

    it("the genesis insert is the one unguarded insert: initialize runs once and never on the implementation", async function () {
      const f = await loadFixture(deployPinnedPool);
      const params: DarkPool.InitParamsStruct = {
        depositVerifier: f.stubs[0],
        withdrawVerifier: f.stubs[1],
        transferVerifier: f.stubs[2],
        joinVerifier: f.stubs[3],
        splitVerifier: f.stubs[4],
        publicClaimVerifier: f.stubs[5],
        withdrawMultisigVerifier: f.stubs[6],
        transferMultisigVerifier: f.stubs[7],
        splitMultisigVerifier: f.stubs[8],
        joinMultisigVerifier: f.stubs[9],
        compliancePkX: CX,
        compliancePkY: CY,
        initialAdminDelay: 0,
        initialAdmin: f.admin.address,
        pauser: f.pauser.address,
        upgrader: f.upgrader.address,
      };
      await expect(f.pool.initialize(params)).to.be.revertedWithCustomError(
        f.pool,
        "InvalidInitialization",
      );
      const impl = DarkPool__factory.connect(f.implAddr, f.user);
      await expect(impl.initialize(params)).to.be.revertedWithCustomError(
        impl,
        "InvalidInitialization",
      );
      expect(
        parsePool(f.pool, f.initReceipt.logs).filter(
          (p) => p.name === "GenesisSeeded",
        ).length,
      ).to.equal(1);
    });
  });

  describe("tree: depth 32, level-absorbing Poseidon2 walk, lean carry-up", function () {
    it("roots after leaves 1..5 follow genesis match the pinned literals and the TS LeanIMT", async function () {
      const f = await loadFixture(deployPinnedPool);
      const tree = await newSeededTree();
      for (let i = 0; i < 5; i++) {
        const v = vectorFor("deposit", await contextFor(f, "deposit"));
        v.pi[2] = w(BigInt(i + 1));
        await mined(send(f, v));
        await tree.insert(new Fr(BigInt(i + 1)));
        expect(
          await f.pool.getCurrentRoot(),
          `root after leaf ${i + 1}`,
        ).to.equal(ROOTS_AFTER_LEAVES_1_TO_5[i]);
        expect(tree.getRoot().toString()).to.equal(
          ROOTS_AFTER_LEAVES_1_TO_5[i],
        );
      }
    });

    it("the Noir inclusion vector (leaf 4 at index 3, depth 8) walks to its pinned root with level-absorbing nodes", async function () {
      const siblings = [
        3n,
        0x038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383n,
        0x232400b3cca0da78d26295f345d21e9bf8949238bee02b285140ebf183119982n,
        0n,
        0n,
        0n,
        0n,
        0n,
      ];
      let node = toFr(4n);
      let index = 3;
      for (let level = 0; level < siblings.length; level++) {
        const sibling = toFr(siblings[level]);
        if (siblings[level] !== 0n) {
          const [l, r] = index & 1 ? [sibling, node] : [node, sibling];
          node = await Poseidon.hash([l, r, toFr(BigInt(level))]);
        } else {
          expect(index & 1, "a right child needs a sibling").to.equal(0);
        }
        index >>= 1;
      }
      expect(node.toString()).to.equal(
        "0x0738cba9a9f3e94b55b9a591c0f0dbd3567358ec0c204e21f565c9d3a744fc3c",
      );
    });

    it("depth is 32 on chain and in TS, and a zero leaf is refused", async function () {
      const f = await loadFixture(deployPinnedPool);
      expect(
        await storageWord(f.poolAddr, NAMESPACES["hisoka.darkpool.tree"]),
      ).to.equal(32n);
      expect(TREE_DEPTH).to.equal(32);
      expect(new LeanIMT(TREE_DEPTH).depth).to.equal(32);
      const v = vectorFor("deposit", await contextFor(f, "deposit"));
      v.pi[2] = w(0n);
      await expect(send(f, v)).to.be.revertedWithCustomError(
        f.pool,
        "InvalidLeaf",
      );
    });
  });

  describe("compliance key history", function () {
    it("initialize announces version 1 as ComplianceKeyRotated(0, 1, x, y); a rotation emits (1, 2, x', y')", async function () {
      const f = await loadFixture(deployPinnedPool);
      const initial = parsePool(f.pool, f.initReceipt.logs).filter(
        (p) => p.name === "ComplianceKeyRotated",
      );
      expect(initial.map((p) => [...p.args])).to.deep.equal([[0n, 1n, CX, CY]]);
      expect([...(await f.pool.complianceKey())]).to.deep.equal([CX, CY, 1n]);

      const [nx, ny] = mulPointEscalar(Base8, 5n);
      const rotated = parsePool(
        f.pool,
        (await mined(f.pool.connect(f.upgrader).rotateComplianceKey(nx, ny)))
          .logs,
      );
      expect(rotated.map((p) => [p.name, ...p.args])).to.deep.equal([
        ["ComplianceKeyRotated", 1n, 2n, nx, ny],
      ]);
      expect([...(await f.pool.complianceKey())]).to.deep.equal([nx, ny, 2n]);
    });
  });

  describe("UUPS for the life of the proxy", function () {
    it("the implementation is UUPS-proxiable at the ERC-1967 slot and the proxy points at it", async function () {
      const f = await loadFixture(deployPinnedPool);
      const impl = DarkPool__factory.connect(f.implAddr, f.user);
      expect(await impl.proxiableUUID()).to.equal(ERC1967_IMPLEMENTATION_SLOT);
      expect(
        ethers.toBeHex(
          BigInt(
            ethers.keccak256(
              ethers.toUtf8Bytes("eip1967.proxy.implementation"),
            ),
          ) - 1n,
          32,
        ),
      ).to.equal(ERC1967_IMPLEMENTATION_SLOT);
      expect(
        ethers.getAddress(
          ethers.dataSlice(
            await ethers.provider.getStorage(
              f.poolAddr,
              ERC1967_IMPLEMENTATION_SLOT,
            ),
            12,
          ),
        ),
      ).to.equal(f.implAddr);
      expect(await f.pool.UPGRADER_ROLE()).to.equal(ethers.id("UPGRADER_ROLE"));
    });

    it("UPGRADER upgrades and returns with storage intact; a non-UUPS target and a non-upgrader are refused", async function () {
      const f = await loadFixture(deployPinnedPool);
      await runAndPinLogs(f, "split");
      const [nx, ny] = mulPointEscalar(Base8, 5n);
      await mined(f.pool.connect(f.upgrader).rotateComplianceKey(nx, ny));
      const spentNullifier = await lastSpentNullifier(f);
      const snapshot = async () => [
        await f.pool.getCurrentRoot(),
        await f.pool.getNextLeafIndex(),
        await f.pool.isNullifierSpent(spentNullifier),
        ...(await f.pool.complianceKey()),
      ];
      const before = await snapshot();

      const v2 = await (
        await ethers.getContractFactory("DarkPoolV2Mock", {
          libraries: { Poseidon2: f.poseidonAddr },
        })
      ).deploy();
      const v2Addr = await v2.getAddress();
      await expect(
        f.pool.connect(f.admin).upgradeToAndCall(v2Addr, "0x"),
      ).to.be.revertedWithCustomError(
        f.pool,
        "AccessControlUnauthorizedAccount",
      );
      await expect(f.pool.connect(f.upgrader).upgradeToAndCall(v2Addr, "0x"))
        .to.emit(f.pool, "Upgraded")
        .withArgs(v2Addr);
      const asV2 = await ethers.getContractAt("DarkPoolV2Mock", f.poolAddr);
      expect(await asV2.version()).to.equal(2n);
      expect(await snapshot()).to.deep.equal(before);

      const notUups = await (
        await ethers.getContractFactory("NotUUPSMock")
      ).deploy();
      await expect(
        f.pool
          .connect(f.upgrader)
          .upgradeToAndCall(await notUups.getAddress(), "0x"),
      ).to.be.revertedWithCustomError(f.pool, "ERC1967InvalidImplementation");

      await mined(
        f.pool.connect(f.upgrader).upgradeToAndCall(f.implAddr, "0x"),
      );
      expect(
        await upgrades.erc1967.getImplementationAddress(f.poolAddr),
      ).to.equal(f.implAddr);
      expect(await snapshot()).to.deep.equal(before);
    });
  });

  describe("governance delays on non-test chains (deploy script)", function () {
    function withDelayEnv<T>(
      timelock: string | undefined,
      admin: string | undefined,
      body: () => T,
    ): T {
      const saved = {
        timelock: process.env.TIMELOCK_MIN_DELAY_SECS,
        admin: process.env.ADMIN_TRANSFER_DELAY_SECS,
      };
      const put = (key: string, value: string | undefined) => {
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
      };
      try {
        put("TIMELOCK_MIN_DELAY_SECS", timelock);
        put("ADMIN_TRANSFER_DELAY_SECS", admin);
        return body();
      } finally {
        put("TIMELOCK_MIN_DELAY_SECS", saved.timelock);
        put("ADMIN_TRANSFER_DELAY_SECS", saved.admin);
      }
    }

    const PRODUCTION_CHAINS = [1n, 10n, 8453n, 42161n, 43114n];
    const SHORT_DELAY_CHAINS = [31337n, 421614n, 11155111n];

    it("defaults both delays to 172800 s on every chain", function () {
      withDelayEnv(undefined, undefined, () => {
        for (const chainId of [...PRODUCTION_CHAINS, ...SHORT_DELAY_CHAINS]) {
          expect(governanceDelays(chainId)).to.deep.equal({
            timelockMinDelay: 172800n,
            adminTransferDelay: 172800n,
          });
        }
      });
    });

    it("refuses a zero delay on production chains and accepts it on exactly 31337, 421614 and 11155111", function () {
      withDelayEnv("0", "0", () => {
        for (const chainId of PRODUCTION_CHAINS) {
          expect(() => governanceDelays(chainId), `${chainId}`).to.throw(
            "only on chain ids 31337, 421614, 11155111",
          );
        }
        for (const chainId of SHORT_DELAY_CHAINS) {
          expect(governanceDelays(chainId)).to.deep.equal({
            timelockMinDelay: 0n,
            adminTransferDelay: 0n,
          });
        }
      });
      withDelayEnv(undefined, "172799", () => {
        expect(() => governanceDelays(1n)).to.throw(
          "ADMIN_TRANSFER_DELAY_SECS=172799 is below the 172800s production default",
        );
      });
    });
  });

  describe("roots are kept forever", function () {
    // More inserts than any bounded root ring up to 256, so a future windowed history cannot pass.
    it(`every root seen across ${ROOT_HISTORY_INSERTS} inserts stays known`, async function () {
      const f = await loadFixture(deployPinnedPool);
      const roots = [GENESIS["31337"]];
      for (let i = 0; i < ROOT_HISTORY_INSERTS; i++) {
        const v = vectorFor("deposit", await contextFor(f, "deposit"));
        const saved = parsePool(f.pool, (await mined(send(f, v))).logs).find(
          (p) => p.name === "RootSaved",
        );
        roots.push(saved!.args.root as string);
      }
      expect(new Set(roots).size).to.equal(ROOT_HISTORY_INSERTS + 1);
      for (const root of roots) {
        expect(await f.pool.isKnownRoot(root), root).to.equal(true);
      }
    });
  });

  describe("storage namespaces, circuit ids and public-input counts", function () {
    it("namespace slots follow the ERC-7201 formula and hold the pool's state", async function () {
      for (const [ns, slot] of Object.entries(NAMESPACES)) {
        expect(erc7201(ns), ns).to.equal(slot);
      }
      const f = await loadFixture(deployPinnedPool);
      const tree = NAMESPACES["hisoka.darkpool.tree"];
      const compliance = NAMESPACES["hisoka.darkpool.compliance"];
      await runAndPinLogs(f, "split");
      const nullifier = await lastSpentNullifier(f);
      const memoId = await postMemo(f, wordCounter++);

      expect(await storageWord(f.poolAddr, tree)).to.equal(32n);
      expect(await storageWord(f.poolAddr, offsetSlot(tree, 2n))).to.equal(
        await f.pool.getNextLeafIndex(),
      );
      expect(w(await storageWord(f.poolAddr, offsetSlot(tree, 3n)))).to.equal(
        await f.pool.getCurrentRoot(),
      );
      expect(
        await storageWord(
          f.poolAddr,
          mappingSlot("bytes32", GENESIS["31337"], offsetSlot(tree, 4n)),
        ),
      ).to.equal(1n);
      expect(await storageWord(f.poolAddr, compliance)).to.equal(CX);
      expect(
        await storageWord(f.poolAddr, offsetSlot(compliance, 1n)),
      ).to.equal(CY);
      expect(
        await storageWord(f.poolAddr, offsetSlot(compliance, 2n)),
      ).to.equal(1n);
      for (let id = 0; id < CIRCUIT_COUNT; id++) {
        expect(
          await storageWord(
            f.poolAddr,
            mappingSlot("uint256", id, NAMESPACES["hisoka.darkpool.verifiers"]),
          ),
        ).to.equal(BigInt(f.stubs[id]));
      }
      expect(
        await storageWord(
          f.poolAddr,
          mappingSlot(
            "bytes32",
            nullifier,
            NAMESPACES["hisoka.darkpool.nullifiers"],
          ),
        ),
      ).to.equal(1n);
      expect(
        await storageWord(
          f.poolAddr,
          mappingSlot("bytes32", memoId, NAMESPACES["hisoka.darkpool.memos"]),
        ),
      ).to.equal(1n);
      expect(
        BigInt.asUintN(
          160,
          await storageWord(
            f.poolAddr,
            mappingSlot(
              "address",
              await f.controller.getAddress(),
              NAMESPACES["hisoka.darkpool.settlement"],
            ),
          ),
        ),
      ).to.equal(BigInt(f.moduleVerifier));
      expect(
        await storageWord(
          f.poolAddr,
          NAMESPACES["openzeppelin.storage.ReentrancyGuard"],
        ),
      ).to.equal(1n);
    });

    for (const c of CIRCUITS) {
      it(`${c.entry} verifies with circuit id ${c.id} and takes exactly ${c.inputs} public inputs`, async function () {
        const f = await loadFixture(deployPinnedPool);
        const ctx = await contextFor(f, c.entry);
        const v = vectorFor(c.entry, ctx);
        expect(v.pi.length).to.equal(c.inputs);
        for (const bad of [c.inputs - 1, c.inputs + 1]) {
          const pi =
            bad < c.inputs ? v.pi.slice(0, bad) : [...v.pi, w(wordCounter++)];
          await expect(
            send(f, { ...v, pi }),
            `${bad} inputs`,
          ).to.be.revertedWithCustomError(f.pool, "InvalidInputsLength");
        }
        for (let id = 0; id < CIRCUIT_COUNT; id++) {
          if (id !== c.id)
            await mined(
              f.pool.connect(f.upgrader).setVerifier(id, f.rejecting),
            );
        }
        await mined(f.pool.connect(f.upgrader).setVerifier(c.id, f.rejecting));
        await expect(send(f, v)).to.be.revertedWithCustomError(
          f.pool,
          "InvalidProof",
        );
        await mined(
          f.pool.connect(f.upgrader).setVerifier(c.id, f.stubs[c.id]),
        );
        await mined(send(f, v));
      });
    }
  });

  describe("note format KATs through @hisoka/wallets (byte-identical to the Noir KATs)", function () {
    const cek = new Fr(
      0x1fbbfa289c50b7ded032c85e5faa8b3790afc2fd059fd3d299294ff879a08bdan,
    );

    it("psi = Poseidon2([cek, PSI_DOMAIN]); nullifier = Poseidon2([psi, leafIndex]); PSI_DOMAIN = keccak256('hisoka.psi.v1') mod p", async function () {
      const psiDomain =
        "0x138d495e7a5c1b3f504318dd6cfcf0a7cf7bb6d69cf9eadb049cc35d6831ef5b";
      expect(w(BigInt(ethers.id("hisoka.psi.v1")) % BN254_FR)).to.equal(
        psiDomain,
      );
      expect(w(PSI_DOMAIN)).to.equal(psiDomain);
      const psi = await computePsi(cek);
      expect(psi.toString()).to.equal(
        "0x0441d9b1006cd55062a6458b5dd1db14869f1a5c8fbc66f73032208c2b109956",
      );
      expect((await computeNullifier(psi, toFr(3n))).toString()).to.equal(
        "0x0ced8160f191dfff5c3432bc36f182188226143b294192021ea754f282075897",
      );
    });

    it("leaf = Poseidon2 over the 8 plaintext fields in frozen order", async function () {
      const commitment = await leaf({
        noteVersion: toFr(1n),
        assetId: toFr(0x1234567890123456789012345678901234567890n),
        noteType: toFr(0n),
        conditionsHash: toFr(0n),
        value: 100n,
        owner:
          toFr(
            0x0bb44e077410f254c45a30b25976ce465e83511d7fda88f26e1296c6978eaf27n,
          ),
        psi: await computePsi(cek),
        parents: toFr(0n),
      });
      expect(commitment.toString()).to.equal(
        "0x1bcd07739b701ccbd05dfb11bb4aaa428b200b37a7cbdc49d575b281b88930cc",
      );
    });

    it("PARENTS_HIDDEN is p - 1", function () {
      expect(w(PARENTS_HIDDEN.toBigInt())).to.equal(
        "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000",
      );
    });
  });

  describe("contract surfaces adaptors depend on", function () {
    it("a contract recipient must answer acceptWithdraw with its own selector", async function () {
      const f = await loadFixture(deployPinnedPool);
      expect(
        ethers.id("acceptWithdraw(bytes32,uint256)").slice(0, 10),
      ).to.equal(ACCEPT_WITHDRAW_SELECTOR);
      expect(
        IWithdrawRecipient__factory.createInterface().getFunction(
          "acceptWithdraw",
        ).selector,
      ).to.equal(ACCEPT_WITHDRAW_SELECTOR);

      const answering = (word: string) =>
        "0x7f" + word.slice(2).padEnd(64, "0") + "600052" + "60206000f3";
      const accepting = "0x00000000000000000000000000000000000acce7";
      const refusing = "0x00000000000000000000000000000000000dec1e";
      await setCode(accepting, answering(ACCEPT_WITHDRAW_SELECTOR));
      await setCode(refusing, answering("0x35307b64"));

      const toAccepting = vectorFor("withdraw", {
        ...(await contextFor(f, "withdraw")),
        recipient: accepting,
      });
      await mined(send(f, toAccepting));
      const toRefusing = vectorFor("withdraw", {
        ...(await contextFor(f, "withdraw")),
        recipient: refusing,
      });
      await expect(send(f, toRefusing))
        .to.be.revertedWithCustomError(f.pool, "RecipientRejectedWithdraw")
        .withArgs(ethers.getAddress(refusing));
    });

    it("publicTransfer derives memoId = Poseidon2(value, asset, timelock, ownerX, ownerY, salt) and bounds value and timelock", async function () {
      const f = await loadFixture(deployPinnedPool);
      const asset = "0x00000000000000000000000000000000000a55e7";
      const tokenCode = await ethers.provider.getCode(
        await f.token.getAddress(),
      );
      await setCode(asset, tokenCode);
      const fixedToken = await ethers.getContractAt("MockERC20", asset);
      await fixedToken.mint(f.user.address, 2n ** 129n);
      await fixedToken.connect(f.user).approve(f.poolAddr, ethers.MaxUint256);
      const [ox, oy] = mulPointEscalar(Base8, 7n);
      const MEMO_ID =
        "0x05198ebbd771ec9064fe2e57b30ffb207281667c77e4a93b481c8bf410050e82";

      const posted = parsePool(
        f.pool,
        (await mined(f.pool.publicTransfer(ox, oy, asset, 1000n, 3600n, 42n)))
          .logs,
      );
      expect(posted.map((p) => [p.name, ...p.args])).to.deep.equal([
        ["NewPublicMemo", MEMO_ID, ethers.getAddress(asset), 1000n, 3600n, 42n],
      ]);
      expect(
        (
          await publicMemoId(
            {
              assetId: addressToFr(asset),
              value: 1000n,
              timelock: 3600n,
              salt: toFr(42n),
            },
            [ox, oy],
          )
        ).toString(),
      ).to.equal(MEMO_ID);

      await mined(
        f.pool.publicTransfer(
          ox,
          oy,
          asset,
          2n ** 128n - 1n,
          2n ** 64n - 1n,
          1n,
        ),
      );
      await expect(
        f.pool.publicTransfer(ox, oy, asset, 2n ** 128n, 0n, 2n),
      ).to.be.revertedWithCustomError(f.pool, "ValueTooLarge");
      await expect(
        f.pool.publicTransfer(ox, oy, asset, 1n, 2n ** 64n, 3n),
      ).to.be.revertedWithCustomError(f.pool, "TimelockTooLarge");
    });
  });

  describe("settlement outputs use the existing insert event", function () {
    it("a real Kage settle emits only frozen topics, its outputs as NewNote triples", async function () {
      const { darkPool, controller } = await loadFixture(
        deployGoldenSettlementFixture,
      );
      const leavesBefore = await darkPool.getNextLeafIndex();
      const receipt = await mined(
        controller.settle(KAGE_PROOF, KAGE_PUBLIC_INPUTS),
      );
      const allowed = new Set([
        ...Object.values(FROZEN_EVENTS).map((e) => e.topic0),
        KAGE_SWAP_SETTLED_TOPIC0,
      ]);
      for (const l of receipt.logs) {
        expect(allowed.has(l.topics[0]), `topic0 ${l.topics[0]}`).to.equal(
          true,
        );
        expectFrozenShape(l);
      }
      const parsed = parsePool(darkPool, receipt.logs);
      expect(parsed.map((p) => p.name)).to.deep.equal(EXPECTED_LOGS.settle);
      const settled = parsed[parsed.length - 1];
      expect(settled.args.controller).to.equal(await controller.getAddress());
      expect(settled.args.firstLeafIndex).to.equal(leavesBefore);
      expect(settled.args.outputCount).to.equal(4n);
    });
  });

  describe("wallet-runtime ABI table against the compiled pool", function () {
    it("each runtime topic0 equals the frozen literal and the compiled event", function () {
      const compiled = POOL_ABI;
      const { topics } = runtimeAbiTables();
      expect(Object.keys(topics).length).to.equal(9);
      for (const [name, topic] of Object.entries(topics)) {
        expect(topic, name).to.equal(FROZEN_EVENTS[name]?.topic0);
        expect(topic, name).to.equal(compiled.getEvent(name)?.topicHash);
      }
    });

    it("each runtime fragment matches the compiled fragment, names and indexed flags included", function () {
      const compiled = POOL_ABI;
      const { fragments, topics } = runtimeAbiTables();
      const runtime = new ethers.Interface(fragments);
      const runtimeEvents: string[] = [];
      runtime.forEachEvent((ev) => {
        runtimeEvents.push(ev.name);
        expect(ev.format("full"), ev.name).to.equal(
          compiled.getEvent(ev.name)?.format("full"),
        );
      });
      expect(runtimeEvents.sort()).to.deep.equal(Object.keys(topics).sort());
      runtime.forEachFunction((fn) => {
        expect(fn.format("full"), fn.name).to.equal(
          compiled.getFunction(fn.name)?.format("full"),
        );
      });
    });
  });
});
