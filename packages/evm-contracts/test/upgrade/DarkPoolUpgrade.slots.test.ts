import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import { AbiCoder, keccak256, toBeHex, toUtf8Bytes, ZeroHash } from "ethers";
import type { DarkPool, DarkPool__factory } from "../../typechain-types";

const abi = AbiCoder.defaultAbiCoder();

function erc7201(id: string): string {
  const inner = BigInt(keccak256(toUtf8Bytes(id)));
  const mask = (1n << 256n) - 1n - 0xffn;
  const slot = BigInt(keccak256(abi.encode(["uint256"], [inner - 1n]))) & mask;
  return toBeHex(slot, 32);
}

// Canonical BabyJubJub Base8 subgroup point (EIP-2494 / circomlib); on-curve so initialize accepts it.
const BASE8_X =
  5299619240641551281634865583518297030282874472190772894086521144482721001553n;
const BASE8_Y =
  16950150798460657717958625567821834550301663161624707787222815936182638968203n;

const NS = {
  tree: "hisoka.darkpool.tree",
  nullifiers: "hisoka.darkpool.nullifiers",
  memos: "hisoka.darkpool.memos",
  verifiers: "hisoka.darkpool.verifiers",
  compliance: "hisoka.darkpool.compliance",
} as const;

// Values hardcoded as the *_LOCATION constants in DarkPool.sol; the JS formula must reproduce them.
const EXPECTED: Record<keyof typeof NS, string> = {
  tree: "0xbdd00c81e71bd165e3ff2099ca204334ffd58a8d7225a33b4761542b7a86e200",
  nullifiers:
    "0xcb1d3464d85c75a880c4f95a3cfd4a5cd80b39c53862d4987d9ec14bb8af6700",
  memos: "0x79ab9646d487c514cf680928de0290895c9ad6720afd1f87136f293781b7ea00",
  verifiers:
    "0x204927e2223572a19571462c2dfb374afbbdb39e695632d6477721409dfb0b00",
  compliance:
    "0x4c6336ddd730b3b6886dcf6c397e5676dac845842540c4592f4e52cea8e9ae00",
};

const VERIFIER_COUNT = 10;

const REENTRANCY_LOCATION =
  "0x9b779b17422d0df92223018b32b4d1fa46e071723d6817e2486d003becc55f00";

function addSlot(base: string, offset: bigint): string {
  return toBeHex(BigInt(base) + offset, 32);
}

function mappingSlot(keyType: string, key: unknown, base: string): string {
  return keccak256(abi.encode([keyType, "uint256"], [key, BigInt(base)]));
}

async function slotValue(addr: string, slot: string): Promise<bigint> {
  return BigInt(await ethers.provider.getStorage(addr, slot));
}

describe("DarkPool UUPS: ERC-7201 slots + proxy init", function () {
  let proxyAddr: string;
  let implAddr: string;
  let darkpool: DarkPool;
  let verifiers: string[];
  let admin: string;
  let pauser: string;
  let upgrader: string;
  let outsider: Awaited<ReturnType<typeof ethers.getSigners>>[number];
  let initParams: unknown[];

  async function deploy() {
    const signers = await ethers.getSigners();
    const [adminS, pauserS, upgraderS, outsiderS] = signers;

    const pos = await (await ethers.getContractFactory("Poseidon2")).deploy();
    await pos.waitForDeployment();

    const DarkPool = (await ethers.getContractFactory("DarkPool", {
      libraries: {
        "contracts/Poseidon/Poseidon2.sol:Poseidon2": await pos.getAddress(),
      },
    })) as unknown as DarkPool__factory;

    const stub = await (
      await ethers.getContractFactory("StubVerifier")
    ).deploy();
    await stub.waitForDeployment();
    const stubAddr = await stub.getAddress();
    const verifierAddrs = Array.from(
      { length: VERIFIER_COUNT },
      () => stubAddr,
    );
    const params = [
      ...verifierAddrs,
      BASE8_X,
      BASE8_Y,
      172800, // initialAdminDelay (48h)
      adminS.address,
      pauserS.address,
      upgraderS.address,
    ];

    // Poseidon2 is a stateless pure linked library (no storage, no delegatecall out); external-library-linking
    // is the OZ-sanctioned acknowledgment for a manually-verified upgrade-safe library. It does not relax any
    // storage-layout safety check.
    const proxy = await upgrades.deployProxy(DarkPool, [params], {
      kind: "uups",
      initializer: "initialize",
      unsafeAllow: ["external-library-linking"],
    });
    await proxy.waitForDeployment();
    const addr = await proxy.getAddress();

    return {
      darkpool: DarkPool.attach(addr),
      factory: DarkPool,
      addr,
      verifierAddrs,
      admin: adminS.address,
      pauser: pauserS.address,
      upgrader: upgraderS.address,
      outsider: outsiderS,
      params,
    };
  }

  before(async function () {
    const d = await deploy();
    darkpool = d.darkpool;
    proxyAddr = d.addr;
    implAddr = await upgrades.erc1967.getImplementationAddress(proxyAddr);
    verifiers = d.verifierAddrs;
    admin = d.admin;
    pauser = d.pauser;
    upgrader = d.upgrader;
    outsider = d.outsider;
    initParams = d.params;
  });

  it("computes the 5 namespace slot constants from the ERC-7201 formula", function () {
    for (const key of Object.keys(NS) as (keyof typeof NS)[]) {
      expect(erc7201(NS[key]), `${NS[key]} slot`).to.equal(EXPECTED[key]);
    }
  });

  it("lands each namespace at its computed slot (raw storage on the proxy)", async function () {
    // tree.TREE_DEPTH == 32 at tree base slot
    expect(await slotValue(proxyAddr, EXPECTED.tree)).to.equal(32n);

    // compliance {pkX, pkY, version} at base+0/+1/+2
    expect(await slotValue(proxyAddr, EXPECTED.compliance)).to.equal(BASE8_X);
    expect(
      await slotValue(proxyAddr, addSlot(EXPECTED.compliance, 1n)),
    ).to.equal(BASE8_Y);
    expect(
      await slotValue(proxyAddr, addSlot(EXPECTED.compliance, 2n)),
    ).to.equal(1n);

    // verifiers[DEPOSIT=0] in the verifiers mapping
    const depositSlot = mappingSlot("uint256", 0, EXPECTED.verifiers);
    expect(await slotValue(proxyAddr, depositSlot)).to.equal(
      BigInt(verifiers[0]),
    );

    // reentrancy guard initialized to NOT_ENTERED at OZ's canonical namespace
    expect(await slotValue(proxyAddr, REENTRANCY_LOCATION)).to.equal(1n);
  });

  it("initialize set compliance key at version 1 and all 10 verifiers (init-path)", async function () {
    const [x, y, version] = await darkpool.complianceKey();
    expect(x).to.equal(BASE8_X);
    expect(y).to.equal(BASE8_Y);
    expect(version).to.equal(1n);

    for (let i = 0; i < VERIFIER_COUNT; i++) {
      expect(await darkpool.verifier(i), `verifier(${i})`).to.equal(
        verifiers[i],
      );
      expect(await darkpool.verifier(i)).to.not.equal(ZeroHash);
    }
    // slot0 genesis seeded: real notes start at index 1 and the root is chain-specific (non-zero).
    expect(await darkpool.getNextLeafIndex()).to.equal(1n);
    expect(await darkpool.getCurrentRoot()).to.not.equal(ZeroHash);
  });

  it("granted governance roles to the passed-in addresses, not the deployer", async function () {
    const DEFAULT_ADMIN_ROLE = ZeroHash;
    const PAUSER_ROLE = await darkpool.PAUSER_ROLE();
    const UPGRADER_ROLE = await darkpool.UPGRADER_ROLE();
    expect(await darkpool.hasRole(DEFAULT_ADMIN_ROLE, admin)).to.equal(true);
    expect(await darkpool.hasRole(PAUSER_ROLE, pauser)).to.equal(true);
    expect(await darkpool.hasRole(UPGRADER_ROLE, upgrader)).to.equal(true);
    expect(await darkpool.hasRole(UPGRADER_ROLE, outsider.address)).to.equal(
      false,
    );
  });

  it("rejects a second initialize on the proxy", async function () {
    await expect(darkpool.initialize(initParams)).to.be.revertedWithCustomError(
      darkpool,
      "InvalidInitialization",
    );
  });

  it("rejects initialize on the raw implementation (disabled initializers)", async function () {
    const impl = darkpool.attach(implAddr) as unknown as DarkPool;
    await expect(impl.initialize(initParams)).to.be.revertedWithCustomError(
      darkpool,
      "InvalidInitialization",
    );
  });

  it("rejects upgradeToAndCall from a non-UPGRADER account", async function () {
    await expect(
      darkpool.connect(outsider).upgradeToAndCall(implAddr, "0x"),
    ).to.be.revertedWithCustomError(
      darkpool,
      "AccessControlUnauthorizedAccount",
    );
  });
});
