import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import { AbiCoder, keccak256, toBeHex, toUtf8Bytes } from "ethers";
import type {
  DarkPool,
  DarkPool__factory,
  DarkPoolV2Mock__factory,
} from "../../typechain-types";

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

const UUPS_OPTS = {
  kind: "uups" as const,
  unsafeAllow: ["external-library-linking" as const],
};

/** Deploy a DarkPool proxy with DISTINCT admin/pauser/upgrader holders (random verifiers; this suite
 * exercises only the proxy/role machinery, never a real proof path). */
async function deployDistinctRoles() {
  const [admin, pauser, upgrader, outsider] = await ethers.getSigners();

  const pos = await (await ethers.getContractFactory("Poseidon2")).deploy();
  await pos.waitForDeployment();
  const posAddr = await pos.getAddress();

  const DarkPoolFactory = (await ethers.getContractFactory("DarkPool", {
    libraries: { Poseidon2: posAddr },
  })) as unknown as DarkPool__factory;

  const stub = await (await ethers.getContractFactory("StubVerifier")).deploy();
  await stub.waitForDeployment();
  const stubAddr = await stub.getAddress();
  const verifierAddrs = Array.from({ length: 10 }, () => stubAddr);
  const params: DarkPool.InitParamsStruct = {
    depositVerifier: verifierAddrs[0],
    withdrawVerifier: verifierAddrs[1],
    transferVerifier: verifierAddrs[2],
    joinVerifier: verifierAddrs[3],
    splitVerifier: verifierAddrs[4],
    publicClaimVerifier: verifierAddrs[5],
    withdrawMultisigVerifier: verifierAddrs[6],
    transferMultisigVerifier: verifierAddrs[7],
    splitMultisigVerifier: verifierAddrs[8],
    joinMultisigVerifier: verifierAddrs[9],
    compliancePkX: BASE8_X,
    compliancePkY: BASE8_Y,
    initialAdminDelay: 0, // admin holds DEFAULT_ADMIN immediately
    initialAdmin: admin.address,
    pauser: pauser.address,
    upgrader: upgrader.address,
  };

  const proxy = (await upgrades.deployProxy(DarkPoolFactory, [params], {
    ...UUPS_OPTS,
    initializer: "initialize",
  })) as unknown as DarkPool;
  await proxy.waitForDeployment();
  const proxyAddr = await proxy.getAddress();

  const V2Factory = (await ethers.getContractFactory("DarkPoolV2Mock", {
    libraries: { Poseidon2: posAddr },
  })) as unknown as DarkPoolV2Mock__factory;

  return {
    proxy,
    proxyAddr,
    DarkPoolFactory,
    V2Factory,
    params,
    admin,
    pauser,
    upgrader,
    outsider,
  };
}

describe("UUPS upgrade-safety (CI-7)", function () {
  it("reverts UUPSUnauthorizedCallContext on upgradeToAndCall against the raw impl", async function () {
    const { proxyAddr, DarkPoolFactory, upgrader } =
      await deployDistinctRoles();
    const implAddr = await upgrades.erc1967.getImplementationAddress(proxyAddr);
    const impl = DarkPoolFactory.attach(implAddr) as unknown as DarkPool;

    // onlyProxy runs before access control: a delegate-less call on the logic contract must revert.
    await expect(
      impl.connect(upgrader).upgradeToAndCall(implAddr, "0x"),
    ).to.be.revertedWithCustomError(impl, "UUPSUnauthorizedCallContext");
  });

  it("reverts AccessControlUnauthorizedAccount for an EOA upgrade and only UPGRADER succeeds", async function () {
    const { proxy, proxyAddr, V2Factory, upgrader, outsider } =
      await deployDistinctRoles();

    const v2impl = await V2Factory.deploy();
    await v2impl.waitForDeployment();
    const v2implAddr = await v2impl.getAddress();

    await expect(
      proxy.connect(outsider).upgradeToAndCall(v2implAddr, "0x"),
    ).to.be.revertedWithCustomError(proxy, "AccessControlUnauthorizedAccount");

    await proxy.connect(upgrader).upgradeToAndCall(v2implAddr, "0x");

    const upgraded = V2Factory.attach(proxyAddr) as unknown as DarkPool & {
      version(): Promise<bigint>;
    };
    expect(await upgraded.version()).to.equal(2n);
  });

  it("locks the impl via _disableInitializers: direct initialize reverts and _initialized == uint64.max", async function () {
    const { proxyAddr, DarkPoolFactory, params } = await deployDistinctRoles();
    const implAddr = await upgrades.erc1967.getImplementationAddress(proxyAddr);
    const impl = DarkPoolFactory.attach(implAddr) as unknown as DarkPool;

    await expect(impl.initialize(params)).to.be.revertedWithCustomError(
      impl,
      "InvalidInitialization",
    );

    const initSlot = erc7201("openzeppelin.storage.Initializable");
    const raw = BigInt(await ethers.provider.getStorage(implAddr, initSlot));
    const initialized = raw & ((1n << 64n) - 1n);
    expect(initialized).to.equal((1n << 64n) - 1n);
  });

  it("rejects a second initialize on the proxy", async function () {
    const { proxy, params } = await deployDistinctRoles();
    await expect(proxy.initialize(params)).to.be.revertedWithCustomError(
      proxy,
      "InvalidInitialization",
    );
  });

  it("reverts ERC1967InvalidImplementation when upgrading to a non-UUPS target", async function () {
    const { proxy, upgrader } = await deployDistinctRoles();

    const notUUPS = await (
      await ethers.getContractFactory("NotUUPSMock")
    ).deploy();
    await notUUPS.waitForDeployment();

    // proxiableUUID cross-check in _upgradeToAndCallUUPS rejects a target that is not itself upgradeable.
    await expect(
      proxy
        .connect(upgrader)
        .upgradeToAndCall(await notUUPS.getAddress(), "0x"),
    ).to.be.revertedWithCustomError(proxy, "ERC1967InvalidImplementation");
  });

  it("gates roles: guardian PAUSER can pause but cannot unpause or upgrade; admin can unpause", async function () {
    const { proxy, proxyAddr, admin, pauser } = await deployDistinctRoles();
    const implAddr = await upgrades.erc1967.getImplementationAddress(proxyAddr);

    await proxy.connect(pauser).pause();
    expect(await proxy.paused()).to.equal(true);

    await expect(proxy.connect(pauser).unpause()).to.be.revertedWithCustomError(
      proxy,
      "AccessControlUnauthorizedAccount",
    );

    await expect(
      proxy.connect(pauser).upgradeToAndCall(implAddr, "0x"),
    ).to.be.revertedWithCustomError(proxy, "AccessControlUnauthorizedAccount");

    await proxy.connect(admin).unpause();
    expect(await proxy.paused()).to.equal(false);
  });
});
