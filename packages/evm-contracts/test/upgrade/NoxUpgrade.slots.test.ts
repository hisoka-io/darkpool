import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { AbiCoder, keccak256, toBeHex, toUtf8Bytes, ZeroHash } from "ethers";
import type {
  NoxRegistry,
  NoxRewardPool,
  MockERC20,
  MockNoxRegistry,
} from "../../typechain-types";

const abi = AbiCoder.defaultAbiCoder();

function erc7201(id: string): string {
  const inner = BigInt(keccak256(toUtf8Bytes(id)));
  const mask = (1n << 256n) - 1n - 0xffn;
  const slot = BigInt(keccak256(abi.encode(["uint256"], [inner - 1n]))) & mask;
  return toBeHex(slot, 32);
}

function addSlot(base: string, offset: bigint): string {
  return toBeHex(BigInt(base) + offset, 32);
}

async function slotValue(addr: string, slot: string): Promise<bigint> {
  return BigInt(await ethers.provider.getStorage(addr, slot));
}

// The *_LOCATION constants hardcoded in the Nox contracts; the ERC-7201 formula must reproduce them, and a
// raw-storage read must find init values at them (catching a typo that the plugin's source-string scan misses).
const REGISTRY_LOCATION =
  "0xe2348d1bc3620e4f532594e661dc0600650faeb9b23105efb1d75c3e0e027400";
const REWARDPOOL_LOCATION =
  "0x54fc6109d79aa70b8d075edff760cc58b2a4f172bcefb22efc43c410f648fa00";
const REENTRANCY_LOCATION =
  "0x9b779b17422d0df92223018b32b4d1fa46e071723d6817e2486d003becc55f00";

// Every OZ base whose storage these proxies inherit. A Nox namespace colliding with one silently corrupts
// roles/pause/init state; the reentrancy guard intentionally REUSES the ReentrancyGuard namespace.
const OZ_NAMESPACES = [
  "openzeppelin.storage.AccessControl",
  "openzeppelin.storage.Pausable",
  "openzeppelin.storage.Initializable",
  "openzeppelin.storage.AccessControlDefaultAdminRules",
  "openzeppelin.storage.ReentrancyGuard",
];

const MIN_STAKE = ethers.parseEther("1000");
const MIN_STAKE_FLOOR = ethers.parseEther("1");
const UNSTAKE_DELAY = 7 * 24 * 60 * 60;
const SPHINX_KEY = keccak256(toUtf8Bytes("relayer-sphinx-key"));

describe("Nox UUPS: ERC-7201 slots + proxy init + upgrade auth", function () {
  describe("NoxRegistry", function () {
    async function deployRegistry() {
      const [admin, upgrader, outsider, relayer] = await ethers.getSigners();
      const token = (await (
        await ethers.getContractFactory("MockERC20")
      ).deploy("StakeToken", "STK", 18)) as unknown as MockERC20;

      const RegistryFactory = await ethers.getContractFactory("NoxRegistry");
      const registry = (await upgrades.deployProxy(
        RegistryFactory,
        [
          [
            0,
            admin.address,
            await token.getAddress(),
            MIN_STAKE,
            UNSTAKE_DELAY,
            MIN_STAKE_FLOOR,
            admin.address,
            admin.address,
            upgrader.address,
          ],
        ],
        { kind: "uups" },
      )) as unknown as NoxRegistry;
      await registry.waitForDeployment();

      return { registry, token, admin, upgrader, outsider, relayer };
    }

    it("reproduces REGISTRY_LOCATION from ERC-7201 and stays collision-free", function () {
      expect(erc7201("hisoka.nox.registry")).to.equal(REGISTRY_LOCATION);
      for (const ns of OZ_NAMESPACES) {
        expect(erc7201(ns), `registry vs ${ns}`).to.not.equal(
          REGISTRY_LOCATION,
        );
      }
      // The reentrancy guard deliberately reuses OZ's canonical namespace, not a Nox-specific one.
      expect(erc7201("openzeppelin.storage.ReentrancyGuard")).to.equal(
        REENTRANCY_LOCATION,
      );
    });

    it("lands config + reentrancy status at the registry ERC-7201 slots", async function () {
      const { registry, token } = await loadFixture(deployRegistry);
      const proxy = await registry.getAddress();

      expect(await slotValue(proxy, REGISTRY_LOCATION)).to.equal(
        BigInt(await token.getAddress()),
      );
      expect(await slotValue(proxy, addSlot(REGISTRY_LOCATION, 1n))).to.equal(
        MIN_STAKE_FLOOR,
      );
      expect(await slotValue(proxy, addSlot(REGISTRY_LOCATION, 2n))).to.equal(
        MIN_STAKE,
      );
      expect(await slotValue(proxy, addSlot(REGISTRY_LOCATION, 3n))).to.equal(
        BigInt(UNSTAKE_DELAY),
      );
      expect(await slotValue(proxy, REENTRANCY_LOCATION)).to.equal(1n);
    });

    it("granted governance roles to the passed-in addresses, not the deployer", async function () {
      const { registry, admin, upgrader, outsider } =
        await loadFixture(deployRegistry);
      const UPGRADER_ROLE = await registry.UPGRADER_ROLE();
      expect(await registry.hasRole(ZeroHash, admin.address)).to.equal(true);
      expect(await registry.hasRole(UPGRADER_ROLE, upgrader.address)).to.equal(
        true,
      );
      expect(await registry.hasRole(UPGRADER_ROLE, admin.address)).to.equal(
        false,
      );
      expect(await registry.hasRole(UPGRADER_ROLE, outsider.address)).to.equal(
        false,
      );
    });

    it("rejects upgradeToAndCall from non-UPGRADER accounts (incl. the admin)", async function () {
      const { registry, admin, outsider } = await loadFixture(deployRegistry);
      const impl = await upgrades.erc1967.getImplementationAddress(
        await registry.getAddress(),
      );
      for (const who of [outsider, admin]) {
        await expect(
          registry.connect(who).upgradeToAndCall(impl, "0x"),
        ).to.be.revertedWithCustomError(
          registry,
          "AccessControlUnauthorizedAccount",
        );
      }
    });

    it("preserves relayer state byte-identical across a UPGRADER-authorized upgrade", async function () {
      const { registry, admin, upgrader, relayer } = await deployRegistry();
      const proxy = await registry.getAddress();

      await registry
        .connect(admin)
        .registerPrivileged(relayer.address, SPHINX_KEY, "u", "i", "m", 3);
      expect(await registry.relayerCount()).to.equal(1n);
      expect(await registry.isActiveRelayer(relayer.address)).to.equal(true);
      const fingerprintBefore = await registry.topologyFingerprint();

      const V2 = await ethers.getContractFactory("NoxRegistryV2Mock", upgrader);
      const upgraded = (await upgrades.upgradeProxy(proxy, V2, {
        kind: "uups",
      })) as unknown as NoxRegistry & { version(): Promise<bigint> };
      await upgraded.waitForDeployment();

      expect(await upgraded.version()).to.equal(2n);
      expect(await upgraded.relayerCount()).to.equal(1n);
      expect(await upgraded.isActiveRelayer(relayer.address)).to.equal(true);
      expect(await upgraded.topologyFingerprint()).to.equal(fingerprintBefore);
    });
  });

  describe("NoxRewardPool", function () {
    async function deployRewardPool() {
      const [admin, upgrader, outsider] = await ethers.getSigners();
      const token = (await (
        await ethers.getContractFactory("MockERC20")
      ).deploy("GasToken", "GAS", 18)) as unknown as MockERC20;
      const mockRegistry = (await (
        await ethers.getContractFactory("MockNoxRegistry")
      ).deploy()) as unknown as MockNoxRegistry;

      const PoolFactory = await ethers.getContractFactory("NoxRewardPool");
      const pool = (await upgrades.deployProxy(
        PoolFactory,
        [
          [
            0,
            admin.address,
            await mockRegistry.getAddress(),
            admin.address,
            admin.address,
            upgrader.address,
          ],
        ],
        { kind: "uups" },
      )) as unknown as NoxRewardPool;
      await pool.waitForDeployment();

      return { pool, token, mockRegistry, admin, upgrader, outsider };
    }

    it("reproduces REWARDPOOL_LOCATION from ERC-7201 and stays collision-free", function () {
      expect(erc7201("hisoka.nox.rewardpool")).to.equal(REWARDPOOL_LOCATION);
      for (const ns of OZ_NAMESPACES) {
        expect(erc7201(ns), `rewardpool vs ${ns}`).to.not.equal(
          REWARDPOOL_LOCATION,
        );
      }
      expect(REWARDPOOL_LOCATION).to.not.equal(REGISTRY_LOCATION);
    });

    it("lands the registry link + reentrancy status at the reward-pool ERC-7201 slots", async function () {
      const { pool, mockRegistry } = await loadFixture(deployRewardPool);
      const proxy = await pool.getAddress();

      expect(await slotValue(proxy, REWARDPOOL_LOCATION)).to.equal(
        BigInt(await mockRegistry.getAddress()),
      );
      expect(await slotValue(proxy, REENTRANCY_LOCATION)).to.equal(1n);
    });

    it("granted governance roles to the passed-in addresses, not the deployer", async function () {
      const { pool, admin, upgrader, outsider } =
        await loadFixture(deployRewardPool);
      const UPGRADER_ROLE = await pool.UPGRADER_ROLE();
      expect(await pool.hasRole(ZeroHash, admin.address)).to.equal(true);
      expect(await pool.hasRole(UPGRADER_ROLE, upgrader.address)).to.equal(
        true,
      );
      expect(await pool.hasRole(UPGRADER_ROLE, admin.address)).to.equal(false);
      expect(await pool.hasRole(UPGRADER_ROLE, outsider.address)).to.equal(
        false,
      );
    });

    it("rejects upgradeToAndCall from non-UPGRADER accounts (incl. the admin)", async function () {
      const { pool, admin, outsider } = await loadFixture(deployRewardPool);
      const impl = await upgrades.erc1967.getImplementationAddress(
        await pool.getAddress(),
      );
      for (const who of [outsider, admin]) {
        await expect(
          pool.connect(who).upgradeToAndCall(impl, "0x"),
        ).to.be.revertedWithCustomError(
          pool,
          "AccessControlUnauthorizedAccount",
        );
      }
    });

    it("preserves collected-fee accounting state across a UPGRADER-authorized upgrade", async function () {
      const { pool, token, mockRegistry, admin, upgrader } =
        await deployRewardPool();
      const proxy = await pool.getAddress();
      const asset = await token.getAddress();

      await pool.connect(admin).setAssetStatus(asset, true);
      expect(await pool.isSupportedAsset(asset)).to.equal(true);
      const registryLinkBefore = await pool.noxRegistry();
      expect(registryLinkBefore).to.equal(await mockRegistry.getAddress());

      const V2 = await ethers.getContractFactory(
        "NoxRewardPoolV2Mock",
        upgrader,
      );
      const upgraded = (await upgrades.upgradeProxy(proxy, V2, {
        kind: "uups",
      })) as unknown as NoxRewardPool & { version(): Promise<bigint> };
      await upgraded.waitForDeployment();

      expect(await upgraded.version()).to.equal(2n);
      expect(await upgraded.isSupportedAsset(asset)).to.equal(true);
      expect(await upgraded.noxRegistry()).to.equal(registryLinkBefore);
    });
  });
});
