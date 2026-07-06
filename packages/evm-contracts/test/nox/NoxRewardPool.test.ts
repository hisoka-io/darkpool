import { assert, expect } from "chai";
import { ethers, upgrades } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import {
  NoxRewardPool,
  MockERC20,
  MockNoxRegistry,
  NoxRegistry,
} from "../../typechain-types";

describe("NoxRewardPool (Treasury)", function () {
  async function deployFixture() {
    const [admin, distributor, user, relayer1, relayer2, attacker] =
      await ethers.getSigners();

    const TokenFactory = await ethers.getContractFactory("MockERC20");
    const token = (await TokenFactory.deploy(
      "GasToken",
      "GAS",
      18,
    )) as unknown as MockERC20;
    const unsupportedToken = (await TokenFactory.deploy(
      "BadToken",
      "BAD",
      18,
    )) as unknown as MockERC20;

    const RegistryFactory = await ethers.getContractFactory("MockNoxRegistry");
    const mockRegistry =
      (await RegistryFactory.deploy()) as unknown as MockNoxRegistry;
    await mockRegistry.setActive(relayer1.address, true);
    await mockRegistry.setActive(relayer2.address, true);

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
          admin.address,
        ],
      ],
      { kind: "uups" },
    )) as unknown as NoxRewardPool;
    await pool.waitForDeployment();

    const DISTRIBUTOR_ROLE = await pool.DISTRIBUTOR_ROLE();
    const ADMIN_ROLE = await pool.ADMIN_ROLE();
    await pool.connect(admin).grantRole(DISTRIBUTOR_ROLE, distributor.address);

    await pool.connect(admin).setAssetStatus(await token.getAddress(), true);

    await token.mint(user.address, ethers.parseEther("1000"));
    await token
      .connect(user)
      .approve(await pool.getAddress(), ethers.MaxUint256);

    return {
      pool,
      mockRegistry,
      token,
      unsupportedToken,
      admin,
      distributor,
      user,
      relayer1,
      relayer2,
      attacker,
      DISTRIBUTOR_ROLE,
      ADMIN_ROLE,
    };
  }

  describe("Configuration & Access Control", function () {
    it("should allow Admin to whitelist assets", async function () {
      const { pool, admin, unsupportedToken } =
        await loadFixture(deployFixture);
      const asset = await unsupportedToken.getAddress();

      await expect(pool.connect(admin).setAssetStatus(asset, true))
        .to.emit(pool, "AssetStatusChanged")
        .withArgs(asset, true);

      assert((await pool.isSupportedAsset(asset)) === true);
    });

    it("should revert if non-Admin tries to whitelist", async function () {
      const { pool, attacker, token } = await loadFixture(deployFixture);

      await expect(
        pool.connect(attacker).setAssetStatus(await token.getAddress(), false),
      ).to.be.revertedWithCustomError(pool, "AccessControlUnauthorizedAccount");
    });

    it("should revert setting status for address(0)", async function () {
      const { pool, admin } = await loadFixture(deployFixture);
      await expect(
        pool.connect(admin).setAssetStatus(ethers.ZeroAddress, true),
      ).to.be.revertedWithCustomError(pool, "ZeroAddress");
    });
  });

  describe("Deposits (Inflow)", function () {
    it("should accept valid deposits and update accounting", async function () {
      const { pool, token, user } = await loadFixture(deployFixture);
      const amount = ethers.parseEther("100");

      await expect(
        pool.connect(user).depositRewards(await token.getAddress(), amount),
      )
        .to.emit(pool, "RewardsDeposited")
        .withArgs(await token.getAddress(), user.address, amount);

      expect(await pool.totalCollected(await token.getAddress())).to.equal(
        amount,
      );
      expect(await token.balanceOf(await pool.getAddress())).to.equal(amount);
    });

    it("should revert deposit of 0 amount", async function () {
      const { pool, token, user } = await loadFixture(deployFixture);
      await expect(
        pool.connect(user).depositRewards(await token.getAddress(), 0),
      ).to.be.revertedWithCustomError(pool, "ZeroAmount");
    });

    it("should revert deposit of unsupported asset", async function () {
      const { pool, unsupportedToken, user } = await loadFixture(deployFixture);
      await expect(
        pool
          .connect(user)
          .depositRewards(await unsupportedToken.getAddress(), 100),
      ).to.be.revertedWithCustomError(pool, "AssetNotSupported");
    });
  });

  describe("Distributions (Outflow)", function () {
    it("should allow Distributor to distribute batch rewards", async function () {
      const { pool, token, user, distributor, relayer1, relayer2 } =
        await loadFixture(deployFixture);

      await pool
        .connect(user)
        .depositRewards(await token.getAddress(), ethers.parseEther("100"));

      const recipients = [relayer1.address, relayer2.address];
      const amounts = [ethers.parseEther("40"), ethers.parseEther("60")];

      await expect(
        pool
          .connect(distributor)
          .distributeRewards(await token.getAddress(), recipients, amounts),
      )
        .to.emit(pool, "RewardsDistributed")
        .withArgs(await token.getAddress(), ethers.parseEther("100"), 2);

      expect(await token.balanceOf(relayer1.address)).to.equal(amounts[0]);
      expect(await token.balanceOf(relayer2.address)).to.equal(amounts[1]);
      expect(await pool.totalDistributed(await token.getAddress())).to.equal(
        ethers.parseEther("100"),
      );
    });

    it("should revert if array lengths mismatch", async function () {
      const { pool, token, distributor, relayer1 } =
        await loadFixture(deployFixture);
      await expect(
        pool
          .connect(distributor)
          .distributeRewards(
            await token.getAddress(),
            [relayer1.address],
            [100, 200],
          ),
      ).to.be.revertedWithCustomError(pool, "ArrayLengthMismatch");
    });

    it("should revert if distributing unsupported asset", async function () {
      const { pool, unsupportedToken, distributor, relayer1 } =
        await loadFixture(deployFixture);
      await expect(
        pool
          .connect(distributor)
          .distributeRewards(
            await unsupportedToken.getAddress(),
            [relayer1.address],
            [100],
          ),
      ).to.be.revertedWithCustomError(pool, "AssetNotSupported");
    });

    it("should revert if recipient is address(0)", async function () {
      const { pool, token, distributor } = await loadFixture(deployFixture);
      await expect(
        pool
          .connect(distributor)
          .distributeRewards(
            await token.getAddress(),
            [ethers.ZeroAddress],
            [100],
          ),
      ).to.be.revertedWithCustomError(pool, "ZeroAddress");
    });

    it("should revert distributing to a non-registered recipient", async function () {
      const { pool, token, user, distributor } =
        await loadFixture(deployFixture);
      // `user` is not marked active in the mock registry.
      await expect(
        pool
          .connect(distributor)
          .distributeRewards(await token.getAddress(), [user.address], [100]),
      ).to.be.revertedWithCustomError(pool, "RecipientNotRegistered");
    });

    it("gates distribution on the real NoxRegistry", async function () {
      const [admin, , user, relayer1] = await ethers.getSigners();
      const TokenFactory = await ethers.getContractFactory("MockERC20");
      const token = (await TokenFactory.deploy(
        "GasToken",
        "GAS",
        18,
      )) as unknown as MockERC20;
      const RegistryFactory = await ethers.getContractFactory("NoxRegistry");
      const registry = (await upgrades.deployProxy(
        RegistryFactory,
        [
          [
            0,
            admin.address,
            await token.getAddress(),
            ethers.parseEther("1"),
            86400,
            ethers.parseEther("1"),
            admin.address,
            admin.address,
            admin.address,
          ],
        ],
        { kind: "uups" },
      )) as unknown as NoxRegistry;
      await registry.waitForDeployment();
      await registry
        .connect(admin)
        .registerPrivileged(
          relayer1.address,
          ethers.randomBytes(32),
          "/ip4/1.1.1.1/tcp/1",
          "",
          "",
          3,
        );

      const PoolFactory = await ethers.getContractFactory("NoxRewardPool");
      const pool = (await upgrades.deployProxy(
        PoolFactory,
        [
          [
            0,
            admin.address,
            await registry.getAddress(),
            admin.address,
            admin.address,
            admin.address,
          ],
        ],
        { kind: "uups" },
      )) as unknown as NoxRewardPool;
      await pool.waitForDeployment();
      const asset = await token.getAddress();
      await pool.connect(admin).setAssetStatus(asset, true);
      await token.mint(user.address, 1000);
      await token
        .connect(user)
        .approve(await pool.getAddress(), ethers.MaxUint256);
      await pool.connect(user).depositRewards(asset, 1000);

      // A relayer registered on the real registry is eligible.
      await expect(
        pool.connect(admin).distributeRewards(asset, [relayer1.address], [500]),
      ).to.emit(pool, "RewardsDistributed");
      expect(await token.balanceOf(relayer1.address)).to.equal(500n);

      // A non-registered address is rejected by the real registry gate.
      await expect(
        pool.connect(admin).distributeRewards(asset, [user.address], [100]),
      ).to.be.revertedWithCustomError(pool, "RecipientNotRegistered");
    });

    it("should revert if non-Distributor tries to distribute", async function () {
      const { pool, token, attacker, relayer1 } =
        await loadFixture(deployFixture);
      await expect(
        pool
          .connect(attacker)
          .distributeRewards(
            await token.getAddress(),
            [relayer1.address],
            [100],
          ),
      ).to.be.revertedWithCustomError(pool, "AccessControlUnauthorizedAccount");
    });
  });

  describe("Emergency Functions", function () {
    it("rescues foreign tokens and free surplus but never the committed reward float", async function () {
      const { pool, token, unsupportedToken, admin, user } =
        await loadFixture(deployFixture);
      const asset = await token.getAddress();

      // Deposit rewards -> a committed float that must never be rescuable.
      await pool.connect(user).depositRewards(asset, 1000);
      await expect(
        pool.connect(admin).rescueFunds(asset, admin.address, 1000),
      ).to.be.revertedWithCustomError(pool, "ExceedsRescuableBalance");

      // De-whitelisting the reward asset does NOT unlock the committed float; the accounting invariant,
      // not the whitelist flag, protects it.
      await pool.connect(admin).setAssetStatus(asset, false);
      await expect(
        pool.connect(admin).rescueFunds(asset, admin.address, 1000),
      ).to.be.revertedWithCustomError(pool, "ExceedsRescuableBalance");

      // Foreign tokens sent here by mistake are fully rescuable.
      await unsupportedToken.mint(await pool.getAddress(), 1000);
      await expect(
        pool
          .connect(admin)
          .rescueFunds(
            await unsupportedToken.getAddress(),
            admin.address,
            1000,
          ),
      )
        .to.emit(pool, "FundsRescued")
        .withArgs(await unsupportedToken.getAddress(), admin.address, 1000);
    });

    it("rescues exactly the free surplus above the committed float", async function () {
      const { pool, token, admin, user } = await loadFixture(deployFixture);
      const asset = await token.getAddress();
      await pool.connect(user).depositRewards(asset, 600); // committed float
      await token.mint(await pool.getAddress(), 400); // free surplus, balance 1000

      await expect(
        pool.connect(admin).rescueFunds(asset, admin.address, 401),
      ).to.be.revertedWithCustomError(pool, "ExceedsRescuableBalance");
      await expect(
        pool.connect(admin).rescueFunds(asset, admin.address, 400),
      ).to.emit(pool, "FundsRescued");
    });

    it("should pause and block deposits/distributions", async function () {
      const {
        pool,
        admin,
        user,
        distributor,
        token,
        unsupportedToken,
        relayer1,
      } = await loadFixture(deployFixture);

      await pool.connect(admin).pause();

      await expect(
        pool.connect(user).depositRewards(await token.getAddress(), 100),
      ).to.be.revertedWithCustomError(pool, "EnforcedPause");

      await expect(
        pool
          .connect(distributor)
          .distributeRewards(
            await token.getAddress(),
            [relayer1.address],
            [100],
          ),
      ).to.be.revertedWithCustomError(pool, "EnforcedPause");

      await unsupportedToken.mint(await pool.getAddress(), 100);
      await expect(
        pool
          .connect(admin)
          .rescueFunds(await unsupportedToken.getAddress(), admin.address, 100),
      ).to.not.be.reverted;
    });
  });
});
