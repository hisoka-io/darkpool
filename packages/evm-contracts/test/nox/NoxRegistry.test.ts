import { assert, expect } from "chai";
import { ethers, upgrades } from "hardhat";
import { loadFixture, time } from "@nomicfoundation/hardhat-network-helpers";
import { NoxRegistry, MockERC20 } from "../../typechain-types";

describe("NoxRegistry (Identity & Staking)", function () {
  const MIN_STAKE = ethers.parseEther("1000");
  const MIN_STAKE_FLOOR = ethers.parseEther("1");
  const UNSTAKE_DELAY = 7 * 24 * 60 * 60; // 7 Days

  async function deployFixture() {
    const [admin, slasher, relayer, relayer2, relayer3, attacker] =
      await ethers.getSigners();

    const TokenFactory = await ethers.getContractFactory("MockERC20");
    const token = (await TokenFactory.deploy(
      "StakeToken",
      "STK",
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
          MIN_STAKE,
          UNSTAKE_DELAY,
          MIN_STAKE_FLOOR,
          admin.address,
          admin.address,
          admin.address,
        ],
      ],
      { kind: "uups" },
    )) as unknown as NoxRegistry;
    await registry.waitForDeployment();

    const SLASHER_ROLE = await registry.SLASHER_ROLE();
    await registry.connect(admin).grantRole(SLASHER_ROLE, slasher.address);

    for (const r of [relayer, relayer2, relayer3]) {
      await token.mint(r.address, ethers.parseEther("10000"));
      await token
        .connect(r)
        .approve(await registry.getAddress(), ethers.MaxUint256);
    }

    return {
      registry,
      token,
      admin,
      slasher,
      relayer,
      relayer2,
      relayer3,
      attacker,
      SLASHER_ROLE,
    };
  }

  // Off-chain keccak256(abi.encodePacked(address))
  function computeAddressHash(address: string): bigint {
    return BigInt(
      ethers.keccak256(ethers.solidityPacked(["address"], [address])),
    );
  }

  function xorHashes(...hashes: bigint[]): string {
    let result = 0n;
    for (const h of hashes) {
      result ^= h;
    }
    return ethers.toBeHex(result, 32);
  }

  describe("XOR Topology Fingerprint", function () {
    const sphinxKey = ethers.randomBytes(32);
    const url = "/ip4/1.2.3.4/tcp/9000";
    const ROLE_FULL = 3;

    it("should start with zero fingerprint (empty set)", async function () {
      const { registry } = await loadFixture(deployFixture);
      const fingerprint = await registry.topologyFingerprint();
      expect(fingerprint).to.equal(ethers.ZeroHash);
    });

    it("should update fingerprint on registration", async function () {
      const { registry, admin, relayer } = await loadFixture(deployFixture);
      await registry
        .connect(admin)
        .registerPrivileged(relayer.address, sphinxKey, url, "", "", ROLE_FULL);

      const fingerprint = await registry.topologyFingerprint();
      const expected = xorHashes(computeAddressHash(relayer.address));
      expect(fingerprint).to.equal(expected);
    });

    it("should produce order-independent fingerprint", async function () {
      const { registry, admin, relayer, relayer2 } =
        await loadFixture(deployFixture);

      await registry
        .connect(admin)
        .registerPrivileged(relayer.address, sphinxKey, url, "", "", ROLE_FULL);
      await registry
        .connect(admin)
        .registerPrivileged(
          relayer2.address,
          ethers.randomBytes(32),
          "/ip4/1.2.3.5/tcp/9000",
          "",
          "",
          ROLE_FULL,
        );
      const fpOrderA = await registry.topologyFingerprint();

      const expected = xorHashes(
        computeAddressHash(relayer.address),
        computeAddressHash(relayer2.address),
      );
      expect(fpOrderA).to.equal(expected);

      const { registry: registry2, admin: admin2 } =
        await loadFixture(deployFixture);

      await registry2
        .connect(admin2)
        .registerPrivileged(
          relayer2.address,
          ethers.randomBytes(32),
          "/ip4/1.2.3.5/tcp/9000",
          "",
          "",
          ROLE_FULL,
        );
      await registry2
        .connect(admin2)
        .registerPrivileged(relayer.address, sphinxKey, url, "", "", ROLE_FULL);
      const fpOrderB = await registry2.topologyFingerprint();

      expect(fpOrderA).to.equal(fpOrderB);
    });

    it("should return to zero when all nodes unregister", async function () {
      const { registry, admin, relayer, relayer2 } =
        await loadFixture(deployFixture);

      await registry
        .connect(admin)
        .registerPrivileged(relayer.address, sphinxKey, url, "", "", ROLE_FULL);
      await registry
        .connect(admin)
        .registerPrivileged(
          relayer2.address,
          ethers.randomBytes(32),
          "/ip4/1.2.3.5/tcp/9000",
          "",
          "",
          ROLE_FULL,
        );

      await registry.connect(admin).forceUnregister(relayer.address);
      await registry.connect(admin).forceUnregister(relayer2.address);

      const fingerprint = await registry.topologyFingerprint();
      expect(fingerprint).to.equal(ethers.ZeroHash);
    });

    it("should handle re-registration correctly", async function () {
      const { registry, admin, relayer } = await loadFixture(deployFixture);

      await registry
        .connect(admin)
        .registerPrivileged(relayer.address, sphinxKey, url, "", "", ROLE_FULL);
      const fpAfterRegister = await registry.topologyFingerprint();

      await registry.connect(admin).forceUnregister(relayer.address);
      const fpAfterUnregister = await registry.topologyFingerprint();
      expect(fpAfterUnregister).to.equal(ethers.ZeroHash);

      await registry
        .connect(admin)
        .registerPrivileged(relayer.address, sphinxKey, url, "", "", ROLE_FULL);
      const fpAfterReregister = await registry.topologyFingerprint();

      expect(fpAfterReregister).to.equal(fpAfterRegister);
    });

    it("should XOR correctly with multiple nodes", async function () {
      const { registry, admin, relayer, relayer2, relayer3 } =
        await loadFixture(deployFixture);

      await registry
        .connect(admin)
        .registerPrivileged(relayer.address, sphinxKey, url, "", "", ROLE_FULL);
      await registry
        .connect(admin)
        .registerPrivileged(
          relayer2.address,
          ethers.randomBytes(32),
          "/ip4/1.2.3.5/tcp/9000",
          "",
          "",
          ROLE_FULL,
        );
      await registry
        .connect(admin)
        .registerPrivileged(
          relayer3.address,
          ethers.randomBytes(32),
          "/ip4/1.2.3.6/tcp/9000",
          "",
          "",
          ROLE_FULL,
        );

      const fingerprint = await registry.topologyFingerprint();
      const expected = xorHashes(
        computeAddressHash(relayer.address),
        computeAddressHash(relayer2.address),
        computeAddressHash(relayer3.address),
      );
      expect(fingerprint).to.equal(expected);
    });

    it("should emit TopologyFingerprintUpdated with correct values", async function () {
      const { registry, admin, relayer } = await loadFixture(deployFixture);

      const expectedNew = xorHashes(computeAddressHash(relayer.address));

      await expect(
        registry
          .connect(admin)
          .registerPrivileged(
            relayer.address,
            sphinxKey,
            url,
            "",
            "",
            ROLE_FULL,
          ),
      )
        .to.emit(registry, "TopologyFingerprintUpdated")
        .withArgs(expectedNew, ethers.ZeroHash);
    });

    it("should not change fingerprint on key rotation", async function () {
      const { registry, admin, relayer } = await loadFixture(deployFixture);

      await registry
        .connect(admin)
        .registerPrivileged(relayer.address, sphinxKey, url, "", "", ROLE_FULL);
      const fpBefore = await registry.topologyFingerprint();

      await registry.connect(relayer).rotateKey(ethers.randomBytes(32));
      const fpAfter = await registry.topologyFingerprint();

      expect(fpAfter).to.equal(fpBefore);
    });
  });

  describe("Manual Whitelisting (Privileged)", function () {
    const sphinxKey = ethers.randomBytes(32);
    const url = "/ip4/1.2.3.4/tcp/9000";
    const ROLE_FULL = 3;

    it("should allow Admin to register a privileged relayer without stake", async function () {
      const { registry, admin, relayer } = await loadFixture(deployFixture);

      await expect(
        registry
          .connect(admin)
          .registerPrivileged(
            relayer.address,
            sphinxKey,
            url,
            "",
            "",
            ROLE_FULL,
          ),
      )
        .to.emit(registry, "PrivilegedRelayerRegistered")
        .withArgs(
          relayer.address,
          ethers.hexlify(sphinxKey),
          url,
          "",
          "",
          ROLE_FULL,
        );

      const profile = await registry.relayers(relayer.address);
      assert(profile.isRegistered === true);
      expect(profile.stakedAmount).to.equal(0);
      expect(await registry.nodeRoles(relayer.address)).to.equal(ROLE_FULL);
    });

    it("should revert if non-admin tries to register privileged", async function () {
      const { registry, attacker, relayer } = await loadFixture(deployFixture);
      await expect(
        registry
          .connect(attacker)
          .registerPrivileged(
            relayer.address,
            sphinxKey,
            url,
            "",
            "",
            ROLE_FULL,
          ),
      ).to.be.revertedWithCustomError(
        registry,
        "AccessControlUnauthorizedAccount",
      );
    });

    it("should allow Admin to force unregister (ban) a node", async function () {
      const { registry, admin, relayer } = await loadFixture(deployFixture);

      await registry
        .connect(admin)
        .registerPrivileged(relayer.address, sphinxKey, url, "", "", ROLE_FULL);

      await expect(registry.connect(admin).forceUnregister(relayer.address))
        .to.emit(registry, "RelayerRemoved")
        .withArgs(relayer.address, admin.address);

      const profile = await registry.relayers(relayer.address);
      assert(profile.isRegistered === false);
    });

    it("should return remaining stake when force unregistering a community node", async function () {
      const { registry, admin, relayer, token } =
        await loadFixture(deployFixture);

      await registry
        .connect(relayer)
        .register(sphinxKey, url, "", "", MIN_STAKE, ROLE_FULL);
      const balBefore = await token.balanceOf(relayer.address);

      await registry.connect(admin).forceUnregister(relayer.address);

      const balAfter = await token.balanceOf(relayer.address);
      expect(balAfter).to.equal(balBefore + MIN_STAKE);

      const profile = await registry.relayers(relayer.address);
      assert(profile.isRegistered === false);
    });
  });

  describe("Community Registration (Staked)", function () {
    const sphinxKey = ethers.randomBytes(32);
    const url = "/ip4/1.2.3.4/tcp/9000";
    const ROLE_FULL = 3;

    it("should allow community registration with sufficient stake", async function () {
      const { registry, relayer } = await loadFixture(deployFixture);

      await expect(
        registry
          .connect(relayer)
          .register(sphinxKey, url, "", "", MIN_STAKE, ROLE_FULL),
      )
        .to.emit(registry, "RelayerRegistered")
        .withArgs(
          relayer.address,
          ethers.hexlify(sphinxKey),
          url,
          "",
          "",
          MIN_STAKE,
          ROLE_FULL,
        );

      const profile = await registry.relayers(relayer.address);
      expect(profile.isRegistered).to.equal(true);
      expect(profile.stakedAmount).to.equal(MIN_STAKE);
      expect(await registry.relayerCount()).to.equal(1);
      expect(await registry.nodeRoles(relayer.address)).to.equal(ROLE_FULL);
    });

    it("should reject registration with insufficient stake", async function () {
      const { registry, relayer } = await loadFixture(deployFixture);
      await expect(
        registry
          .connect(relayer)
          .register(sphinxKey, url, "", "", MIN_STAKE - 1n, ROLE_FULL),
      ).to.be.revertedWithCustomError(registry, "InsufficientStake");
    });

    it("should reject duplicate registration", async function () {
      const { registry, relayer } = await loadFixture(deployFixture);
      await registry
        .connect(relayer)
        .register(sphinxKey, url, "", "", MIN_STAKE, ROLE_FULL);
      await expect(
        registry
          .connect(relayer)
          .register(sphinxKey, url, "", "", MIN_STAKE, ROLE_FULL),
      ).to.be.revertedWithCustomError(registry, "AlreadyRegistered");
    });

    it("should reject registration with empty URL", async function () {
      const { registry, relayer } = await loadFixture(deployFixture);
      await expect(
        registry
          .connect(relayer)
          .register(sphinxKey, "", "", "", MIN_STAKE, ROLE_FULL),
      ).to.be.revertedWithCustomError(registry, "EmptyString");
    });

    it("should reject registration with zero sphinxKey", async function () {
      const { registry, relayer } = await loadFixture(deployFixture);
      await expect(
        registry
          .connect(relayer)
          .register(ethers.ZeroHash, url, "", "", MIN_STAKE, ROLE_FULL),
      ).to.be.revertedWithCustomError(registry, "InvalidKey");
    });

    it("should transfer tokens on registration", async function () {
      const { registry, relayer, token } = await loadFixture(deployFixture);
      const balBefore = await token.balanceOf(relayer.address);

      await registry
        .connect(relayer)
        .register(sphinxKey, url, "", "", MIN_STAKE, ROLE_FULL);

      const balAfter = await token.balanceOf(relayer.address);
      expect(balBefore - balAfter).to.equal(MIN_STAKE);
    });
  });

  describe("Staking", function () {
    const sphinxKey = ethers.randomBytes(32);
    const url = "/ip4/1.2.3.4/tcp/9000";
    const ROLE_FULL = 3;

    it("should allow adding stake", async function () {
      const { registry, relayer } = await loadFixture(deployFixture);
      await registry
        .connect(relayer)
        .register(sphinxKey, url, "", "", MIN_STAKE, ROLE_FULL);

      const extra = ethers.parseEther("500");
      await expect(registry.connect(relayer).addStake(extra))
        .to.emit(registry, "StakeAdded")
        .withArgs(relayer.address, extra);

      const profile = await registry.relayers(relayer.address);
      expect(profile.stakedAmount).to.equal(MIN_STAKE + extra);
    });

    it("should reject adding stake when not registered", async function () {
      const { registry, relayer } = await loadFixture(deployFixture);
      await expect(
        registry.connect(relayer).addStake(ethers.parseEther("100")),
      ).to.be.revertedWithCustomError(registry, "NotRegistered");
    });

    it("should reject adding zero stake", async function () {
      const { registry, relayer } = await loadFixture(deployFixture);
      await registry
        .connect(relayer)
        .register(sphinxKey, url, "", "", MIN_STAKE, ROLE_FULL);
      await expect(
        registry.connect(relayer).addStake(0),
      ).to.be.revertedWithCustomError(registry, "InvalidAmount");
    });

    it("should reject adding stake during unstake cooldown", async function () {
      const { registry, relayer } = await loadFixture(deployFixture);
      await registry
        .connect(relayer)
        .register(sphinxKey, url, "", "", MIN_STAKE, ROLE_FULL);
      await registry.connect(relayer).requestUnstake();

      await expect(
        registry.connect(relayer).addStake(ethers.parseEther("100")),
      ).to.be.revertedWithCustomError(registry, "UnstakeAlreadyRequested");
    });
  });

  describe("Exit Flow (Unstake)", function () {
    const sphinxKey = ethers.randomBytes(32);
    const url = "/ip4/1.2.3.4/tcp/9000";
    const ROLE_FULL = 3;

    it("should allow requesting unstake", async function () {
      const { registry, relayer } = await loadFixture(deployFixture);
      await registry
        .connect(relayer)
        .register(sphinxKey, url, "", "", MIN_STAKE, ROLE_FULL);

      await expect(registry.connect(relayer).requestUnstake()).to.emit(
        registry,
        "UnstakeRequested",
      );

      const profile = await registry.relayers(relayer.address);
      expect(profile.unlockTime).to.be.gt(0);
    });

    it("honors the unlock-time snapshot when config delay is later increased", async function () {
      const { registry, admin, relayer, token } =
        await loadFixture(deployFixture);
      await registry
        .connect(relayer)
        .register(sphinxKey, url, "", "", MIN_STAKE, ROLE_FULL);
      await registry.connect(relayer).requestUnstake();

      await registry.connect(admin).updateConfig(MIN_STAKE, UNSTAKE_DELAY * 5);

      await time.increase(UNSTAKE_DELAY + 1);
      const balBefore = await token.balanceOf(relayer.address);
      await registry.connect(relayer).executeUnstake();
      const balAfter = await token.balanceOf(relayer.address);
      expect(balAfter - balBefore).to.equal(MIN_STAKE);
    });

    it("should reject duplicate unstake request", async function () {
      const { registry, relayer } = await loadFixture(deployFixture);
      await registry
        .connect(relayer)
        .register(sphinxKey, url, "", "", MIN_STAKE, ROLE_FULL);
      await registry.connect(relayer).requestUnstake();

      await expect(
        registry.connect(relayer).requestUnstake(),
      ).to.be.revertedWithCustomError(registry, "UnstakeAlreadyRequested");
    });

    it("should reject execute unstake before delay", async function () {
      const { registry, relayer } = await loadFixture(deployFixture);
      await registry
        .connect(relayer)
        .register(sphinxKey, url, "", "", MIN_STAKE, ROLE_FULL);
      await registry.connect(relayer).requestUnstake();

      await expect(
        registry.connect(relayer).executeUnstake(),
      ).to.be.revertedWithCustomError(registry, "UnstakeTooEarly");
    });

    it("should allow execute unstake after delay", async function () {
      const { registry, relayer, token } = await loadFixture(deployFixture);
      await registry
        .connect(relayer)
        .register(sphinxKey, url, "", "", MIN_STAKE, ROLE_FULL);
      await registry.connect(relayer).requestUnstake();

      await time.increase(UNSTAKE_DELAY + 1);

      const balBefore = await token.balanceOf(relayer.address);
      await registry.connect(relayer).executeUnstake();
      const balAfter = await token.balanceOf(relayer.address);

      expect(balAfter - balBefore).to.equal(MIN_STAKE);

      const profile = await registry.relayers(relayer.address);
      expect(profile.isRegistered).to.equal(false);

      expect(await registry.relayerCount()).to.equal(0);

      expect(await registry.topologyFingerprint()).to.equal(ethers.ZeroHash);
    });
  });

  describe("Slashing", function () {
    const sphinxKey = ethers.randomBytes(32);
    const url = "/ip4/1.2.3.4/tcp/9000";
    const ROLE_FULL = 3;

    it("should allow slasher to slash a node", async function () {
      const { registry, relayer, slasher, token } =
        await loadFixture(deployFixture);
      await registry
        .connect(relayer)
        .register(sphinxKey, url, "", "", MIN_STAKE * 2n, ROLE_FULL);

      const slashAmount = ethers.parseEther("500");
      const slasherBalBefore = await token.balanceOf(slasher.address);

      await expect(
        registry.connect(slasher).slash(relayer.address, slashAmount),
      )
        .to.emit(registry, "Slashed")
        .withArgs(relayer.address, slashAmount, slasher.address);

      // Remaining (1500) is still >= minStake, so the node stays registered and collateralized.
      const profile = await registry.relayers(relayer.address);
      expect(profile.stakedAmount).to.equal(MIN_STAKE * 2n - slashAmount);

      const slasherBalAfter = await token.balanceOf(slasher.address);
      expect(slasherBalAfter - slasherBalBefore).to.equal(slashAmount);
    });

    it("should cap slash at available stake", async function () {
      const { registry, relayer, slasher, token } =
        await loadFixture(deployFixture);
      await registry
        .connect(relayer)
        .register(sphinxKey, url, "", "", MIN_STAKE, ROLE_FULL);

      const overSlash = MIN_STAKE + ethers.parseEther("999");
      const slasherBalBefore = await token.balanceOf(slasher.address);

      await registry.connect(slasher).slash(relayer.address, overSlash);

      const profile = await registry.relayers(relayer.address);
      expect(profile.stakedAmount).to.equal(0);

      const slasherBalAfter = await token.balanceOf(slasher.address);
      expect(slasherBalAfter - slasherBalBefore).to.equal(MIN_STAKE);
    });

    it("deregisters a relayer slashed to zero stake", async function () {
      const { registry, relayer, slasher } = await loadFixture(deployFixture);
      await registry
        .connect(relayer)
        .register(sphinxKey, url, "", "", MIN_STAKE, ROLE_FULL);
      expect((await registry.relayers(relayer.address)).isRegistered).to.equal(
        true,
      );

      await registry.connect(slasher).slash(relayer.address, MIN_STAKE);

      const profile = await registry.relayers(relayer.address);
      expect(profile.isRegistered).to.equal(false);
      expect(profile.stakedAmount).to.equal(0);
    });

    it("should reject slash from non-slasher", async function () {
      const { registry, relayer, attacker } = await loadFixture(deployFixture);
      await registry
        .connect(relayer)
        .register(sphinxKey, url, "", "", MIN_STAKE, ROLE_FULL);

      await expect(
        registry
          .connect(attacker)
          .slash(relayer.address, ethers.parseEther("100")),
      ).to.be.revertedWithCustomError(
        registry,
        "AccessControlUnauthorizedAccount",
      );
    });

    it("should reject slash of unregistered node", async function () {
      const { registry, slasher, relayer } = await loadFixture(deployFixture);
      await expect(
        registry
          .connect(slasher)
          .slash(relayer.address, ethers.parseEther("100")),
      ).to.be.revertedWithCustomError(registry, "NotRegistered");
    });
  });

  describe("Key Rotation & URL Update", function () {
    const sphinxKey = ethers.randomBytes(32);
    const url = "/ip4/1.2.3.4/tcp/9000";
    const ROLE_FULL = 3;

    it("should allow key rotation", async function () {
      const { registry, relayer } = await loadFixture(deployFixture);
      await registry
        .connect(relayer)
        .register(sphinxKey, url, "", "", MIN_STAKE, ROLE_FULL);

      const newKey = ethers.randomBytes(32);
      await expect(registry.connect(relayer).rotateKey(newKey))
        .to.emit(registry, "KeyRotated")
        .withArgs(relayer.address, ethers.hexlify(newKey));

      const profile = await registry.relayers(relayer.address);
      expect(profile.sphinxKey).to.equal(ethers.hexlify(newKey));
    });

    it("should reject key rotation when not registered", async function () {
      const { registry, relayer } = await loadFixture(deployFixture);
      await expect(
        registry.connect(relayer).rotateKey(ethers.randomBytes(32)),
      ).to.be.revertedWithCustomError(registry, "NotRegistered");
    });

    it("should reject key rotation to zero key", async function () {
      const { registry, relayer } = await loadFixture(deployFixture);
      await registry
        .connect(relayer)
        .register(sphinxKey, url, "", "", MIN_STAKE, ROLE_FULL);

      await expect(
        registry.connect(relayer).rotateKey(ethers.ZeroHash),
      ).to.be.revertedWithCustomError(registry, "InvalidKey");
    });

    it("should allow URL update", async function () {
      const { registry, relayer } = await loadFixture(deployFixture);
      await registry
        .connect(relayer)
        .register(sphinxKey, url, "", "", MIN_STAKE, ROLE_FULL);

      const newUrl = "/ip4/5.6.7.8/tcp/9001";
      await expect(registry.connect(relayer).updateUrl(newUrl))
        .to.emit(registry, "RelayerUpdated")
        .withArgs(relayer.address, newUrl);

      const profile = await registry.relayers(relayer.address);
      expect(profile.url).to.equal(newUrl);
    });

    it("should reject URL update when not registered", async function () {
      const { registry, relayer } = await loadFixture(deployFixture);
      await expect(
        registry.connect(relayer).updateUrl("/ip4/5.6.7.8/tcp/9001"),
      ).to.be.revertedWithCustomError(registry, "NotRegistered");
    });

    it("should reject empty URL update", async function () {
      const { registry, relayer } = await loadFixture(deployFixture);
      await registry
        .connect(relayer)
        .register(sphinxKey, url, "", "", MIN_STAKE, ROLE_FULL);

      await expect(
        registry.connect(relayer).updateUrl(""),
      ).to.be.revertedWithCustomError(registry, "EmptyString");
    });
  });

  describe("Node Roles", function () {
    const sphinxKey = ethers.randomBytes(32);
    const url = "/ip4/1.2.3.4/tcp/9000";
    const ROLE_RELAY = 1;
    const ROLE_EXIT = 2;
    const ROLE_FULL = 3;

    it("should store role on community registration", async function () {
      const { registry, relayer } = await loadFixture(deployFixture);
      await registry
        .connect(relayer)
        .register(sphinxKey, url, "", "", MIN_STAKE, ROLE_RELAY);
      expect(await registry.nodeRoles(relayer.address)).to.equal(ROLE_RELAY);
    });

    it("should store role on privileged registration", async function () {
      const { registry, admin, relayer } = await loadFixture(deployFixture);
      await registry
        .connect(admin)
        .registerPrivileged(relayer.address, sphinxKey, url, "", "", ROLE_EXIT);
      expect(await registry.nodeRoles(relayer.address)).to.equal(ROLE_EXIT);
    });

    it("should reject invalid role (0)", async function () {
      const { registry, relayer } = await loadFixture(deployFixture);
      await expect(
        registry
          .connect(relayer)
          .register(sphinxKey, url, "", "", MIN_STAKE, 0),
      ).to.be.revertedWithCustomError(registry, "InvalidRole");
    });

    it("should reject invalid role (4)", async function () {
      const { registry, relayer } = await loadFixture(deployFixture);
      await expect(
        registry
          .connect(relayer)
          .register(sphinxKey, url, "", "", MIN_STAKE, 4),
      ).to.be.revertedWithCustomError(registry, "InvalidRole");
    });

    it("should reject invalid role on privileged registration", async function () {
      const { registry, admin, relayer } = await loadFixture(deployFixture);
      await expect(
        registry
          .connect(admin)
          .registerPrivileged(relayer.address, sphinxKey, url, "", "", 0),
      ).to.be.revertedWithCustomError(registry, "InvalidRole");
    });

    it("should allow updating role", async function () {
      const { registry, relayer } = await loadFixture(deployFixture);
      await registry
        .connect(relayer)
        .register(sphinxKey, url, "", "", MIN_STAKE, ROLE_RELAY);

      await expect(registry.connect(relayer).updateRole(ROLE_FULL))
        .to.emit(registry, "RoleUpdated")
        .withArgs(relayer.address, ROLE_FULL);

      expect(await registry.nodeRoles(relayer.address)).to.equal(ROLE_FULL);
    });

    it("should reject role update when not registered", async function () {
      const { registry, relayer } = await loadFixture(deployFixture);
      await expect(
        registry.connect(relayer).updateRole(ROLE_FULL),
      ).to.be.revertedWithCustomError(registry, "NotRegistered");
    });

    it("should reject role update with invalid role", async function () {
      const { registry, relayer } = await loadFixture(deployFixture);
      await registry
        .connect(relayer)
        .register(sphinxKey, url, "", "", MIN_STAKE, ROLE_FULL);
      await expect(
        registry.connect(relayer).updateRole(0),
      ).to.be.revertedWithCustomError(registry, "InvalidRole");
    });

    it("should cleanup role on unstake", async function () {
      const { registry, relayer } = await loadFixture(deployFixture);
      await registry
        .connect(relayer)
        .register(sphinxKey, url, "", "", MIN_STAKE, ROLE_EXIT);
      expect(await registry.nodeRoles(relayer.address)).to.equal(ROLE_EXIT);

      await registry.connect(relayer).requestUnstake();
      await time.increase(UNSTAKE_DELAY + 1);
      await registry.connect(relayer).executeUnstake();

      expect(await registry.nodeRoles(relayer.address)).to.equal(0);
    });

    it("should cleanup role on force unregister", async function () {
      const { registry, admin, relayer } = await loadFixture(deployFixture);
      await registry
        .connect(admin)
        .registerPrivileged(
          relayer.address,
          sphinxKey,
          url,
          "",
          "",
          ROLE_RELAY,
        );
      expect(await registry.nodeRoles(relayer.address)).to.equal(ROLE_RELAY);

      await registry.connect(admin).forceUnregister(relayer.address);
      expect(await registry.nodeRoles(relayer.address)).to.equal(0);
    });

    it("should return Full for unset roles via getNodeRole", async function () {
      const { registry, relayer } = await loadFixture(deployFixture);
      // Unregistered address: nodeRoles[addr] = 0, getNodeRole returns ROLE_FULL
      expect(await registry.getNodeRole(relayer.address)).to.equal(ROLE_FULL);
    });

    it("should return correct role via getNodeRole for registered nodes", async function () {
      const { registry, relayer } = await loadFixture(deployFixture);
      await registry
        .connect(relayer)
        .register(sphinxKey, url, "", "", MIN_STAKE, ROLE_RELAY);
      expect(await registry.getNodeRole(relayer.address)).to.equal(ROLE_RELAY);
    });

    it("should emit role in RelayerRegistered event", async function () {
      const { registry, relayer } = await loadFixture(deployFixture);
      await expect(
        registry
          .connect(relayer)
          .register(sphinxKey, url, "", "", MIN_STAKE, ROLE_EXIT),
      )
        .to.emit(registry, "RelayerRegistered")
        .withArgs(
          relayer.address,
          ethers.hexlify(sphinxKey),
          url,
          "",
          "",
          MIN_STAKE,
          ROLE_EXIT,
        );
    });
  });

  describe("Config", function () {
    it("should allow CONFIG_ROLE to update config", async function () {
      const { registry, admin } = await loadFixture(deployFixture);

      const newMinStake = ethers.parseEther("2000");
      const newDelay = 14 * 24 * 60 * 60; // 14 days

      await expect(registry.connect(admin).updateConfig(newMinStake, newDelay))
        .to.emit(registry, "ConfigUpdated")
        .withArgs(newMinStake, newDelay);

      expect(await registry.minStakeAmount()).to.equal(newMinStake);
      expect(await registry.unstakeDelay()).to.equal(newDelay);
    });

    it("should reject config update from unauthorized account", async function () {
      const { registry, attacker } = await loadFixture(deployFixture);
      await expect(
        registry
          .connect(attacker)
          .updateConfig(ethers.parseEther("2000"), 14 * 24 * 60 * 60),
      ).to.be.revertedWithCustomError(
        registry,
        "AccessControlUnauthorizedAccount",
      );
    });
  });

  describe("Unstake lifecycle, freeze, and collateral floor", function () {
    const ROLE_FULL = 3;
    const key = () => ethers.randomBytes(32);

    async function registered() {
      const ctx = await loadFixture(deployFixture);
      await ctx.registry
        .connect(ctx.relayer)
        .register(key(), "/ip4/1.1.1.1/tcp/1", "", "", MIN_STAKE, ROLE_FULL);
      return ctx;
    }

    it("cancelUnstake returns an unstaking node to active", async function () {
      const { registry, relayer } = await registered();
      await registry.connect(relayer).requestUnstake();
      expect((await registry.relayers(relayer.address)).status).to.equal(2n);

      await registry.connect(relayer).cancelUnstake();
      const profile = await registry.relayers(relayer.address);
      expect(profile.status).to.equal(1n);
      expect(profile.unlockTime).to.equal(0n);

      await registry.connect(relayer).addStake(MIN_STAKE);
      expect((await registry.relayers(relayer.address)).stakedAmount).to.equal(
        MIN_STAKE * 2n,
      );
    });

    it("blocks addStake while an unstake is pending", async function () {
      const { registry, relayer } = await registered();
      await registry.connect(relayer).requestUnstake();
      await expect(
        registry.connect(relayer).addStake(MIN_STAKE),
      ).to.be.revertedWithCustomError(registry, "UnstakeAlreadyRequested");
    });

    it("freeze blocks executeUnstake and cancelUnstake; unfreeze restores exit", async function () {
      const { registry, relayer, slasher } = await registered();
      await registry.connect(relayer).requestUnstake();
      await time.increase(UNSTAKE_DELAY + 1);

      await registry.connect(slasher).freeze(relayer.address);
      await expect(
        registry.connect(relayer).executeUnstake(),
      ).to.be.revertedWithCustomError(registry, "NodeFrozen");
      await expect(
        registry.connect(relayer).cancelUnstake(),
      ).to.be.revertedWithCustomError(registry, "NodeFrozen");

      await registry.connect(slasher).unfreeze(relayer.address);
      await expect(registry.connect(relayer).executeUnstake()).to.emit(
        registry,
        "Unstaked",
      );
    });

    it("keeps a node slashable throughout the unstake cooldown", async function () {
      const { registry, relayer, slasher } = await registered();
      await registry.connect(relayer).requestUnstake();
      await expect(
        registry.connect(slasher).slash(relayer.address, MIN_STAKE),
      ).to.emit(registry, "Slashed");
      expect((await registry.relayers(relayer.address)).isRegistered).to.equal(
        false,
      );
    });

    it("restricts freeze to the slasher and rejects redundant freeze/unfreeze", async function () {
      const { registry, relayer, slasher, attacker } = await registered();
      await expect(
        registry.connect(attacker).freeze(relayer.address),
      ).to.be.revertedWithCustomError(
        registry,
        "AccessControlUnauthorizedAccount",
      );
      await expect(
        registry.connect(slasher).unfreeze(relayer.address),
      ).to.be.revertedWithCustomError(registry, "NotFrozen");
      await registry.connect(slasher).freeze(relayer.address);
      await expect(
        registry.connect(slasher).freeze(relayer.address),
      ).to.be.revertedWithCustomError(registry, "AlreadyFrozen");
    });

    it("deregisters and refunds the remainder when a slash drops stake below the floor", async function () {
      const ctx = await loadFixture(deployFixture);
      const { registry, relayer, slasher, token } = ctx;
      await registry
        .connect(relayer)
        .register(
          key(),
          "/ip4/1.1.1.1/tcp/1",
          "",
          "",
          MIN_STAKE * 2n,
          ROLE_FULL,
        );

      const relayerBalBefore = await token.balanceOf(relayer.address);
      // Slash 1500 of 2000 -> remaining 500 < minStake(1000) -> deregister + refund 500.
      await registry
        .connect(slasher)
        .slash(relayer.address, MIN_STAKE + ethers.parseEther("500"));

      expect((await registry.relayers(relayer.address)).isRegistered).to.equal(
        false,
      );
      expect(await registry.relayerCount()).to.equal(0n);
      expect(await token.balanceOf(relayer.address)).to.equal(
        relayerBalBefore + ethers.parseEther("500"),
      );
    });

    it("permissionlessly removes a node stranded by a minStake raise, exempting trusted nodes", async function () {
      const ctx = await loadFixture(deployFixture);
      const { registry, relayer, relayer2, admin, token } = ctx;

      await registry
        .connect(admin)
        .registerPrivileged(
          relayer2.address,
          key(),
          "/ip4/2.2.2.2/tcp/2",
          "",
          "",
          ROLE_FULL,
        );
      await registry
        .connect(relayer)
        .register(key(), "/ip4/1.1.1.1/tcp/1", "", "", MIN_STAKE, ROLE_FULL);

      await registry.connect(admin).updateConfig(MIN_STAKE * 2n, UNSTAKE_DELAY);

      const balBefore = await token.balanceOf(relayer.address);
      await registry
        .connect(relayer2)
        .removeUnderCollateralized(relayer.address);
      expect((await registry.relayers(relayer.address)).isRegistered).to.equal(
        false,
      );
      expect(await token.balanceOf(relayer.address)).to.equal(
        balBefore + MIN_STAKE,
      );

      // A trusted zero-stake node is not removable this way.
      await expect(
        registry.connect(relayer).removeUnderCollateralized(relayer2.address),
      ).to.be.revertedWithCustomError(registry, "NotUnderCollateralized");
    });

    it("blocks removeUnderCollateralized while a node is frozen", async function () {
      const ctx = await loadFixture(deployFixture);
      const { registry, relayer, slasher, admin } = ctx;
      await registry
        .connect(relayer)
        .register(key(), "/ip4/1.1.1.1/tcp/1", "", "", MIN_STAKE, ROLE_FULL);
      // Raise the floor so the node is under-collateralized, then freeze it pending investigation.
      await registry.connect(admin).updateConfig(MIN_STAKE * 2n, UNSTAKE_DELAY);
      await registry.connect(slasher).freeze(relayer.address);

      await expect(
        registry.connect(relayer).removeUnderCollateralized(relayer.address),
      ).to.be.revertedWithCustomError(registry, "NodeFrozen");

      // Once the slasher lifts the freeze, cleanup proceeds.
      await registry.connect(slasher).unfreeze(relayer.address);
      await expect(
        registry.connect(relayer).removeUnderCollateralized(relayer.address),
      ).to.emit(registry, "RelayerRemoved");
    });

    it("reverts slashing a zero-stake node", async function () {
      const ctx = await loadFixture(deployFixture);
      const { registry, relayer2, admin, slasher } = ctx;
      await registry
        .connect(admin)
        .registerPrivileged(
          relayer2.address,
          key(),
          "/ip4/2.2.2.2/tcp/2",
          "",
          "",
          ROLE_FULL,
        );
      await expect(
        registry.connect(slasher).slash(relayer2.address, MIN_STAKE),
      ).to.be.revertedWithCustomError(registry, "NothingToSlash");
    });

    it("enforces the minStake floor at initialize and on updateConfig", async function () {
      const { registry, admin, token } = await loadFixture(deployFixture);
      const RegistryFactory = await ethers.getContractFactory("NoxRegistry");

      await expect(
        upgrades.deployProxy(
          RegistryFactory,
          [
            [
              0,
              admin.address,
              await token.getAddress(),
              MIN_STAKE_FLOOR - 1n,
              UNSTAKE_DELAY,
              MIN_STAKE_FLOOR,
              admin.address,
              admin.address,
              admin.address,
            ],
          ],
          { kind: "uups" },
        ),
      ).to.be.revertedWithCustomError(registry, "MinStakeBelowFloor");

      await expect(
        upgrades.deployProxy(
          RegistryFactory,
          [
            [
              0,
              admin.address,
              await token.getAddress(),
              MIN_STAKE,
              UNSTAKE_DELAY,
              0n,
              admin.address,
              admin.address,
              admin.address,
            ],
          ],
          { kind: "uups" },
        ),
      ).to.be.revertedWithCustomError(registry, "InvalidAmount");

      await expect(
        registry
          .connect(admin)
          .updateConfig(MIN_STAKE_FLOOR - 1n, UNSTAKE_DELAY),
      ).to.be.revertedWithCustomError(registry, "MinStakeBelowFloor");
    });

    it("pauses churn paths while leaving incident levers callable", async function () {
      const { registry, relayer, slasher, admin } = await registered();
      await registry.connect(admin).pause();

      await expect(
        registry.connect(relayer).requestUnstake(),
      ).to.be.revertedWithCustomError(registry, "EnforcedPause");
      await expect(
        registry.connect(relayer).rotateKey(key()),
      ).to.be.revertedWithCustomError(registry, "EnforcedPause");
      await expect(
        registry.connect(relayer).updateRole(2),
      ).to.be.revertedWithCustomError(registry, "EnforcedPause");

      await expect(
        registry.connect(slasher).slash(relayer.address, MIN_STAKE),
      ).to.emit(registry, "Slashed");
    });

    it("allows executeUnstake while paused when matured and not frozen", async function () {
      const { registry, relayer, admin } = await registered();
      await registry.connect(relayer).requestUnstake();
      await time.increase(UNSTAKE_DELAY + 1);
      await registry.connect(admin).pause();
      await expect(registry.connect(relayer).executeUnstake()).to.emit(
        registry,
        "Unstaked",
      );
    });
  });
});
