import { assert, expect } from "chai";
import { ethers } from "hardhat";
import {
    loadFixture,
    time,
} from "@nomicfoundation/hardhat-network-helpers";
import { NoxRegistry, MockERC20 } from "../../typechain-types";

describe("NoxRegistry (Identity & Staking)", function () {
    const MIN_STAKE = ethers.parseEther("1000");
    const UNSTAKE_DELAY = 7 * 24 * 60 * 60; // 7 Days

    async function deployFixture() {
        const [admin, slasher, relayer, relayer2, relayer3, attacker] =
            await ethers.getSigners();

        // 1. Deploy Token
        const TokenFactory = await ethers.getContractFactory("MockERC20");
        const token = (await TokenFactory.deploy(
            "StakeToken",
            "STK",
            18
        )) as unknown as MockERC20;

        // 2. Deploy Registry
        const RegistryFactory =
            await ethers.getContractFactory("NoxRegistry");
        const registry = (await RegistryFactory.deploy(
            admin.address,
            await token.getAddress(),
            MIN_STAKE,
            UNSTAKE_DELAY
        )) as unknown as NoxRegistry;

        // 3. Roles
        const SLASHER_ROLE = await registry.SLASHER_ROLE();
        await registry
            .connect(admin)
            .grantRole(SLASHER_ROLE, slasher.address);

        // 4. Fund Relayers
        for (const r of [relayer, relayer2, relayer3]) {
            await token.mint(r.address, ethers.parseEther("10000"));
            await token
                .connect(r)
                .approve(
                    await registry.getAddress(),
                    ethers.MaxUint256
                );
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

    // ========================================================================
    // Helper: compute keccak256(abi.encodePacked(address)) off-chain
    // ========================================================================

    function computeAddressHash(address: string): bigint {
        return BigInt(
            ethers.keccak256(
                ethers.solidityPacked(["address"], [address])
            )
        );
    }

    function xorHashes(...hashes: bigint[]): string {
        let result = 0n;
        for (const h of hashes) {
            result ^= h;
        }
        return ethers.toBeHex(result, 32);
    }

    // ========================================================================
    // XOR Topology Fingerprint
    // ========================================================================

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
            const { registry, admin, relayer } =
                await loadFixture(deployFixture);
            await registry
                .connect(admin)
                .registerPrivileged(relayer.address, sphinxKey, url, "", "", ROLE_FULL);

            const fingerprint = await registry.topologyFingerprint();
            const expected = xorHashes(
                computeAddressHash(relayer.address)
            );
            expect(fingerprint).to.equal(expected);
        });

        it("should produce order-independent fingerprint", async function () {
            const { registry, admin, relayer, relayer2 } =
                await loadFixture(deployFixture);

            // Order A: relayer first, then relayer2
            await registry
                .connect(admin)
                .registerPrivileged(relayer.address, sphinxKey, url, "", "", ROLE_FULL);
            await registry
                .connect(admin)
                .registerPrivileged(
                    relayer2.address,
                    ethers.randomBytes(32),
                    "/ip4/1.2.3.5/tcp/9000", "", "",
                    ROLE_FULL
                );
            const fpOrderA = await registry.topologyFingerprint();

            // Compute expected XOR (order doesn't matter)
            const expected = xorHashes(
                computeAddressHash(relayer.address),
                computeAddressHash(relayer2.address)
            );
            expect(fpOrderA).to.equal(expected);

            // Deploy a fresh registry for Order B
            const { registry: registry2, admin: admin2 } =
                await loadFixture(deployFixture);

            // Order B: relayer2 first, then relayer
            await registry2
                .connect(admin2)
                .registerPrivileged(
                    relayer2.address,
                    ethers.randomBytes(32),
                    "/ip4/1.2.3.5/tcp/9000", "", "",
                    ROLE_FULL
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

            // Register 2 nodes
            await registry
                .connect(admin)
                .registerPrivileged(relayer.address, sphinxKey, url, "", "", ROLE_FULL);
            await registry
                .connect(admin)
                .registerPrivileged(
                    relayer2.address,
                    ethers.randomBytes(32),
                    "/ip4/1.2.3.5/tcp/9000", "", "",
                    ROLE_FULL
                );

            // Unregister both
            await registry
                .connect(admin)
                .forceUnregister(relayer.address);
            await registry
                .connect(admin)
                .forceUnregister(relayer2.address);

            const fingerprint = await registry.topologyFingerprint();
            expect(fingerprint).to.equal(ethers.ZeroHash);
        });

        it("should handle re-registration correctly", async function () {
            const { registry, admin, relayer } =
                await loadFixture(deployFixture);

            // Register
            await registry
                .connect(admin)
                .registerPrivileged(relayer.address, sphinxKey, url, "", "", ROLE_FULL);
            const fpAfterRegister =
                await registry.topologyFingerprint();

            // Unregister
            await registry
                .connect(admin)
                .forceUnregister(relayer.address);
            const fpAfterUnregister =
                await registry.topologyFingerprint();
            expect(fpAfterUnregister).to.equal(ethers.ZeroHash);

            // Re-register
            await registry
                .connect(admin)
                .registerPrivileged(relayer.address, sphinxKey, url, "", "", ROLE_FULL);
            const fpAfterReregister =
                await registry.topologyFingerprint();

            // Same fingerprint as after first registration
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
                    "/ip4/1.2.3.5/tcp/9000", "", "",
                    ROLE_FULL
                );
            await registry
                .connect(admin)
                .registerPrivileged(
                    relayer3.address,
                    ethers.randomBytes(32),
                    "/ip4/1.2.3.6/tcp/9000", "", "",
                    ROLE_FULL
                );

            const fingerprint = await registry.topologyFingerprint();
            const expected = xorHashes(
                computeAddressHash(relayer.address),
                computeAddressHash(relayer2.address),
                computeAddressHash(relayer3.address)
            );
            expect(fingerprint).to.equal(expected);
        });

        it("should emit TopologyFingerprintUpdated with correct values", async function () {
            const { registry, admin, relayer } =
                await loadFixture(deployFixture);

            const expectedNew = xorHashes(
                computeAddressHash(relayer.address)
            );

            await expect(
                registry
                    .connect(admin)
                    .registerPrivileged(relayer.address, sphinxKey, url, "", "", ROLE_FULL)
            )
                .to.emit(registry, "TopologyFingerprintUpdated")
                .withArgs(expectedNew, ethers.ZeroHash);
        });

        it("should not change fingerprint on key rotation", async function () {
            const { registry, admin, relayer } =
                await loadFixture(deployFixture);

            await registry
                .connect(admin)
                .registerPrivileged(relayer.address, sphinxKey, url, "", "", ROLE_FULL);
            const fpBefore = await registry.topologyFingerprint();

            // Rotate key
            await registry
                .connect(relayer)
                .rotateKey(ethers.randomBytes(32));
            const fpAfter = await registry.topologyFingerprint();

            expect(fpAfter).to.equal(fpBefore);
        });
    });

    // ========================================================================
    // Manual Whitelisting (Privileged)
    // ========================================================================

    describe("Manual Whitelisting (Privileged)", function () {
        const sphinxKey = ethers.randomBytes(32);
        const url = "/ip4/1.2.3.4/tcp/9000";
        const ROLE_FULL = 3;

        it("should allow Admin to register a privileged relayer without stake", async function () {
            const { registry, admin, relayer } =
                await loadFixture(deployFixture);

            await expect(
                registry
                    .connect(admin)
                    .registerPrivileged(
                        relayer.address,
                        sphinxKey,
                        url, "", "",
                        ROLE_FULL
                    )
            )
                .to.emit(registry, "PrivilegedRelayerRegistered")
                .withArgs(
                    relayer.address,
                    ethers.hexlify(sphinxKey),
                    url,
                    "",
                    "",
                    ROLE_FULL
                );

            const profile = await registry.relayers(relayer.address);
            assert(profile.isRegistered === true);
            expect(profile.stakedAmount).to.equal(0);
            expect(await registry.nodeRoles(relayer.address)).to.equal(ROLE_FULL);
        });

        it("should revert if non-admin tries to register privileged", async function () {
            const { registry, attacker, relayer } =
                await loadFixture(deployFixture);
            await expect(
                registry
                    .connect(attacker)
                    .registerPrivileged(
                        relayer.address,
                        sphinxKey,
                        url, "", "",
                        ROLE_FULL
                    )
            ).to.be.revertedWithCustomError(
                registry,
                "AccessControlUnauthorizedAccount"
            );
        });

        it("should allow Admin to force unregister (ban) a node", async function () {
            const { registry, admin, relayer } =
                await loadFixture(deployFixture);

            await registry
                .connect(admin)
                .registerPrivileged(relayer.address, sphinxKey, url, "", "", ROLE_FULL);

            await expect(
                registry.connect(admin).forceUnregister(relayer.address)
            )
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

            await registry
                .connect(admin)
                .forceUnregister(relayer.address);

            const balAfter = await token.balanceOf(relayer.address);
            expect(balAfter).to.equal(balBefore + MIN_STAKE);

            const profile = await registry.relayers(relayer.address);
            assert(profile.isRegistered === false);
        });
    });

    // ========================================================================
    // Community Registration (Staked)
    // ========================================================================

    describe("Community Registration (Staked)", function () {
        const sphinxKey = ethers.randomBytes(32);
        const url = "/ip4/1.2.3.4/tcp/9000";
        const ROLE_FULL = 3;

        it("should allow community registration with sufficient stake", async function () {
            const { registry, relayer } =
                await loadFixture(deployFixture);

            await expect(
                registry
                    .connect(relayer)
                    .register(sphinxKey, url, "", "", MIN_STAKE, ROLE_FULL)
            )
                .to.emit(registry, "RelayerRegistered")
                .withArgs(
                    relayer.address,
                    ethers.hexlify(sphinxKey),
                    url,
                    "",
                    "",
                    MIN_STAKE,
                    ROLE_FULL
                );

            const profile = await registry.relayers(relayer.address);
            expect(profile.isRegistered).to.equal(true);
            expect(profile.stakedAmount).to.equal(MIN_STAKE);
            expect(await registry.relayerCount()).to.equal(1);
            expect(await registry.nodeRoles(relayer.address)).to.equal(ROLE_FULL);
        });

        it("should reject registration with insufficient stake", async function () {
            const { registry, relayer } =
                await loadFixture(deployFixture);
            await expect(
                registry
                    .connect(relayer)
                    .register(sphinxKey, url, "", "", MIN_STAKE - 1n, ROLE_FULL)
            ).to.be.revertedWithCustomError(registry, "InsufficientStake");
        });

        it("should reject duplicate registration", async function () {
            const { registry, relayer } =
                await loadFixture(deployFixture);
            await registry
                .connect(relayer)
                .register(sphinxKey, url, "", "", MIN_STAKE, ROLE_FULL);
            await expect(
                registry
                    .connect(relayer)
                    .register(sphinxKey, url, "", "", MIN_STAKE, ROLE_FULL)
            ).to.be.revertedWithCustomError(registry, "AlreadyRegistered");
        });

        it("should reject registration with empty URL", async function () {
            const { registry, relayer } =
                await loadFixture(deployFixture);
            await expect(
                registry
                    .connect(relayer)
                    .register(sphinxKey, "", "", "", MIN_STAKE, ROLE_FULL)
            ).to.be.revertedWithCustomError(registry, "EmptyString");
        });

        it("should reject registration with zero sphinxKey", async function () {
            const { registry, relayer } =
                await loadFixture(deployFixture);
            await expect(
                registry
                    .connect(relayer)
                    .register(ethers.ZeroHash, url, "", "", MIN_STAKE, ROLE_FULL)
            ).to.be.revertedWithCustomError(registry, "InvalidKey");
        });

        it("should transfer tokens on registration", async function () {
            const { registry, relayer, token } =
                await loadFixture(deployFixture);
            const balBefore = await token.balanceOf(relayer.address);

            await registry
                .connect(relayer)
                .register(sphinxKey, url, "", "", MIN_STAKE, ROLE_FULL);

            const balAfter = await token.balanceOf(relayer.address);
            expect(balBefore - balAfter).to.equal(MIN_STAKE);
        });
    });

    // ========================================================================
    // Staking
    // ========================================================================

    describe("Staking", function () {
        const sphinxKey = ethers.randomBytes(32);
        const url = "/ip4/1.2.3.4/tcp/9000";
        const ROLE_FULL = 3;

        it("should allow adding stake", async function () {
            const { registry, relayer } =
                await loadFixture(deployFixture);
            await registry
                .connect(relayer)
                .register(sphinxKey, url, "", "", MIN_STAKE, ROLE_FULL);

            const extra = ethers.parseEther("500");
            await expect(
                registry.connect(relayer).addStake(extra)
            )
                .to.emit(registry, "StakeAdded")
                .withArgs(relayer.address, extra);

            const profile = await registry.relayers(relayer.address);
            expect(profile.stakedAmount).to.equal(MIN_STAKE + extra);
        });

        it("should reject adding stake when not registered", async function () {
            const { registry, relayer } =
                await loadFixture(deployFixture);
            await expect(
                registry
                    .connect(relayer)
                    .addStake(ethers.parseEther("100"))
            ).to.be.revertedWithCustomError(registry, "NotRegistered");
        });

        it("should reject adding zero stake", async function () {
            const { registry, relayer } =
                await loadFixture(deployFixture);
            await registry
                .connect(relayer)
                .register(sphinxKey, url, "", "", MIN_STAKE, ROLE_FULL);
            await expect(
                registry.connect(relayer).addStake(0)
            ).to.be.revertedWithCustomError(registry, "InvalidAmount");
        });

        it("should reject adding stake during unstake cooldown", async function () {
            const { registry, relayer } =
                await loadFixture(deployFixture);
            await registry
                .connect(relayer)
                .register(sphinxKey, url, "", "", MIN_STAKE, ROLE_FULL);
            await registry.connect(relayer).requestUnstake();

            await expect(
                registry
                    .connect(relayer)
                    .addStake(ethers.parseEther("100"))
            ).to.be.revertedWithCustomError(
                registry,
                "UnstakeAlreadyRequested"
            );
        });
    });

    // ========================================================================
    // Exit Flow (Unstake)
    // ========================================================================

    describe("Exit Flow (Unstake)", function () {
        const sphinxKey = ethers.randomBytes(32);
        const url = "/ip4/1.2.3.4/tcp/9000";
        const ROLE_FULL = 3;

        it("should allow requesting unstake", async function () {
            const { registry, relayer } =
                await loadFixture(deployFixture);
            await registry
                .connect(relayer)
                .register(sphinxKey, url, "", "", MIN_STAKE, ROLE_FULL);

            await expect(
                registry.connect(relayer).requestUnstake()
            ).to.emit(registry, "UnstakeRequested");

            const profile = await registry.relayers(relayer.address);
            expect(profile.unstakeRequestTime).to.be.gt(0);
        });

        it("should reject duplicate unstake request", async function () {
            const { registry, relayer } =
                await loadFixture(deployFixture);
            await registry
                .connect(relayer)
                .register(sphinxKey, url, "", "", MIN_STAKE, ROLE_FULL);
            await registry.connect(relayer).requestUnstake();

            await expect(
                registry.connect(relayer).requestUnstake()
            ).to.be.revertedWithCustomError(
                registry,
                "UnstakeAlreadyRequested"
            );
        });

        it("should reject execute unstake before delay", async function () {
            const { registry, relayer } =
                await loadFixture(deployFixture);
            await registry
                .connect(relayer)
                .register(sphinxKey, url, "", "", MIN_STAKE, ROLE_FULL);
            await registry.connect(relayer).requestUnstake();

            await expect(
                registry.connect(relayer).executeUnstake()
            ).to.be.revertedWithCustomError(
                registry,
                "UnstakeTooEarly"
            );
        });

        it("should allow execute unstake after delay", async function () {
            const { registry, relayer, token } =
                await loadFixture(deployFixture);
            await registry
                .connect(relayer)
                .register(sphinxKey, url, "", "", MIN_STAKE, ROLE_FULL);
            await registry.connect(relayer).requestUnstake();

            // Advance time past unstake delay
            await time.increase(UNSTAKE_DELAY + 1);

            const balBefore = await token.balanceOf(relayer.address);
            await registry.connect(relayer).executeUnstake();
            const balAfter = await token.balanceOf(relayer.address);

            // Tokens returned
            expect(balAfter - balBefore).to.equal(MIN_STAKE);

            // Profile deleted
            const profile = await registry.relayers(relayer.address);
            expect(profile.isRegistered).to.equal(false);

            // Relayer count decremented
            expect(await registry.relayerCount()).to.equal(0);

            // Fingerprint back to zero
            expect(await registry.topologyFingerprint()).to.equal(
                ethers.ZeroHash
            );
        });
    });

    // ========================================================================
    // Slashing
    // ========================================================================

    describe("Slashing", function () {
        const sphinxKey = ethers.randomBytes(32);
        const url = "/ip4/1.2.3.4/tcp/9000";
        const ROLE_FULL = 3;

        it("should allow slasher to slash a node", async function () {
            const { registry, relayer, slasher, token } =
                await loadFixture(deployFixture);
            await registry
                .connect(relayer)
                .register(sphinxKey, url, "", "", MIN_STAKE, ROLE_FULL);

            const slashAmount = ethers.parseEther("500");
            const slasherBalBefore = await token.balanceOf(
                slasher.address
            );

            await expect(
                registry
                    .connect(slasher)
                    .slash(relayer.address, slashAmount)
            )
                .to.emit(registry, "Slashed")
                .withArgs(
                    relayer.address,
                    slashAmount,
                    slasher.address
                );

            const profile = await registry.relayers(relayer.address);
            expect(profile.stakedAmount).to.equal(
                MIN_STAKE - slashAmount
            );

            const slasherBalAfter = await token.balanceOf(
                slasher.address
            );
            expect(slasherBalAfter - slasherBalBefore).to.equal(
                slashAmount
            );
        });

        it("should cap slash at available stake", async function () {
            const { registry, relayer, slasher, token } =
                await loadFixture(deployFixture);
            await registry
                .connect(relayer)
                .register(sphinxKey, url, "", "", MIN_STAKE, ROLE_FULL);

            const overSlash = MIN_STAKE + ethers.parseEther("999");
            const slasherBalBefore = await token.balanceOf(
                slasher.address
            );

            await registry
                .connect(slasher)
                .slash(relayer.address, overSlash);

            // Only staked amount taken
            const profile = await registry.relayers(relayer.address);
            expect(profile.stakedAmount).to.equal(0);

            const slasherBalAfter = await token.balanceOf(
                slasher.address
            );
            expect(slasherBalAfter - slasherBalBefore).to.equal(
                MIN_STAKE
            );
        });

        it("should reject slash from non-slasher", async function () {
            const { registry, relayer, attacker } =
                await loadFixture(deployFixture);
            await registry
                .connect(relayer)
                .register(sphinxKey, url, "", "", MIN_STAKE, ROLE_FULL);

            await expect(
                registry
                    .connect(attacker)
                    .slash(relayer.address, ethers.parseEther("100"))
            ).to.be.revertedWithCustomError(
                registry,
                "AccessControlUnauthorizedAccount"
            );
        });

        it("should reject slash of unregistered node", async function () {
            const { registry, slasher, relayer } =
                await loadFixture(deployFixture);
            await expect(
                registry
                    .connect(slasher)
                    .slash(relayer.address, ethers.parseEther("100"))
            ).to.be.revertedWithCustomError(registry, "NotRegistered");
        });
    });

    // ========================================================================
    // Key Rotation & URL Update
    // ========================================================================

    describe("Key Rotation & URL Update", function () {
        const sphinxKey = ethers.randomBytes(32);
        const url = "/ip4/1.2.3.4/tcp/9000";
        const ROLE_FULL = 3;

        it("should allow key rotation", async function () {
            const { registry, relayer } =
                await loadFixture(deployFixture);
            await registry
                .connect(relayer)
                .register(sphinxKey, url, "", "", MIN_STAKE, ROLE_FULL);

            const newKey = ethers.randomBytes(32);
            await expect(
                registry.connect(relayer).rotateKey(newKey)
            )
                .to.emit(registry, "KeyRotated")
                .withArgs(relayer.address, ethers.hexlify(newKey));

            const profile = await registry.relayers(relayer.address);
            expect(profile.sphinxKey).to.equal(
                ethers.hexlify(newKey)
            );
        });

        it("should reject key rotation when not registered", async function () {
            const { registry, relayer } =
                await loadFixture(deployFixture);
            await expect(
                registry
                    .connect(relayer)
                    .rotateKey(ethers.randomBytes(32))
            ).to.be.revertedWithCustomError(registry, "NotRegistered");
        });

        it("should reject key rotation to zero key", async function () {
            const { registry, relayer } =
                await loadFixture(deployFixture);
            await registry
                .connect(relayer)
                .register(sphinxKey, url, "", "", MIN_STAKE, ROLE_FULL);

            await expect(
                registry.connect(relayer).rotateKey(ethers.ZeroHash)
            ).to.be.revertedWithCustomError(registry, "InvalidKey");
        });

        it("should allow URL update", async function () {
            const { registry, relayer } =
                await loadFixture(deployFixture);
            await registry
                .connect(relayer)
                .register(sphinxKey, url, "", "", MIN_STAKE, ROLE_FULL);

            const newUrl = "/ip4/5.6.7.8/tcp/9001";
            await expect(
                registry.connect(relayer).updateUrl(newUrl)
            )
                .to.emit(registry, "RelayerUpdated")
                .withArgs(relayer.address, newUrl);

            const profile = await registry.relayers(relayer.address);
            expect(profile.url).to.equal(newUrl);
        });

        it("should reject URL update when not registered", async function () {
            const { registry, relayer } =
                await loadFixture(deployFixture);
            await expect(
                registry
                    .connect(relayer)
                    .updateUrl("/ip4/5.6.7.8/tcp/9001")
            ).to.be.revertedWithCustomError(registry, "NotRegistered");
        });

        it("should reject empty URL update", async function () {
            const { registry, relayer } =
                await loadFixture(deployFixture);
            await registry
                .connect(relayer)
                .register(sphinxKey, url, "", "", MIN_STAKE, ROLE_FULL);

            await expect(
                registry.connect(relayer).updateUrl("")
            ).to.be.revertedWithCustomError(registry, "EmptyString");
        });
    });

    // ========================================================================
    // Node Roles
    // ========================================================================

    describe("Node Roles", function () {
        const sphinxKey = ethers.randomBytes(32);
        const url = "/ip4/1.2.3.4/tcp/9000";
        const ROLE_RELAY = 1;
        const ROLE_EXIT = 2;
        const ROLE_FULL = 3;

        it("should store role on community registration", async function () {
            const { registry, relayer } =
                await loadFixture(deployFixture);
            await registry
                .connect(relayer)
                .register(sphinxKey, url, "", "", MIN_STAKE, ROLE_RELAY);
            expect(await registry.nodeRoles(relayer.address)).to.equal(
                ROLE_RELAY
            );
        });

        it("should store role on privileged registration", async function () {
            const { registry, admin, relayer } =
                await loadFixture(deployFixture);
            await registry
                .connect(admin)
                .registerPrivileged(
                    relayer.address,
                    sphinxKey,
                    url, "", "",
                    ROLE_EXIT
                );
            expect(await registry.nodeRoles(relayer.address)).to.equal(
                ROLE_EXIT
            );
        });

        it("should reject invalid role (0)", async function () {
            const { registry, relayer } =
                await loadFixture(deployFixture);
            await expect(
                registry
                    .connect(relayer)
                    .register(sphinxKey, url, "", "", MIN_STAKE, 0)
            ).to.be.revertedWithCustomError(registry, "InvalidRole");
        });

        it("should reject invalid role (4)", async function () {
            const { registry, relayer } =
                await loadFixture(deployFixture);
            await expect(
                registry
                    .connect(relayer)
                    .register(sphinxKey, url, "", "", MIN_STAKE, 4)
            ).to.be.revertedWithCustomError(registry, "InvalidRole");
        });

        it("should reject invalid role on privileged registration", async function () {
            const { registry, admin, relayer } =
                await loadFixture(deployFixture);
            await expect(
                registry
                    .connect(admin)
                    .registerPrivileged(
                        relayer.address,
                        sphinxKey,
                        url, "", "",
                        0
                    )
            ).to.be.revertedWithCustomError(registry, "InvalidRole");
        });

        it("should allow updating role", async function () {
            const { registry, relayer } =
                await loadFixture(deployFixture);
            await registry
                .connect(relayer)
                .register(sphinxKey, url, "", "", MIN_STAKE, ROLE_RELAY);

            await expect(
                registry.connect(relayer).updateRole(ROLE_FULL)
            )
                .to.emit(registry, "RoleUpdated")
                .withArgs(relayer.address, ROLE_FULL);

            expect(await registry.nodeRoles(relayer.address)).to.equal(
                ROLE_FULL
            );
        });

        it("should reject role update when not registered", async function () {
            const { registry, relayer } =
                await loadFixture(deployFixture);
            await expect(
                registry.connect(relayer).updateRole(ROLE_FULL)
            ).to.be.revertedWithCustomError(registry, "NotRegistered");
        });

        it("should reject role update with invalid role", async function () {
            const { registry, relayer } =
                await loadFixture(deployFixture);
            await registry
                .connect(relayer)
                .register(sphinxKey, url, "", "", MIN_STAKE, ROLE_FULL);
            await expect(
                registry.connect(relayer).updateRole(0)
            ).to.be.revertedWithCustomError(registry, "InvalidRole");
        });

        it("should cleanup role on unstake", async function () {
            const { registry, relayer } =
                await loadFixture(deployFixture);
            await registry
                .connect(relayer)
                .register(sphinxKey, url, "", "", MIN_STAKE, ROLE_EXIT);
            expect(await registry.nodeRoles(relayer.address)).to.equal(
                ROLE_EXIT
            );

            await registry.connect(relayer).requestUnstake();
            await time.increase(UNSTAKE_DELAY + 1);
            await registry.connect(relayer).executeUnstake();

            expect(await registry.nodeRoles(relayer.address)).to.equal(0);
        });

        it("should cleanup role on force unregister", async function () {
            const { registry, admin, relayer } =
                await loadFixture(deployFixture);
            await registry
                .connect(admin)
                .registerPrivileged(
                    relayer.address,
                    sphinxKey,
                    url, "", "",
                    ROLE_RELAY
                );
            expect(await registry.nodeRoles(relayer.address)).to.equal(
                ROLE_RELAY
            );

            await registry
                .connect(admin)
                .forceUnregister(relayer.address);
            expect(await registry.nodeRoles(relayer.address)).to.equal(0);
        });

        it("should return Full for unset roles via getNodeRole", async function () {
            const { registry, relayer } =
                await loadFixture(deployFixture);
            // Unregistered address: nodeRoles[addr] = 0, getNodeRole returns ROLE_FULL
            expect(
                await registry.getNodeRole(relayer.address)
            ).to.equal(ROLE_FULL);
        });

        it("should return correct role via getNodeRole for registered nodes", async function () {
            const { registry, relayer } =
                await loadFixture(deployFixture);
            await registry
                .connect(relayer)
                .register(sphinxKey, url, "", "", MIN_STAKE, ROLE_RELAY);
            expect(
                await registry.getNodeRole(relayer.address)
            ).to.equal(ROLE_RELAY);
        });

        it("should emit role in RelayerRegistered event", async function () {
            const { registry, relayer } =
                await loadFixture(deployFixture);
            await expect(
                registry
                    .connect(relayer)
                    .register(sphinxKey, url, "", "", MIN_STAKE, ROLE_EXIT)
            )
                .to.emit(registry, "RelayerRegistered")
                .withArgs(
                    relayer.address,
                    ethers.hexlify(sphinxKey),
                    url,
                    "",
                    "",
                    MIN_STAKE,
                    ROLE_EXIT
                );
        });
    });

    // ========================================================================
    // Config
    // ========================================================================

    describe("Config", function () {
        it("should allow CONFIG_ROLE to update config", async function () {
            const { registry, admin } =
                await loadFixture(deployFixture);

            const newMinStake = ethers.parseEther("2000");
            const newDelay = 14 * 24 * 60 * 60; // 14 days

            await expect(
                registry
                    .connect(admin)
                    .updateConfig(newMinStake, newDelay)
            )
                .to.emit(registry, "ConfigUpdated")
                .withArgs(newMinStake, newDelay);

            expect(await registry.minStakeAmount()).to.equal(
                newMinStake
            );
            expect(await registry.unstakeDelay()).to.equal(newDelay);
        });

        it("should reject config update from unauthorized account", async function () {
            const { registry, attacker } =
                await loadFixture(deployFixture);
            await expect(
                registry
                    .connect(attacker)
                    .updateConfig(
                        ethers.parseEther("2000"),
                        14 * 24 * 60 * 60
                    )
            ).to.be.revertedWithCustomError(
                registry,
                "AccessControlUnauthorizedAccount"
            );
        });
    });
});
