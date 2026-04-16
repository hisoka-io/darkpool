import { assert, expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { NoxRewardPool, MockERC20 } from "../../typechain-types";

describe("NoxRewardPool (Treasury)", function () {
    async function deployFixture() {
        const [admin, distributor, user, relayer1, relayer2, attacker] =
            await ethers.getSigners();

        // 1. Deploy Token
        const TokenFactory = await ethers.getContractFactory("MockERC20");
        const token = (await TokenFactory.deploy("GasToken", "GAS", 18)) as unknown as MockERC20;
        const unsupportedToken = (await TokenFactory.deploy(
            "BadToken",
            "BAD",
            18
        )) as unknown as MockERC20;

        // 2. Deploy Pool
        const PoolFactory = await ethers.getContractFactory("NoxRewardPool");
        const pool = (await PoolFactory.deploy(admin.address)) as unknown as NoxRewardPool;

        // 3. Setup Roles
        const DISTRIBUTOR_ROLE = await pool.DISTRIBUTOR_ROLE();
        const ADMIN_ROLE = await pool.ADMIN_ROLE();
        await pool.connect(admin).grantRole(DISTRIBUTOR_ROLE, distributor.address);

        // 4. Whitelist Token
        await pool.connect(admin).setAssetStatus(await token.getAddress(), true);

        // 5. Mint tokens to User
        await token.mint(user.address, ethers.parseEther("1000"));
        await token
            .connect(user)
            .approve(await pool.getAddress(), ethers.MaxUint256);

        return {
            pool,
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
            const { pool, admin, unsupportedToken } = await loadFixture(deployFixture);
            const asset = await unsupportedToken.getAddress();

            await expect(pool.connect(admin).setAssetStatus(asset, true))
                .to.emit(pool, "AssetStatusChanged")
                .withArgs(asset, true);

            assert(await pool.isSupportedAsset(asset) === true);
        });

        it("should revert if non-Admin tries to whitelist", async function () {
            const { pool, attacker, token } = await loadFixture(deployFixture);

            await expect(
                pool.connect(attacker).setAssetStatus(await token.getAddress(), false)
            ).to.be.revertedWithCustomError(pool, "AccessControlUnauthorizedAccount");
        });

        it("should revert setting status for address(0)", async function () {
            const { pool, admin } = await loadFixture(deployFixture);
            await expect(
                pool.connect(admin).setAssetStatus(ethers.ZeroAddress, true)
            ).to.be.revertedWithCustomError(pool, "ZeroAddress");
        });
    });

    describe("Deposits (Inflow)", function () {
        it("should accept valid deposits and update accounting", async function () {
            const { pool, token, user } = await loadFixture(deployFixture);
            const amount = ethers.parseEther("100");

            await expect(
                pool
                    .connect(user)
                    .depositRewards(await token.getAddress(), amount)
            )
                .to.emit(pool, "RewardsDeposited")
                .withArgs(await token.getAddress(), user.address, amount);

            expect(await pool.totalCollected(await token.getAddress())).to.equal(amount);
            expect(await token.balanceOf(await pool.getAddress())).to.equal(amount);
        });

        it("should revert deposit of 0 amount", async function () {
            const { pool, token, user } = await loadFixture(deployFixture);
            await expect(
                pool.connect(user).depositRewards(await token.getAddress(), 0)
            ).to.be.revertedWithCustomError(pool, "ZeroAmount");
        });

        it("should revert deposit of unsupported asset", async function () {
            const { pool, unsupportedToken, user } = await loadFixture(deployFixture);
            await expect(
                pool
                    .connect(user)
                    .depositRewards(await unsupportedToken.getAddress(), 100)
            ).to.be.revertedWithCustomError(pool, "AssetNotSupported");
        });
    });

    describe("Distributions (Outflow)", function () {
        it("should allow Distributor to distribute batch rewards", async function () {
            const { pool, token, user, distributor, relayer1, relayer2 } =
                await loadFixture(deployFixture);

            // Setup: Deposit 100
            await pool
                .connect(user)
                .depositRewards(await token.getAddress(), ethers.parseEther("100"));

            const recipients = [relayer1.address, relayer2.address];
            const amounts = [ethers.parseEther("40"), ethers.parseEther("60")];

            await expect(
                pool
                    .connect(distributor)
                    .distributeRewards(await token.getAddress(), recipients, amounts)
            )
                .to.emit(pool, "RewardsDistributed")
                .withArgs(await token.getAddress(), ethers.parseEther("100"), 2);

            // Verify Balances
            expect(await token.balanceOf(relayer1.address)).to.equal(amounts[0]);
            expect(await token.balanceOf(relayer2.address)).to.equal(amounts[1]);
            expect(await pool.totalDistributed(await token.getAddress())).to.equal(
                ethers.parseEther("100")
            );
        });

        it("should revert if array lengths mismatch", async function () {
            const { pool, token, distributor, relayer1 } = await loadFixture(
                deployFixture
            );
            await expect(
                pool
                    .connect(distributor)
                    .distributeRewards(
                        await token.getAddress(),
                        [relayer1.address],
                        [100, 200]
                    )
            ).to.be.revertedWithCustomError(pool, "ArrayLengthMismatch");
        });

        it("should revert if distributing unsupported asset", async function () {
            const { pool, unsupportedToken, distributor, relayer1 } = await loadFixture(
                deployFixture
            );
            await expect(
                pool
                    .connect(distributor)
                    .distributeRewards(
                        await unsupportedToken.getAddress(),
                        [relayer1.address],
                        [100]
                    )
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
                        [100]
                    )
            ).to.be.revertedWithCustomError(pool, "ZeroAddress");
        });

        it("should revert if non-Distributor tries to distribute", async function () {
            const { pool, token, attacker, relayer1 } = await loadFixture(
                deployFixture
            );
            await expect(
                pool
                    .connect(attacker)
                    .distributeRewards(
                        await token.getAddress(),
                        [relayer1.address],
                        [100]
                    )
            ).to.be.revertedWithCustomError(pool, "AccessControlUnauthorizedAccount");
        });
    });

    describe("Emergency Functions", function () {
        it("should allow Admin to rescue funds", async function () {
            const { pool, token, admin } = await loadFixture(deployFixture);

            // Send tokens directly (simulate accidental transfer)
            await token.mint(await pool.getAddress(), 1000);

            await expect(
                pool.connect(admin).rescueFunds(await token.getAddress(), admin.address, 1000)
            )
                .to.emit(pool, "FundsRescued")
                .withArgs(await token.getAddress(), admin.address, 1000);

            expect(await token.balanceOf(admin.address)).to.equal(1000);
        });

        it("should pause and block deposits/distributions", async function () {
            const { pool, admin, user, distributor, token, relayer1 } = await loadFixture(
                deployFixture
            );

            await pool.connect(admin).pause();

            await expect(
                pool.connect(user).depositRewards(await token.getAddress(), 100)
            ).to.be.revertedWithCustomError(pool, "EnforcedPause");

            await expect(
                pool
                    .connect(distributor)
                    .distributeRewards(
                        await token.getAddress(),
                        [relayer1.address],
                        [100]
                    )
            ).to.be.revertedWithCustomError(pool, "EnforcedPause");

            // Admin rescue should still work
            await token.mint(await pool.getAddress(), 100);
            await expect(
                pool.connect(admin).rescueFunds(await token.getAddress(), admin.address, 100)
            ).to.not.be.reverted;
        });
    });
});