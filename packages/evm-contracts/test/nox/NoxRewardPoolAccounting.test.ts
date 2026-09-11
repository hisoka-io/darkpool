import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";

describe("NoxRewardPool execution accounting", function () {
  async function deployFixture() {
    const [admin, entryPoint, exit, relay, recipient, attacker] =
      await ethers.getSigners();
    const token = await (
      await ethers.getContractFactory("MockERC20")
    ).deploy("Fee", "FEE", 18);
    const registry = await (
      await ethers.getContractFactory("MockNoxRegistry")
    ).deploy();
    await registry.setActive(relay.address, true);
    const pool = await upgrades.deployProxy(
      await ethers.getContractFactory("NoxRewardPool"),
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
    );
    const asset = await token.getAddress();
    await pool.setAssetStatus(asset, true);
    await pool.grantRole(await pool.ENTRYPOINT_ROLE(), entryPoint.address);
    return {
      admin,
      entryPoint,
      exit,
      relay,
      recipient,
      attacker,
      token,
      pool,
      asset,
    };
  }

  it("preserves legacy liability through classification, credits, claims, distribution, and donation rescue", async function () {
    const { admin, entryPoint, exit, relay, recipient, token, pool, asset } =
      await loadFixture(deployFixture);
    await token.mint(admin.address, 100n);
    await token.approve(await pool.getAddress(), 100n);
    await pool.depositRewards(asset, 100n);
    await pool.distributeRewards(asset, [relay.address], [40n]);
    await pool.classifyAsset(asset);
    expect(await pool.networkOutstanding(asset)).to.equal(60n);

    await token.mint(admin.address, 20n);
    await token.approve(await pool.getAddress(), 20n);
    await pool.depositRewards(asset, 20n);
    expect(await pool.networkOutstanding(asset)).to.equal(80n);

    await token.mint(entryPoint.address, 40n);
    await token.connect(entryPoint).approve(await pool.getAddress(), 40n);
    await pool
      .connect(entryPoint)
      .recordExecutionFee(
        ethers.id("execution"),
        ethers.id("payment"),
        exit.address,
        asset,
        30n,
        10n,
      );
    expect(await pool.networkOutstanding(asset)).to.equal(90n);
    expect(await pool.exitOutstanding(asset)).to.equal(30n);

    await token.mint(await pool.getAddress(), 50n);
    await expect(
      pool.rescueFunds(asset, admin.address, 51n),
    ).to.be.revertedWithCustomError(pool, "ExceedsRescuableBalance");
    await pool.rescueFunds(asset, admin.address, 50n);

    await pool.connect(exit).claimExitCredit(asset, recipient.address, 30n);
    await pool.distributeRewards(asset, [relay.address], [90n]);
    expect(await pool.networkOutstanding(asset)).to.equal(0n);
    expect(await pool.exitOutstanding(asset)).to.equal(0n);
    expect(await token.balanceOf(await pool.getAddress())).to.equal(0n);
  });

  it("maintains solvency across varied execution fee splits", async function () {
    const { admin, entryPoint, exit, token, pool, asset } =
      await loadFixture(deployFixture);
    await pool.classifyAsset(asset);
    const splits = [
      [1n, 1n],
      [2n, 3n],
      [5n, 8n],
      [13n, 21n],
      [34n, 55n],
      [89n, 144n],
      [233n, 377n],
      [610n, 987n],
    ] as const;
    const total = splits.reduce(
      (sum, [exitAmount, networkAmount]) => sum + exitAmount + networkAmount,
      0n,
    );
    await token.mint(entryPoint.address, total);
    await token.connect(entryPoint).approve(await pool.getAddress(), total);

    for (let i = 0; i < splits.length; i++) {
      const [exitAmount, networkAmount] = splits[i]!;
      await pool
        .connect(entryPoint)
        .recordExecutionFee(
          ethers.id(`execution-${i}`),
          ethers.id(`payment-${i}`),
          exit.address,
          asset,
          exitAmount,
          networkAmount,
        );
      const protectedBalance =
        (await pool.networkOutstanding(asset)) +
        (await pool.exitOutstanding(asset));
      expect(
        await token.balanceOf(await pool.getAddress()),
      ).to.be.greaterThanOrEqual(protectedBalance);
    }

    await expect(
      pool
        .connect(admin)
        .recordExecutionFee(
          ethers.id("unauthorized"),
          ethers.id("unauthorized-payment"),
          exit.address,
          asset,
          1n,
          1n,
        ),
    ).to.be.revertedWithCustomError(pool, "AccessControlUnauthorizedAccount");
  });

  it("rejects execution-fee arithmetic overflow with a typed error", async function () {
    const { entryPoint, exit, pool, asset } = await loadFixture(deployFixture);
    await pool.classifyAsset(asset);
    await expect(
      pool
        .connect(entryPoint)
        .recordExecutionFee(
          ethers.id("overflow"),
          ethers.id("overflow-payment"),
          exit.address,
          asset,
          ethers.MaxUint256,
          1n,
        ),
    ).to.be.revertedWithCustomError(pool, "AccountingOverflow");
  });
});
