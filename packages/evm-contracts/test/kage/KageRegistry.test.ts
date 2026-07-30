import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture, time } from "@nomicfoundation/hardhat-network-helpers";
import { KageRegistry, MockERC20 } from "../../typechain-types";

describe("KageRegistry (Solver Staking)", function () {
  const MIN_STAKE = ethers.parseEther("1000");
  const COOLDOWN = 24 * 60 * 60;
  const NOISE_KEY = ethers.keccak256(ethers.toUtf8Bytes("noise-pubkey"));

  async function deployFixture() {
    const [admin, slasher, solver, anyone] = await ethers.getSigners();

    const TokenFactory = await ethers.getContractFactory("MockERC20");
    const token = (await TokenFactory.deploy(
      "StakeToken",
      "STK",
      18,
    )) as unknown as MockERC20;

    const RegistryFactory = await ethers.getContractFactory("KageRegistry");
    const registry = (await RegistryFactory.deploy(
      await token.getAddress(),
      MIN_STAKE,
      admin.address,
      slasher.address,
    )) as unknown as KageRegistry;
    await registry.waitForDeployment();

    await token.mint(solver.address, ethers.parseEther("10000"));
    await token
      .connect(solver)
      .approve(await registry.getAddress(), ethers.MaxUint256);

    return { registry, token, admin, slasher, solver, anyone };
  }

  it("registers a solver instantly with stake", async function () {
    const { registry, solver } = await loadFixture(deployFixture);
    await registry.connect(solver).register(NOISE_KEY, MIN_STAKE);

    expect(await registry.isActiveSolver(solver.address)).to.equal(true);
    expect(await registry.solverCount()).to.equal(1);
    const profile = await registry.solvers(solver.address);
    expect(profile.stakedAmount).to.equal(MIN_STAKE);
  });

  it("rejects registration below minStake", async function () {
    const { registry, solver } = await loadFixture(deployFixture);
    await expect(
      registry.connect(solver).register(NOISE_KEY, MIN_STAKE - 1n),
    ).to.be.revertedWithCustomError(registry, "InsufficientStake");
  });

  it("deregister removes the solver from the network immediately", async function () {
    const { registry, solver } = await loadFixture(deployFixture);
    await registry.connect(solver).register(NOISE_KEY, MIN_STAKE);
    await registry.connect(solver).deregister();

    expect(await registry.isActiveSolver(solver.address)).to.equal(false);
    expect(await registry.solverCount()).to.equal(0);
  });

  it("anyone can unstake after the cooldown; funds go to the solver", async function () {
    const { registry, token, solver, anyone } =
      await loadFixture(deployFixture);
    await registry.connect(solver).register(NOISE_KEY, MIN_STAKE);
    await registry.connect(solver).deregister();

    await expect(
      registry.connect(anyone).unstake(solver.address),
    ).to.be.revertedWithCustomError(registry, "CooldownNotOver");

    await time.increase(COOLDOWN + 1);
    const before = await token.balanceOf(solver.address);
    await registry.connect(anyone).unstake(solver.address);

    expect(await token.balanceOf(solver.address)).to.equal(before + MIN_STAKE);
    const profile = await registry.solvers(solver.address);
    expect(profile.status).to.equal(3); // Deregistered

    // a Deregistered address may register again
    await registry.connect(solver).register(NOISE_KEY, MIN_STAKE);
    expect(await registry.isActiveSolver(solver.address)).to.equal(true);
  });

  it("re-registering from cooldown reuses the locked stake and cancels the cooldown", async function () {
    const { registry, token, solver } = await loadFixture(deployFixture);
    await registry.connect(solver).register(NOISE_KEY, MIN_STAKE);
    await registry.connect(solver).deregister();

    const before = await token.balanceOf(solver.address);
    await registry.connect(solver).register(NOISE_KEY, 0); // no new transfer needed
    expect(await token.balanceOf(solver.address)).to.equal(before);
    expect(await registry.isActiveSolver(solver.address)).to.equal(true);
    const profile = await registry.solvers(solver.address);
    expect(profile.stakedAmount).to.equal(MIN_STAKE);
    expect(profile.unlockTime).to.equal(0);
  });

  it("cannot unstake a solver that has not deregistered", async function () {
    const { registry, solver, anyone } = await loadFixture(deployFixture);
    await registry.connect(solver).register(NOISE_KEY, MIN_STAKE);
    await expect(
      registry.connect(anyone).unstake(solver.address),
    ).to.be.revertedWithCustomError(registry, "NotInCooldown");
  });

  it("slash below minStake pushes the solver into cooldown; remainder claimable", async function () {
    const { registry, token, slasher, solver, anyone } =
      await loadFixture(deployFixture);
    await registry.connect(solver).register(NOISE_KEY, MIN_STAKE);

    const slashAmount = ethers.parseEther("600");
    await registry.connect(slasher).slash(solver.address, slashAmount);

    expect(await registry.isActiveSolver(solver.address)).to.equal(false);
    expect(await token.balanceOf(slasher.address)).to.equal(slashAmount);

    await time.increase(COOLDOWN + 1);
    const before = await token.balanceOf(solver.address);
    await registry.connect(anyone).unstake(solver.address);
    expect(await token.balanceOf(solver.address)).to.equal(
      before + MIN_STAKE - slashAmount,
    );
  });

  it("stake remains slashable during the cooldown", async function () {
    const { registry, token, slasher, solver } =
      await loadFixture(deployFixture);
    await registry.connect(solver).register(NOISE_KEY, MIN_STAKE);
    await registry.connect(solver).deregister();

    await registry.connect(slasher).slash(solver.address, MIN_STAKE);
    expect(await token.balanceOf(slasher.address)).to.equal(MIN_STAKE);
    const profile = await registry.solvers(solver.address);
    expect(profile.stakedAmount).to.equal(0);
  });

  it("stores the noise key and rejects a zero key", async function () {
    const { registry, solver } = await loadFixture(deployFixture);
    await expect(
      registry.connect(solver).register(ethers.ZeroHash, MIN_STAKE),
    ).to.be.revertedWithCustomError(registry, "InvalidKey");

    await registry.connect(solver).register(NOISE_KEY, MIN_STAKE);
    expect((await registry.solvers(solver.address)).noiseKey).to.equal(
      NOISE_KEY,
    );

    const newKey = ethers.keccak256(ethers.toUtf8Bytes("rotated"));
    await registry.connect(solver).updateNoiseKey(newKey);
    expect((await registry.solvers(solver.address)).noiseKey).to.equal(newKey);
  });

  it("slashing a solver mid-cooldown resets the cooldown clock", async function () {
    const { registry, slasher, solver, anyone } =
      await loadFixture(deployFixture);
    await registry.connect(solver).register(NOISE_KEY, MIN_STAKE);
    await registry.connect(solver).deregister();

    await time.increase(COOLDOWN - 60); // almost done
    await registry.connect(slasher).slash(solver.address, 1n);

    await time.increase(120); // past the original unlock, not the reset one
    await expect(
      registry.connect(anyone).unstake(solver.address),
    ).to.be.revertedWithCustomError(registry, "CooldownNotOver");

    await time.increase(COOLDOWN);
    await registry.connect(anyone).unstake(solver.address);
  });

  it("records received amount (not sent amount) for fee-on-transfer tokens", async function () {
    const { admin, slasher, solver } = await loadFixture(deployFixture);
    const FeeToken = await ethers.getContractFactory("MockFeeOnTransferERC20");
    const feeToken = await FeeToken.deploy("Fee", "FEE", 18, 100); // 1% fee
    const RegistryFactory = await ethers.getContractFactory("KageRegistry");
    const registry = (await RegistryFactory.deploy(
      await feeToken.getAddress(),
      MIN_STAKE,
      admin.address,
      slasher.address,
    )) as unknown as KageRegistry;

    await feeToken.mint(solver.address, ethers.parseEther("10000"));
    await feeToken
      .connect(solver)
      .approve(await registry.getAddress(), ethers.MaxUint256);

    // sending exactly MIN_STAKE arrives 1% short and must be rejected
    await expect(
      registry.connect(solver).register(NOISE_KEY, MIN_STAKE),
    ).to.be.revertedWithCustomError(registry, "InsufficientStake");

    const sent = (MIN_STAKE * 10_000n) / 9_900n + 1n; // gross-up for the 1% fee
    await registry.connect(solver).register(NOISE_KEY, sent);
    const profile = await registry.solvers(solver.address);
    expect(profile.stakedAmount).to.equal(
      await feeToken.balanceOf(await registry.getAddress()),
    );

    // full round trip stays solvent
    await registry.connect(solver).deregister();
    await time.increase(COOLDOWN + 1);
    await registry.connect(solver).unstake(solver.address);
  });

  it("frozen solver is not active and cannot act until unfrozen", async function () {
    const { registry, slasher, solver } = await loadFixture(deployFixture);
    await registry.connect(solver).register(NOISE_KEY, MIN_STAKE);
    await registry.connect(slasher).freeze(solver.address);

    expect(await registry.isActiveSolver(solver.address)).to.equal(false);

    const newKey = ethers.keccak256(ethers.toUtf8Bytes("evade"));
    await expect(
      registry.connect(solver).updateNoiseKey(newKey),
    ).to.be.revertedWithCustomError(registry, "NodeFrozen");
    await expect(
      registry.connect(solver).deregister(),
    ).to.be.revertedWithCustomError(registry, "NodeFrozen");

    await registry.connect(slasher).unfreeze(solver.address);
    expect(await registry.isActiveSolver(solver.address)).to.equal(true);
    await registry.connect(solver).deregister();
  });

  it("frozen solver in cooldown cannot re-register or unstake", async function () {
    const { registry, slasher, solver, anyone } =
      await loadFixture(deployFixture);
    await registry.connect(solver).register(NOISE_KEY, MIN_STAKE);
    await registry.connect(solver).deregister();
    await registry.connect(slasher).freeze(solver.address);

    await expect(
      registry.connect(solver).register(NOISE_KEY, 0),
    ).to.be.revertedWithCustomError(registry, "NodeFrozen");

    await time.increase(COOLDOWN + 1);
    await expect(
      registry.connect(anyone).unstake(solver.address),
    ).to.be.revertedWithCustomError(registry, "NodeFrozen");

    await registry.connect(slasher).unfreeze(solver.address);
    await registry.connect(anyone).unstake(solver.address);
  });

  it("only slasher can slash", async function () {
    const { registry, solver, anyone } = await loadFixture(deployFixture);
    await registry.connect(solver).register(NOISE_KEY, MIN_STAKE);
    await expect(registry.connect(anyone).slash(solver.address, MIN_STAKE)).to
      .be.reverted;
  });
});
