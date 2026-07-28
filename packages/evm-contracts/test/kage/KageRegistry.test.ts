import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture, time } from "@nomicfoundation/hardhat-network-helpers";
import { KageRegistry, MockERC20 } from "../../typechain-types";

describe("KageRegistry (Solver Staking)", function () {
  const MIN_STAKE = ethers.parseEther("1000");
  const COOLDOWN = 24 * 60 * 60;

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
    await registry.connect(solver).register(MIN_STAKE);

    expect(await registry.isActiveSolver(solver.address)).to.equal(true);
    expect(await registry.solverCount()).to.equal(1);
    const profile = await registry.solvers(solver.address);
    expect(profile.stakedAmount).to.equal(MIN_STAKE);
  });

  it("rejects registration below minStake", async function () {
    const { registry, solver } = await loadFixture(deployFixture);
    await expect(
      registry.connect(solver).register(MIN_STAKE - 1n),
    ).to.be.revertedWithCustomError(registry, "InsufficientStake");
  });

  it("deregister removes the solver from the network immediately", async function () {
    const { registry, solver } = await loadFixture(deployFixture);
    await registry.connect(solver).register(MIN_STAKE);
    await registry.connect(solver).deregister();

    expect(await registry.isActiveSolver(solver.address)).to.equal(false);
    expect(await registry.solverCount()).to.equal(0);
  });

  it("anyone can unstake after the cooldown; funds go to the solver", async function () {
    const { registry, token, solver, anyone } =
      await loadFixture(deployFixture);
    await registry.connect(solver).register(MIN_STAKE);
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
    await registry.connect(solver).register(MIN_STAKE);
    expect(await registry.isActiveSolver(solver.address)).to.equal(true);
  });

  it("re-registering from cooldown reuses the locked stake and cancels the cooldown", async function () {
    const { registry, token, solver } = await loadFixture(deployFixture);
    await registry.connect(solver).register(MIN_STAKE);
    await registry.connect(solver).deregister();

    const before = await token.balanceOf(solver.address);
    await registry.connect(solver).register(0); // no new transfer needed
    expect(await token.balanceOf(solver.address)).to.equal(before);
    expect(await registry.isActiveSolver(solver.address)).to.equal(true);
    const profile = await registry.solvers(solver.address);
    expect(profile.stakedAmount).to.equal(MIN_STAKE);
    expect(profile.unlockTime).to.equal(0);
  });

  it("cannot unstake a solver that has not deregistered", async function () {
    const { registry, solver, anyone } = await loadFixture(deployFixture);
    await registry.connect(solver).register(MIN_STAKE);
    await expect(
      registry.connect(anyone).unstake(solver.address),
    ).to.be.revertedWithCustomError(registry, "NotInCooldown");
  });

  it("slash below minStake pushes the solver into cooldown; remainder claimable", async function () {
    const { registry, token, slasher, solver, anyone } =
      await loadFixture(deployFixture);
    await registry.connect(solver).register(MIN_STAKE);

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
    await registry.connect(solver).register(MIN_STAKE);
    await registry.connect(solver).deregister();

    await registry.connect(slasher).slash(solver.address, MIN_STAKE);
    expect(await token.balanceOf(slasher.address)).to.equal(MIN_STAKE);
    const profile = await registry.solvers(solver.address);
    expect(profile.stakedAmount).to.equal(0);
  });

  it("only slasher can slash", async function () {
    const { registry, solver, anyone } = await loadFixture(deployFixture);
    await registry.connect(solver).register(MIN_STAKE);
    await expect(registry.connect(anyone).slash(solver.address, MIN_STAKE)).to
      .be.reverted;
  });
});
