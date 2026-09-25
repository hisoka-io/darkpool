import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { NoxRegistry, SokaToken } from "../../typechain-types";

describe("SokaToken", function () {
  const SUPPLY = ethers.parseEther("1000000000");

  async function deployFixture() {
    const [deployer, treasury, owner, relayer, stranger] =
      await ethers.getSigners();
    const token = (await (
      await ethers.getContractFactory("SokaToken")
    ).deploy(treasury.address, SUPPLY, owner.address)) as unknown as SokaToken;
    await token.waitForDeployment();
    return { token, deployer, treasury, owner, relayer, stranger };
  }

  it("is Soka / SOKA with 18 decimals", async function () {
    const { token } = await loadFixture(deployFixture);
    expect(await token.name()).to.equal("Soka");
    expect(await token.symbol()).to.equal("SOKA");
    expect(await token.decimals()).to.equal(18n);
  });

  it("mints the whole initial supply to the treasury and nothing to the deployer", async function () {
    const { token, deployer, treasury } = await loadFixture(deployFixture);
    expect(await token.totalSupply()).to.equal(SUPPLY);
    expect(await token.balanceOf(treasury.address)).to.equal(SUPPLY);
    expect(await token.balanceOf(deployer.address)).to.equal(0n);
  });

  it("lets only the owner mint", async function () {
    const { token, owner, stranger, treasury } =
      await loadFixture(deployFixture);
    await expect(token.connect(stranger).mint(stranger.address, 1n))
      .to.be.revertedWithCustomError(token, "OwnableUnauthorizedAccount")
      .withArgs(stranger.address);
    await expect(token.connect(treasury).mint(treasury.address, 1n))
      .to.be.revertedWithCustomError(token, "OwnableUnauthorizedAccount")
      .withArgs(treasury.address);

    await token.connect(owner).mint(stranger.address, 5n);
    expect(await token.balanceOf(stranger.address)).to.equal(5n);
    expect(await token.totalSupply()).to.equal(SUPPLY + 5n);
  });

  it("fixes the supply for good once ownership is renounced", async function () {
    const { token, owner } = await loadFixture(deployFixture);
    await token.connect(owner).renounceOwnership();
    expect(await token.owner()).to.equal(ethers.ZeroAddress);
    await expect(token.connect(owner).mint(owner.address, 1n))
      .to.be.revertedWithCustomError(token, "OwnableUnauthorizedAccount")
      .withArgs(owner.address);
  });

  it("rejects a zero treasury and a zero owner at construction", async function () {
    const [, treasury, owner] = await ethers.getSigners();
    const factory = await ethers.getContractFactory("SokaToken");
    await expect(factory.deploy(ethers.ZeroAddress, SUPPLY, owner.address))
      .to.be.revertedWithCustomError(factory, "ERC20InvalidReceiver")
      .withArgs(ethers.ZeroAddress);
    await expect(factory.deploy(treasury.address, SUPPLY, ethers.ZeroAddress))
      .to.be.revertedWithCustomError(factory, "OwnableInvalidOwner")
      .withArgs(ethers.ZeroAddress);
  });

  it("works as the NoxRegistry staking token: a stake moves in full and comes back on unstake", async function () {
    const { token, treasury, relayer } = await loadFixture(deployFixture);
    const [admin] = await ethers.getSigners();
    const minStake = ethers.parseEther("1");
    const registry = (await upgrades.deployProxy(
      await ethers.getContractFactory("NoxRegistry"),
      [
        [
          0,
          admin.address,
          await token.getAddress(),
          minStake,
          86400,
          minStake,
          admin.address,
          admin.address,
          admin.address,
        ],
      ],
      { kind: "uups" },
    )) as unknown as NoxRegistry;
    await registry.waitForDeployment();
    const registryAddress = await registry.getAddress();

    await token.connect(treasury).transfer(relayer.address, minStake);
    await token.connect(relayer).approve(registryAddress, minStake);
    await registry
      .connect(relayer)
      .register(
        ethers.hexlify(ethers.randomBytes(32)),
        "/ip4/127.0.0.1/tcp/15000",
        "",
        "",
        minStake,
        1,
      );
    expect(await token.balanceOf(registryAddress)).to.equal(minStake);
    expect((await registry.relayers(relayer.address)).stakedAmount).to.equal(
      minStake,
    );

    await registry.forceUnregister(relayer.address);
    expect(await token.balanceOf(relayer.address)).to.equal(minStake);
    expect(await token.balanceOf(registryAddress)).to.equal(0n);
  });
});
