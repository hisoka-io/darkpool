import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import { loadFixture, time } from "@nomicfoundation/hardhat-network-helpers";
import { KAGE_PROOF, KAGE_PUBLIC_INPUTS } from "../integration/kageGolden";
import {
  EXIT_DELAY,
  HOT_KEY,
  MIN_STAKE,
  MIN_STAKE_FLOOR,
  ROTATED_KEY,
  SETTLE_WINDOW,
  STAKE_DECIMALS,
  deployKageFixture,
  deployKageRegistry,
  messageFor,
  registerSolver,
  signSettlement,
  type KageDeployment,
} from "./kageFixtures";
import type {
  KageRegistry,
  KageRegistryV2Mock,
  MockFeeOnTransferERC20,
} from "../../typechain-types";

const PI = KAGE_PUBLIC_INPUTS;
const ACTIVE = 1n;
const EXITING = 2n;
const EXITED = 3n;
const REGISTRY_LOCATION =
  "0x102b9fa007d4c73faa68f63651f6c057c7e7cb4c5454c9575e84d8c78e4a1b00";
const MAX_EXIT_DELAY = 30n * 24n * 3600n;

async function settleWith(
  d: KageDeployment,
  key: typeof HOT_KEY,
  solverId: bigint = d.solverId,
) {
  const deadline = BigInt(await time.latest()) + SETTLE_WINDOW;
  const sig = await signSettlement(
    key,
    await messageFor(d, PI, deadline, solverId),
  );
  return d.settlement.settleSwap(solverId, deadline, sig, KAGE_PROOF, PI);
}

async function registryFixture() {
  const r = await deployKageRegistry();
  const id = await registerSolver(
    r.registry,
    r.stakeToken,
    r.solverOwner,
    HOT_KEY.address,
  );
  return { ...r, id };
}

describe("KageRegistry", function () {
  describe("initialize", function () {
    it("stores config in the staking token's base units and grants roles to the passed addresses", async function () {
      const { registry, stakeToken, admin, slasher, config, upgrader } =
        await loadFixture(registryFixture);
      expect(await registry.stakingToken()).to.equal(
        await stakeToken.getAddress(),
      );
      expect(await stakeToken.decimals()).to.equal(BigInt(STAKE_DECIMALS));
      expect(await registry.minStake()).to.equal(10_000_000_000n);
      expect(await registry.minStakeFloor()).to.equal(1_000_000_000n);
      expect(await registry.exitDelay()).to.equal(EXIT_DELAY);
      expect(await registry.defaultAdmin()).to.equal(admin.address);
      expect(
        await registry.hasRole(await registry.SLASHER_ROLE(), slasher.address),
      ).to.equal(true);
      expect(
        await registry.hasRole(await registry.CONFIG_ROLE(), config.address),
      ).to.equal(true);
      expect(
        await registry.hasRole(
          await registry.UPGRADER_ROLE(),
          upgrader.address,
        ),
      ).to.equal(true);
    });

    it("rejects zero addresses, a zero floor, a minimum below the floor and a short or overlong exit delay", async function () {
      const [admin, other] = await ethers.getSigners();
      const F = await ethers.getContractFactory("KageRegistry");
      const token = other.address;
      const base: [
        number,
        string,
        string,
        bigint,
        bigint,
        bigint,
        string,
        string,
        string,
      ] = [
        0,
        admin.address,
        token,
        MIN_STAKE,
        MIN_STAKE_FLOOR,
        EXIT_DELAY,
        admin.address,
        admin.address,
        admin.address,
      ];
      const cases: [number, unknown, string][] = [
        [1, ethers.ZeroAddress, "ZeroAddress"],
        [2, ethers.ZeroAddress, "ZeroAddress"],
        [6, ethers.ZeroAddress, "ZeroAddress"],
        [7, ethers.ZeroAddress, "ZeroAddress"],
        [8, ethers.ZeroAddress, "ZeroAddress"],
        [4, 0n, "InvalidAmount"],
        [3, MIN_STAKE_FLOOR - 1n, "MinStakeBelowFloor"],
        [5, 24n * 3600n - 1n, "InvalidDelay"],
        [5, MAX_EXIT_DELAY + 1n, "InvalidDelay"],
      ];
      for (const [i, v, err] of cases) {
        const p = [...base] as unknown[];
        p[i] = v;
        await expect(
          upgrades.deployProxy(F, [p], { kind: "uups" }),
        ).to.be.revertedWithCustomError(F, err);
      }
    });

    it("cannot be initialized twice, and the implementation cannot be initialized at all", async function () {
      const { registry, admin } = await loadFixture(registryFixture);
      const p = {
        initialAdminDelay: 0,
        initialAdmin: admin.address,
        stakingToken: admin.address,
        minStake: MIN_STAKE,
        minStakeFloor: MIN_STAKE_FLOOR,
        exitDelay: EXIT_DELAY,
        slasher: admin.address,
        configManager: admin.address,
        upgrader: admin.address,
      };
      await expect(registry.initialize(p)).to.be.revertedWithCustomError(
        registry,
        "InvalidInitialization",
      );
      const impl = (await ethers.getContractAt(
        "KageRegistry",
        await upgrades.erc1967.getImplementationAddress(
          await registry.getAddress(),
        ),
      )) as unknown as KageRegistry;
      await expect(impl.initialize(p)).to.be.revertedWithCustomError(
        impl,
        "InvalidInitialization",
      );
    });
  });

  describe("register", function () {
    it("issues sequential ids, pulls exactly the stake and emits SolverRegistered", async function () {
      const { registry, stakeToken, solverOwner, stranger, id } =
        await loadFixture(registryFixture);
      expect(id).to.equal(1n);
      const s = await registry.solver(1n);
      expect(s.owner).to.equal(solverOwner.address);
      expect(s.signer).to.equal(HOT_KEY.address);
      expect(s.status).to.equal(ACTIVE);
      expect(s.stake).to.equal(MIN_STAKE);
      expect(await registry.settlementSigner(1n)).to.equal(HOT_KEY.address);

      const amount = MIN_STAKE + 7n;
      await stakeToken.mint(stranger.address, amount);
      await stakeToken
        .connect(stranger)
        .approve(await registry.getAddress(), amount);
      await expect(
        registry.connect(stranger).register(ROTATED_KEY.address, amount),
      )
        .to.emit(registry, "SolverRegistered")
        .withArgs(2n, stranger.address, ROTATED_KEY.address, amount);
      expect(await registry.solverCount()).to.equal(2n);
      expect(await stakeToken.balanceOf(await registry.getAddress())).to.equal(
        MIN_STAKE + amount,
      );
    });

    it("rejects a zero signer and a stake below the minimum", async function () {
      const { registry, stakeToken, stranger } =
        await loadFixture(registryFixture);
      await stakeToken.mint(stranger.address, MIN_STAKE);
      await stakeToken
        .connect(stranger)
        .approve(await registry.getAddress(), MIN_STAKE);
      await expect(
        registry.connect(stranger).register(ethers.ZeroAddress, MIN_STAKE),
      ).to.be.revertedWithCustomError(registry, "ZeroAddress");
      await expect(
        registry.connect(stranger).register(HOT_KEY.address, MIN_STAKE - 1n),
      ).to.be.revertedWithCustomError(registry, "InsufficientStake");
    });

    it("rejects a fee-on-transfer staking token", async function () {
      const fot = (await (
        await ethers.getContractFactory("MockFeeOnTransferERC20")
      ).deploy(
        "Fee USD",
        "FUSD",
        STAKE_DECIMALS,
        100,
      )) as unknown as MockFeeOnTransferERC20;
      const { registry, stranger } = await deployKageRegistry(
        await fot.getAddress(),
      );
      await fot.mint(stranger.address, MIN_STAKE);
      await fot
        .connect(stranger)
        .approve(await registry.getAddress(), MIN_STAKE);
      await expect(
        registry.connect(stranger).register(HOT_KEY.address, MIN_STAKE),
      ).to.be.revertedWithCustomError(registry, "FeeOnTransferUnsupported");
      expect(await registry.solverCount()).to.equal(0n);
    });
  });

  describe("lifecycle against real settlements", function () {
    it("rotation: the old key's approval fails from that block, the new key's settles the same proof", async function () {
      const d = await loadFixture(deployKageFixture);
      await expect(
        d.registry
          .connect(d.solverOwner)
          .rotateSigner(d.solverId, ROTATED_KEY.address),
      )
        .to.emit(d.registry, "SignerRotated")
        .withArgs(d.solverId, HOT_KEY.address, ROTATED_KEY.address);
      await expect(settleWith(d, HOT_KEY))
        .to.be.revertedWithCustomError(d.settlement, "InvalidSolverSignature")
        .withArgs(d.solverId);
      await expect(settleWith(d, ROTATED_KEY)).to.emit(
        d.settlement,
        "KageSwapSettled",
      );
    });

    it("rotation rules: owner only, non-zero, changed, refused once exited", async function () {
      const d = await loadFixture(deployKageFixture);
      await expect(
        d.registry
          .connect(d.stranger)
          .rotateSigner(d.solverId, ROTATED_KEY.address),
      )
        .to.be.revertedWithCustomError(d.registry, "NotSolverOwner")
        .withArgs(d.solverId);
      await expect(
        d.registry
          .connect(d.solverOwner)
          .rotateSigner(d.solverId, ethers.ZeroAddress),
      ).to.be.revertedWithCustomError(d.registry, "ZeroAddress");
      await expect(
        d.registry
          .connect(d.solverOwner)
          .rotateSigner(d.solverId, HOT_KEY.address),
      ).to.be.revertedWithCustomError(d.registry, "SignerUnchanged");
      await d.registry.connect(d.solverOwner).requestExit(d.solverId);
      await d.registry
        .connect(d.solverOwner)
        .rotateSigner(d.solverId, ROTATED_KEY.address);
      await time.increase(EXIT_DELAY);
      await d.registry.withdrawStake(d.solverId);
      await expect(
        d.registry
          .connect(d.solverOwner)
          .rotateSigner(d.solverId, HOT_KEY.address),
      )
        .to.be.revertedWithCustomError(d.registry, "SolverNotRegistered")
        .withArgs(d.solverId);
    });

    it("requestExit stops settling; cancelExit restores it", async function () {
      const d = await loadFixture(deployKageFixture);
      const tx = d.registry.connect(d.solverOwner).requestExit(d.solverId);
      await expect(tx).to.emit(d.registry, "ExitRequested");
      expect((await d.registry.solver(d.solverId)).status).to.equal(EXITING);
      expect(await d.registry.settlementSigner(d.solverId)).to.equal(
        ethers.ZeroAddress,
      );
      await expect(settleWith(d, HOT_KEY))
        .to.be.revertedWithCustomError(d.settlement, "SolverNotActive")
        .withArgs(d.solverId);

      await expect(d.registry.connect(d.solverOwner).cancelExit(d.solverId))
        .to.emit(d.registry, "ExitCancelled")
        .withArgs(d.solverId);
      await expect(settleWith(d, HOT_KEY)).to.emit(
        d.settlement,
        "KageSwapSettled",
      );
    });

    it("withdrawStake: refused before the exit delay, then pays the owner whoever calls, once", async function () {
      const d = await loadFixture(deployKageFixture);
      await d.registry.connect(d.solverOwner).requestExit(d.solverId);
      const unlock = (await d.registry.solver(d.solverId)).unlockTime;
      expect(unlock).to.equal(BigInt(await time.latest()) + EXIT_DELAY);
      await time.setNextBlockTimestamp(unlock - 1n);
      await expect(d.registry.connect(d.stranger).withdrawStake(d.solverId))
        .to.be.revertedWithCustomError(d.registry, "ExitTooEarly")
        .withArgs(unlock);

      await time.setNextBlockTimestamp(unlock);
      const before = await d.stakeToken.balanceOf(d.solverOwner.address);
      await expect(d.registry.connect(d.stranger).withdrawStake(d.solverId))
        .to.emit(d.registry, "Unstaked")
        .withArgs(d.solverId, d.solverOwner.address, MIN_STAKE);
      expect(await d.stakeToken.balanceOf(d.solverOwner.address)).to.equal(
        before + MIN_STAKE,
      );
      const s = await d.registry.solver(d.solverId);
      expect(s.status).to.equal(EXITED);
      expect(s.stake).to.equal(0n);
      await expect(
        d.registry.withdrawStake(d.solverId),
      ).to.be.revertedWithCustomError(d.registry, "SolverNotExiting");
      await expect(settleWith(d, HOT_KEY)).to.be.revertedWithCustomError(
        d.settlement,
        "SolverNotActive",
      );
    });

    it("freeze blocks settling, exit, cancel, withdrawal and top-up; unfreeze restores settling", async function () {
      const d = await loadFixture(deployKageFixture);
      const owner = d.registry.connect(d.solverOwner);
      await expect(d.registry.connect(d.slasher).freeze(d.solverId))
        .to.emit(d.registry, "SolverFrozen")
        .withArgs(d.solverId, d.slasher.address);
      expect(await d.registry.settlementSigner(d.solverId)).to.equal(
        ethers.ZeroAddress,
      );
      await expect(settleWith(d, HOT_KEY)).to.be.revertedWithCustomError(
        d.settlement,
        "SolverNotActive",
      );
      await expect(owner.requestExit(d.solverId)).to.be.revertedWithCustomError(
        d.registry,
        "SolverIsFrozen",
      );
      await expect(
        owner.addStake(d.solverId, 1n),
      ).to.be.revertedWithCustomError(d.registry, "SolverIsFrozen");
      await expect(
        d.registry.connect(d.slasher).freeze(d.solverId),
      ).to.be.revertedWithCustomError(d.registry, "SolverIsFrozen");

      await d.registry.connect(d.slasher).unfreeze(d.solverId);
      await owner.requestExit(d.solverId);
      await d.registry.connect(d.slasher).freeze(d.solverId);
      await expect(owner.cancelExit(d.solverId)).to.be.revertedWithCustomError(
        d.registry,
        "SolverIsFrozen",
      );
      await time.increase(EXIT_DELAY);
      await expect(
        d.registry.withdrawStake(d.solverId),
      ).to.be.revertedWithCustomError(d.registry, "SolverIsFrozen");
      await expect(d.registry.connect(d.slasher).unfreeze(d.solverId))
        .to.emit(d.registry, "SolverUnfrozen")
        .withArgs(d.solverId, d.slasher.address);
      await expect(
        d.registry.connect(d.slasher).unfreeze(d.solverId),
      ).to.be.revertedWithCustomError(d.registry, "SolverNotFrozen");
      await owner.cancelExit(d.solverId);
      await expect(settleWith(d, HOT_KEY)).to.emit(
        d.settlement,
        "KageSwapSettled",
      );
    });

    it("slash below the minimum stops settling until addStake; the slasher receives min(amount, stake)", async function () {
      const d = await loadFixture(deployKageFixture);
      const cut = 1n;
      await expect(d.registry.connect(d.slasher).slash(d.solverId, cut))
        .to.emit(d.registry, "Slashed")
        .withArgs(d.solverId, cut, d.slasher.address);
      expect(await d.stakeToken.balanceOf(d.slasher.address)).to.equal(cut);
      expect(await d.registry.settlementSigner(d.solverId)).to.equal(
        ethers.ZeroAddress,
      );
      await expect(settleWith(d, HOT_KEY)).to.be.revertedWithCustomError(
        d.settlement,
        "SolverNotActive",
      );

      await d.stakeToken.mint(d.solverOwner.address, cut);
      await d.stakeToken
        .connect(d.solverOwner)
        .approve(await d.registry.getAddress(), cut);
      await expect(d.registry.connect(d.solverOwner).addStake(d.solverId, cut))
        .to.emit(d.registry, "StakeAdded")
        .withArgs(d.solverId, cut);
      await expect(settleWith(d, HOT_KEY)).to.emit(
        d.settlement,
        "KageSwapSettled",
      );

      await d.registry.connect(d.slasher).slash(d.solverId, MIN_STAKE * 10n);
      expect((await d.registry.solver(d.solverId)).stake).to.equal(0n);
      expect(await d.stakeToken.balanceOf(d.slasher.address)).to.equal(
        MIN_STAKE + cut,
      );
      await expect(
        d.registry.connect(d.slasher).slash(d.solverId, 1n),
      ).to.be.revertedWithCustomError(d.registry, "NothingToSlash");
    });

    it("slashing an exiting solver restarts its exit delay", async function () {
      const d = await loadFixture(deployKageFixture);
      await d.registry.connect(d.solverOwner).requestExit(d.solverId);
      await time.increase(EXIT_DELAY - 10n);
      await d.registry.connect(d.slasher).slash(d.solverId, 5n);
      const unlock = (await d.registry.solver(d.solverId)).unlockTime;
      expect(unlock).to.equal(BigInt(await time.latest()) + EXIT_DELAY);
      await time.increase(20n);
      await expect(
        d.registry.withdrawStake(d.solverId),
      ).to.be.revertedWithCustomError(d.registry, "ExitTooEarly");
    });

    it("an exited solver cannot be slashed or frozen", async function () {
      const d = await loadFixture(deployKageFixture);
      await d.registry.connect(d.solverOwner).requestExit(d.solverId);
      await time.increase(EXIT_DELAY);
      await d.registry.withdrawStake(d.solverId);
      await expect(d.registry.connect(d.slasher).slash(d.solverId, 1n))
        .to.be.revertedWithCustomError(d.registry, "SolverNotRegistered")
        .withArgs(d.solverId);
      await expect(
        d.registry.connect(d.slasher).freeze(d.solverId),
      ).to.be.revertedWithCustomError(d.registry, "SolverNotRegistered");
    });

    it("updateConfig raising the minimum stops an under-staked solver; floors are enforced", async function () {
      const d = await loadFixture(deployKageFixture);
      const raised = MIN_STAKE * 2n;
      await expect(
        d.registry.connect(d.config).updateConfig(raised, EXIT_DELAY),
      )
        .to.emit(d.registry, "ConfigUpdated")
        .withArgs(raised, EXIT_DELAY);
      expect((await d.registry.solver(d.solverId)).stake).to.equal(MIN_STAKE);
      await expect(settleWith(d, HOT_KEY)).to.be.revertedWithCustomError(
        d.settlement,
        "SolverNotActive",
      );
      await d.registry.connect(d.config).updateConfig(MIN_STAKE, EXIT_DELAY);
      expect(await d.registry.settlementSigner(d.solverId)).to.equal(
        HOT_KEY.address,
      );
      await expect(
        d.registry
          .connect(d.config)
          .updateConfig(MIN_STAKE_FLOOR - 1n, EXIT_DELAY),
      ).to.be.revertedWithCustomError(d.registry, "MinStakeBelowFloor");
      await expect(
        d.registry.connect(d.config).updateConfig(MIN_STAKE, 24n * 3600n - 1n),
      ).to.be.revertedWithCustomError(d.registry, "InvalidDelay");
      await expect(
        d.registry
          .connect(d.config)
          .updateConfig(MIN_STAKE, MAX_EXIT_DELAY + 1n),
      ).to.be.revertedWithCustomError(d.registry, "InvalidDelay");
    });

    it("the maximum exit delay is accepted at initialize and updateConfig, and exit, slash and withdrawal run at it", async function () {
      const d = await loadFixture(deployKageFixture);
      expect(await d.registry.MAX_EXIT_DELAY()).to.equal(MAX_EXIT_DELAY);

      const [admin] = await ethers.getSigners();
      const atMax = (await upgrades.deployProxy(
        await ethers.getContractFactory("KageRegistry"),
        [
          [
            0,
            admin.address,
            await d.stakeToken.getAddress(),
            MIN_STAKE,
            MIN_STAKE_FLOOR,
            MAX_EXIT_DELAY,
            admin.address,
            admin.address,
            admin.address,
          ],
        ],
        { kind: "uups", initializer: "initialize" },
      )) as unknown as KageRegistry;
      expect(await atMax.exitDelay()).to.equal(MAX_EXIT_DELAY);

      await expect(
        d.registry.connect(d.config).updateConfig(MIN_STAKE, MAX_EXIT_DELAY),
      )
        .to.emit(d.registry, "ConfigUpdated")
        .withArgs(MIN_STAKE, MAX_EXIT_DELAY);
      await d.registry.connect(d.solverOwner).requestExit(d.solverId);
      expect((await d.registry.solver(d.solverId)).unlockTime).to.equal(
        BigInt(await time.latest()) + MAX_EXIT_DELAY,
      );
      await time.increase(MAX_EXIT_DELAY - 10n);
      await d.registry.connect(d.slasher).slash(d.solverId, 5n);
      const unlock = (await d.registry.solver(d.solverId)).unlockTime;
      expect(unlock).to.equal(BigInt(await time.latest()) + MAX_EXIT_DELAY);
      await time.increaseTo(unlock);
      await expect(d.registry.withdrawStake(d.solverId))
        .to.emit(d.registry, "Unstaked")
        .withArgs(d.solverId, d.solverOwner.address, MIN_STAKE - 5n);
    });

    it("owner-only calls reject everyone else, and addStake requires an active solver", async function () {
      const d = await loadFixture(deployKageFixture);
      const s = d.registry.connect(d.stranger);
      for (const call of [
        () => s.addStake(d.solverId, 1n),
        () => s.requestExit(d.solverId),
        () => s.cancelExit(d.solverId),
        () => s.rotateSigner(d.solverId, ROTATED_KEY.address),
      ]) {
        await expect(call())
          .to.be.revertedWithCustomError(d.registry, "NotSolverOwner")
          .withArgs(d.solverId);
      }
      const owner = d.registry.connect(d.solverOwner);
      await expect(owner.cancelExit(d.solverId)).to.be.revertedWithCustomError(
        d.registry,
        "SolverNotExiting",
      );
      await owner.requestExit(d.solverId);
      await expect(owner.addStake(d.solverId, 1n))
        .to.be.revertedWithCustomError(d.registry, "SolverNotActive")
        .withArgs(d.solverId);
      await expect(owner.requestExit(d.solverId)).to.be.revertedWithCustomError(
        d.registry,
        "SolverNotActive",
      );
    });
  });

  describe("pause", function () {
    it("blocks register, addStake, requestExit and cancelExit; leaves rotateSigner, withdrawStake, slash and freeze open", async function () {
      const { registry, stakeToken, admin, slasher, solverOwner, id } =
        await loadFixture(registryFixture);
      const second = await registerSolver(
        registry,
        stakeToken,
        solverOwner,
        ROTATED_KEY.address,
      );
      await registry.connect(solverOwner).requestExit(second);
      await registry.connect(admin).pause();
      const owner = registry.connect(solverOwner);
      for (const call of [
        () => owner.register(HOT_KEY.address, MIN_STAKE),
        () => owner.addStake(id, 1n),
        () => owner.requestExit(id),
        () => owner.cancelExit(second),
      ]) {
        await expect(call()).to.be.revertedWithCustomError(
          registry,
          "EnforcedPause",
        );
      }
      await expect(owner.rotateSigner(id, ROTATED_KEY.address)).to.emit(
        registry,
        "SignerRotated",
      );
      await expect(registry.connect(slasher).slash(id, 1n)).to.emit(
        registry,
        "Slashed",
      );
      await expect(registry.connect(slasher).freeze(id)).to.emit(
        registry,
        "SolverFrozen",
      );
      await time.increase(EXIT_DELAY);
      await expect(registry.withdrawStake(second)).to.emit(
        registry,
        "Unstaked",
      );
      await registry.connect(admin).unpause();
      await registry.connect(slasher).unfreeze(id);
      await expect(owner.requestExit(id)).to.emit(registry, "ExitRequested");
    });
  });

  describe("roles", function () {
    it("each privileged function rejects every other role", async function () {
      const { registry, admin, slasher, config, upgrader, stranger, id } =
        await loadFixture(registryFixture);
      const roles = {
        admin: await registry.DEFAULT_ADMIN_ROLE(),
        slasher: await registry.SLASHER_ROLE(),
        config: await registry.CONFIG_ROLE(),
        upgrader: await registry.UPGRADER_ROLE(),
      };
      const holders = { admin, slasher, config, upgrader, stranger };
      const v2 = await (
        await ethers.getContractFactory("KageRegistryV2Mock")
      ).deploy();
      const v2Addr = await v2.getAddress();
      const calls: [
        string,
        keyof typeof roles,
        (r: KageRegistry) => unknown,
      ][] = [
        ["freeze", "slasher", (r) => r.freeze(id)],
        ["unfreeze", "slasher", (r) => r.unfreeze(id)],
        ["slash", "slasher", (r) => r.slash(id, 1n)],
        [
          "updateConfig",
          "config",
          (r) => r.updateConfig(MIN_STAKE, EXIT_DELAY),
        ],
        ["pause", "admin", (r) => r.pause()],
        ["unpause", "admin", (r) => r.unpause()],
        [
          "upgradeToAndCall",
          "upgrader",
          (r) => r.upgradeToAndCall(v2Addr, "0x"),
        ],
      ];
      for (const [name, role, call] of calls) {
        for (const [who, signer] of Object.entries(holders)) {
          if (who === role) continue;
          await expect(
            call(registry.connect(signer)) as Promise<unknown>,
            `${name} by ${who}`,
          )
            .to.be.revertedWithCustomError(
              registry,
              "AccessControlUnauthorizedAccount",
            )
            .withArgs(signer.address, roles[role]);
        }
      }
    });
  });

  describe("UUPS upgrade", function () {
    it("an UPGRADER upgrade keeps every solver and config word; a non-UUPS implementation is refused", async function () {
      const { registry, upgrader, stakeToken, solverOwner, id } =
        await loadFixture(registryFixture);
      const proxy = await registry.getAddress();
      expect(
        await ethers.provider.getStorage(proxy, REGISTRY_LOCATION),
      ).to.equal(ethers.zeroPadValue(await stakeToken.getAddress(), 32));
      const before = await registry.solver(id);

      const notUups = await (
        await ethers.getContractFactory("NotUUPSMock")
      ).deploy();
      await expect(
        registry
          .connect(upgrader)
          .upgradeToAndCall(await notUups.getAddress(), "0x"),
      ).to.be.revertedWithCustomError(registry, "ERC1967InvalidImplementation");

      const v2 = await (
        await ethers.getContractFactory("KageRegistryV2Mock")
      ).deploy();
      await registry
        .connect(upgrader)
        .upgradeToAndCall(await v2.getAddress(), "0x");
      const upgraded = (await ethers.getContractAt(
        "KageRegistryV2Mock",
        proxy,
      )) as unknown as KageRegistryV2Mock;
      expect(await upgraded.version()).to.equal(2n);
      const after = await upgraded.solver(id);
      expect(after.owner).to.equal(solverOwner.address);
      expect(after.signer).to.equal(before.signer);
      expect(after.stake).to.equal(before.stake);
      expect(after.status).to.equal(before.status);
      expect(await upgraded.solverCount()).to.equal(1n);
      expect(await upgraded.minStake()).to.equal(MIN_STAKE);
      expect(await upgraded.stakingToken()).to.equal(
        await stakeToken.getAddress(),
      );
      expect(await upgraded.settlementSigner(id)).to.equal(HOT_KEY.address);
    });

    it("pins every namespace word and both packed Solver words at their raw slots", async function () {
      const { registry, stakeToken, slasher, solverOwner, id } =
        await loadFixture(registryFixture);
      const proxy = await registry.getAddress();
      await registry.connect(solverOwner).requestExit(id);
      const unlockTime = BigInt(await time.latest()) + EXIT_DELAY;
      await registry.connect(slasher).freeze(id);

      const base = BigInt(REGISTRY_LOCATION);
      const word = async (slot: bigint) =>
        BigInt(await ethers.provider.getStorage(proxy, slot));
      expect(await word(base)).to.equal(BigInt(await stakeToken.getAddress()));
      expect(await word(base + 1n)).to.equal(MIN_STAKE_FLOOR);
      expect(await word(base + 2n)).to.equal(MIN_STAKE);
      expect(await word(base + 3n)).to.equal(EXIT_DELAY);
      expect(await word(base + 4n)).to.equal(1n);

      const solverSlot = BigInt(
        ethers.keccak256(
          ethers.AbiCoder.defaultAbiCoder().encode(
            ["uint256", "uint256"],
            [id, base + 5n],
          ),
        ),
      );
      // Word 0: owner (bytes 0-19), status (20), frozen (21), unlockTime (22-29). Word 1: signer (0-19), stake (20-31).
      expect(await word(solverSlot)).to.equal(
        BigInt(solverOwner.address) |
          (EXITING << 160n) |
          (1n << 168n) |
          (unlockTime << 176n),
      );
      expect(await word(solverSlot + 1n)).to.equal(
        BigInt(HOT_KEY.address) | (MIN_STAKE << 160n),
      );
    });

    it("the ERC-7201 namespace constant matches its formula", async function () {
      const inner = BigInt(ethers.id("hisoka.kage.registry")) - 1n;
      const slot =
        BigInt(
          ethers.keccak256(
            ethers.AbiCoder.defaultAbiCoder().encode(["uint256"], [inner]),
          ),
        ) & ~0xffn;
      expect(ethers.toBeHex(slot, 32)).to.equal(REGISTRY_LOCATION);
    });
  });
});
