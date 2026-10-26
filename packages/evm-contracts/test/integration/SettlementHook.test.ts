import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture, time } from "@nomicfoundation/hardhat-network-helpers";
import { COMPLIANCE_PK } from "../helpers/fixtures";
import {
  BN254_FR,
  NO_BOUND,
  OUTPUT_WORDS,
  b32,
  deployController,
  deployStubbedPool,
} from "../helpers/settlementFixtures";
import type {
  DarkPool,
  SettlementControllerHarness,
} from "../../typechain-types";

const MAX_UINT256 = 2n ** 256n - 1n;

interface Layout {
  k: number;
  m: number;
  e: number;
}
const KAGE: Layout = { k: 2, m: 4, e: 0 };

function vectorLength({ k, m, e }: Layout): number {
  return 4 + k + OUTPUT_WORDS * m + e;
}

let nonce = 0n;

/**
 * A valid-shaped vector for `layout` that passes every pre-verify guard: current compliance key, the pool's
 * current root, timestamp `ts`, distinct fresh nullifiers, distinct non-zero output leaves.
 */
async function moduleVector(
  darkPool: DarkPool,
  layout: Layout,
  ts?: bigint,
): Promise<string[]> {
  const pi = new Array<string>(vectorLength(layout)).fill(b32(0n));
  pi[0] = b32(COMPLIANCE_PK[0]);
  pi[1] = b32(COMPLIANCE_PK[1]);
  pi[2] = b32(ts ?? BigInt(await time.latest()));
  nonce += 1000n;
  for (let i = 0; i < layout.k; i++)
    pi[3 + i] = b32(0x1000000n + nonce + BigInt(i));
  const r = 3 + layout.k;
  pi[r] = await darkPool.getCurrentRoot();
  for (let j = 0; j < layout.m; j++) {
    const b = r + 1 + OUTPUT_WORDS * j;
    pi[b] = b32(0xa000000n + nonce + BigInt(j));
    pi[b + 1] = b32(0xe000000n + nonce + BigInt(j));
    for (let c = 0; c < 7; c++)
      pi[b + 2 + c] = b32(BigInt(1 + c) * 0x10n + BigInt(j));
  }
  for (let x = 0; x < layout.e; x++) {
    pi[r + 1 + OUTPUT_WORDS * layout.m + x] = b32(0xdead00n + BigInt(x));
  }
  return pi;
}

async function registered(
  layout: Layout = KAGE,
  maxPast: bigint = NO_BOUND,
  maxFuture: bigint = NO_BOUND,
) {
  const pool = await deployStubbedPool();
  const controller = await deployController(pool.darkPool);
  await pool.darkPool
    .connect(pool.upgrader)
    .registerSettlementModule(
      await controller.getAddress(),
      await pool.stub.getAddress(),
      layout.k,
      layout.m,
      layout.e,
      maxPast,
      maxFuture,
    );
  return { ...pool, controller };
}

const kageModule = () => registered();

describe("settle (generic settlement hook)", function () {
  describe("effects", function () {
    it("spends k nullifiers, inserts m outputs in vector order, emits ModuleSettled last, moves no value", async function () {
      const { darkPool, controller, token } = await loadFixture(kageModule);
      const pi = await moduleVector(darkPool, KAGE);
      const first = await darkPool.getNextLeafIndex();
      const poolAddr = await darkPool.getAddress();
      const balBefore = await token.balanceOf(poolAddr);

      const receipt = await (await controller.settle("0x", pi)).wait();
      const parsed = receipt!.logs
        .filter((l) => l.address === poolAddr)
        .map((l) => darkPool.interface.parseLog(l));

      expect(await darkPool.isNullifierSpent(pi[3])).to.equal(true);
      expect(await darkPool.isNullifierSpent(pi[4])).to.equal(true);
      expect(await darkPool.getNextLeafIndex()).to.equal(first + 4n);
      const notes = parsed.filter((p) => p?.name === "NewNote");
      expect(notes.map((n) => n!.args.commitment)).to.deep.equal([
        pi[6],
        pi[15],
        pi[24],
        pi[33],
      ]);
      expect(notes.map((n) => n!.args.leafIndex)).to.deep.equal([
        first,
        first + 1n,
        first + 2n,
        first + 3n,
      ]);
      expect(parsed[parsed.length - 1]!.name).to.equal("ModuleSettled");
      await expect(receipt)
        .to.emit(darkPool, "ModuleSettled")
        .withArgs(await controller.getAddress(), first, 4n);
      expect(await token.balanceOf(poolAddr)).to.equal(balBefore);
    });

    it("indexes a batch-shaped module generically (k=8, m=9, e=1): nullifiers 3..10, root 11, nine inserts, word 93 unread", async function () {
      const layout = { k: 8, m: 9, e: 1 };
      const { darkPool, controller } = await registered(layout);
      const pi = await moduleVector(darkPool, layout);
      expect(pi.length).to.equal(94);
      pi[93] = b32(BN254_FR - 1n);
      const first = await darkPool.getNextLeafIndex();
      const receipt = await (await controller.settle("0x", pi)).wait();
      for (let i = 3; i <= 10; i++) {
        expect(
          await darkPool.isNullifierSpent(pi[i]),
          `nullifier ${i}`,
        ).to.equal(true);
      }
      expect(await darkPool.isNullifierSpent(pi[11])).to.equal(false);
      expect(await darkPool.isNullifierSpent(pi[93])).to.equal(false);
      const notes = receipt!.logs
        .map((l) => {
          try {
            return darkPool.interface.parseLog(l);
          } catch {
            return null;
          }
        })
        .filter((p) => p?.name === "NewNote");
      expect(notes.map((n) => n!.args.commitment)).to.deep.equal(
        Array.from({ length: 9 }, (_, j) => pi[12 + 9 * j]),
      );
      await expect(receipt)
        .to.emit(darkPool, "ModuleSettled")
        .withArgs(await controller.getAddress(), first, 9n);
    });

    it("reverts NullifierAlreadySpent on a replay and on a nullifier repeated inside one vector", async function () {
      const { darkPool, controller } = await loadFixture(kageModule);
      const pi = await moduleVector(darkPool, KAGE);
      await controller.settle("0x", pi);
      const replay = await moduleVector(darkPool, KAGE);
      replay[4] = pi[3];
      await expect(
        controller.settle("0x", replay),
      ).to.be.revertedWithCustomError(darkPool, "NullifierAlreadySpent");
      const dup = await moduleVector(darkPool, KAGE);
      dup[4] = dup[3];
      await expect(controller.settle("0x", dup)).to.be.revertedWithCustomError(
        darkPool,
        "NullifierAlreadySpent",
      );
    });

    it("reverts InvalidLeaf for a zero output leaf", async function () {
      const { darkPool, controller } = await loadFixture(kageModule);
      const pi = await moduleVector(darkPool, KAGE);
      pi[15] = b32(0n);
      await expect(controller.settle("0x", pi)).to.be.revertedWithCustomError(
        darkPool,
        "InvalidLeaf",
      );
    });
  });

  describe("guards", function () {
    it("rejects a caller that is not a registered module: an EOA and an unregistered contract", async function () {
      const { darkPool, user } = await loadFixture(kageModule);
      const pi = await moduleVector(darkPool, KAGE);
      await expect(darkPool.connect(user).settle("0x", pi))
        .to.be.revertedWithCustomError(darkPool, "UnknownModule")
        .withArgs(user.address);
      const stranger = await deployController(darkPool);
      await expect(stranger.settle("0x", pi))
        .to.be.revertedWithCustomError(darkPool, "UnknownModule")
        .withArgs(await stranger.getAddress());
    });

    it("rejects a vector one word short or one word long, counting the module words", async function () {
      const layout = { k: 2, m: 4, e: 1 };
      const { darkPool, controller } = await registered(layout);
      const pi = await moduleVector(darkPool, layout);
      expect(pi.length).to.equal(43);
      await expect(
        controller.settle("0x", pi.slice(0, 42)),
      ).to.be.revertedWithCustomError(darkPool, "InvalidInputsLength");
      await expect(
        controller.settle("0x", [...pi, b32(1n)]),
      ).to.be.revertedWithCustomError(darkPool, "InvalidInputsLength");
      await expect(controller.settle("0x", pi)).to.not.be.reverted;
    });

    it("rejects an unknown root", async function () {
      const { darkPool, controller } = await loadFixture(kageModule);
      const pi = await moduleVector(darkPool, KAGE);
      pi[5] = b32(0xdeadn);
      await expect(controller.settle("0x", pi)).to.be.revertedWithCustomError(
        darkPool,
        "InvalidRoot",
      );
    });

    it("rejects a compliance key that is not the current one, including the key rotated away from", async function () {
      const { darkPool, controller, upgrader } = await loadFixture(kageModule);
      const wrong = await moduleVector(darkPool, KAGE);
      wrong[0] = b32(COMPLIANCE_PK[0] + 1n);
      await expect(
        controller.settle("0x", wrong),
      ).to.be.revertedWithCustomError(darkPool, "ComplianceKeyStale");

      const BASE8_X =
        5299619240641551281634865583518297030282874472190772894086521144482721001553n;
      const BASE8_Y =
        16950150798460657717958625567821834550301663161624707787222815936182638968203n;
      await darkPool.connect(upgrader).rotateComplianceKey(BASE8_X, BASE8_Y);
      const stale = await moduleVector(darkPool, KAGE);
      await expect(controller.settle("0x", stale))
        .to.be.revertedWithCustomError(darkPool, "ComplianceKeyStale")
        .withArgs(2n, BASE8_X, BASE8_Y);
    });

    it("rejects with InvalidProof when the module verifier returns false", async function () {
      const { darkPool, controller, upgrader } = await loadFixture(kageModule);
      const falseVerifier = await (
        await ethers.getContractFactory("FalseVerifier")
      ).deploy();
      await darkPool
        .connect(upgrader)
        .setModuleVerifier(
          await controller.getAddress(),
          await falseVerifier.getAddress(),
        );
      const pi = await moduleVector(darkPool, KAGE);
      await expect(controller.settle("0x", pi)).to.be.revertedWithCustomError(
        darkPool,
        "InvalidProof",
      );
      expect(await darkPool.isNullifierSpent(pi[3])).to.equal(false);
    });

    it("pause() blocks settle; unpause restores it", async function () {
      const { darkPool, controller, pauser, admin } =
        await loadFixture(kageModule);
      await darkPool.connect(pauser).pause();
      const pi = await moduleVector(darkPool, KAGE);
      await expect(controller.settle("0x", pi)).to.be.revertedWithCustomError(
        darkPool,
        "EnforcedPause",
      );
      await darkPool.connect(admin).unpause();
      await expect(controller.settle("0x", pi)).to.not.be.reverted;
    });

    it("rejects re-entry: a deposit's token pull that calls settle through a registered module", async function () {
      const { darkPool, controller } = await loadFixture(kageModule);
      const token = await (
        await ethers.getContractFactory("SettleReentrantToken")
      ).deploy(await controller.getAddress());
      await token.setPublicInputs(await moduleVector(darkPool, KAGE));

      const dep = new Array<string>(13).fill(b32(0n));
      dep[0] = b32(COMPLIANCE_PK[0]);
      dep[1] = b32(COMPLIANCE_PK[1]);
      dep[2] = b32(0xabcn);
      dep[4] = b32(1n);
      dep[5] = ethers.zeroPadValue(await token.getAddress(), 32);
      await expect(darkPool.deposit("0x", dep)).to.be.revertedWithCustomError(
        darkPool,
        "ReentrancyGuardReentrantCall",
      );
    });
  });

  describe("timestamp rule", function () {
    const cases: Array<{
      name: string;
      maxPast: bigint;
      maxFuture: bigint;
      ok: bigint[];
      bad: bigint[];
    }> = [
      {
        name: "floor 0",
        maxPast: 0n,
        maxFuture: NO_BOUND,
        ok: [0n, 1n, 10n ** 9n],
        bad: [-1n, -300n],
      },
      {
        name: "floor 300",
        maxPast: 300n,
        maxFuture: NO_BOUND,
        ok: [-300n, 0n, 10n ** 9n],
        bad: [-301n],
      },
      {
        name: "ceiling 0",
        maxPast: NO_BOUND,
        maxFuture: 0n,
        ok: [0n, -1n, -(10n ** 6n)],
        bad: [1n, 300n],
      },
      {
        name: "ceiling 300",
        maxPast: NO_BOUND,
        maxFuture: 300n,
        ok: [300n, 0n, -(10n ** 6n)],
        bad: [301n],
      },
      {
        name: "both NO_BOUND",
        maxPast: NO_BOUND,
        maxFuture: NO_BOUND,
        ok: [-(10n ** 6n), 0n, 10n ** 9n],
        bad: [],
      },
    ];

    for (const c of cases) {
      it(`${c.name}: accepts ${c.ok.join(", ")} and rejects ${c.bad.join(", ") || "nothing"} seconds from the block time`, async function () {
        const { darkPool, controller } = await registered(
          KAGE,
          c.maxPast,
          c.maxFuture,
        );
        for (const delta of [...c.ok, ...c.bad]) {
          const at = BigInt(await time.latest()) + 10_000n;
          const pi = await moduleVector(darkPool, KAGE, at + delta);
          await time.setNextBlockTimestamp(at);
          const tx = controller.settle("0x", pi, { gasLimit: 3_000_000 });
          if (c.ok.includes(delta)) {
            await expect(tx, `delta ${delta}`).to.not.be.reverted;
          } else {
            await expect(tx, `delta ${delta}`).to.be.revertedWithCustomError(
              darkPool,
              "TimestampInvalid",
            );
          }
        }
      });
    }

    it("a timestamp near 2^256 never overflows the rule: floor-only module reaches the field check, ceiling module rejects", async function () {
      const floorOnly = await registered(KAGE, 300n, NO_BOUND);
      const pi = await moduleVector(floorOnly.darkPool, KAGE, MAX_UINT256);
      await expect(
        floorOnly.controller.settle("0x", pi),
      ).to.be.revertedWithCustomError(floorOnly.darkPool, "NonCanonicalField");

      const ceiling = await registered(KAGE, 300n, 300n);
      const pi2 = await moduleVector(ceiling.darkPool, KAGE, MAX_UINT256);
      await expect(
        ceiling.controller.settle("0x", pi2),
      ).to.be.revertedWithCustomError(ceiling.darkPool, "TimestampInvalid");
    });
  });

  describe("registration and governance", function () {
    let darkPool: DarkPool;
    let controller: SettlementControllerHarness;
    let stubAddr: string;
    let upgrader: Awaited<ReturnType<typeof deployStubbedPool>>["upgrader"];
    let pauser: Awaited<ReturnType<typeof deployStubbedPool>>["pauser"];
    let admin: Awaited<ReturnType<typeof deployStubbedPool>>["admin"];

    beforeEach(async function () {
      const pool = await deployStubbedPool();
      ({ darkPool, upgrader, pauser, admin } = pool);
      stubAddr = await pool.stub.getAddress();
      controller = await deployController(darkPool);
    });

    const register = (
      ctrl: string,
      verifier: string,
      k: number,
      m: number,
      e: number,
    ) =>
      darkPool
        .connect(upgrader)
        .registerSettlementModule(ctrl, verifier, k, m, e, 300n, NO_BOUND);

    it("stores the packed module and emits ModuleRegistered", async function () {
      const ctrl = await controller.getAddress();
      await expect(register(ctrl, stubAddr, 2, 4, 0))
        .to.emit(darkPool, "ModuleRegistered")
        .withArgs(ctrl, stubAddr, 2, 4, 0, 300n, NO_BOUND);
      const m = await darkPool.settlementModule(ctrl);
      expect(m.verifier).to.equal(stubAddr);
      expect(m.nullifierCount).to.equal(2n);
      expect(m.outputCount).to.equal(4n);
      expect(m.extraCount).to.equal(0n);
      expect(m.maxPast).to.equal(300n);
      expect(m.maxFuture).to.equal(NO_BOUND);
      expect(m.active).to.equal(true);
    });

    it("rejects a zero or code-less controller, a second registration, and a zero or code-less verifier", async function () {
      const ctrl = await controller.getAddress();
      await expect(
        register(ethers.ZeroAddress, stubAddr, 2, 4, 0),
      ).to.be.revertedWithCustomError(darkPool, "ZeroAddress");
      await expect(
        register(admin.address, stubAddr, 2, 4, 0),
      ).to.be.revertedWithCustomError(darkPool, "ControllerHasNoCode");
      await expect(
        register(ctrl, ethers.ZeroAddress, 2, 4, 0),
      ).to.be.revertedWithCustomError(darkPool, "ZeroAddress");
      await expect(
        register(ctrl, admin.address, 2, 4, 0),
      ).to.be.revertedWithCustomError(darkPool, "VerifierHasNoCode");
      await register(ctrl, stubAddr, 2, 4, 0);
      await expect(register(ctrl, stubAddr, 1, 1, 0))
        .to.be.revertedWithCustomError(darkPool, "ModuleAlreadyRegistered")
        .withArgs(ctrl);
      await darkPool.connect(pauser).disableModule(ctrl);
      await expect(
        register(ctrl, stubAddr, 2, 4, 0),
      ).to.be.revertedWithCustomError(darkPool, "ModuleAlreadyRegistered");
    });

    for (const [k, m, e] of [
      [0, 4, 0],
      [17, 4, 0],
      [2, 0, 0],
      [2, 17, 0],
      [2, 4, 9],
    ]) {
      it(`rejects layout k=${k} m=${m} e=${e}`, async function () {
        await expect(
          register(await controller.getAddress(), stubAddr, k, m, e),
        ).to.be.revertedWithCustomError(darkPool, "InvalidModuleLayout");
      });
    }

    it("accepts the layout bounds k=1, k=16, m=1, m=16, e=8", async function () {
      for (const [k, m, e] of [
        [1, 1, 0],
        [16, 16, 8],
      ]) {
        const ctrl = await deployController(darkPool);
        await expect(register(await ctrl.getAddress(), stubAddr, k, m, e)).to
          .not.be.reverted;
      }
    });

    it("only UPGRADER registers and re-points; only PAUSER disables; only DEFAULT_ADMIN enables", async function () {
      const ctrl = await controller.getAddress();
      await expect(
        darkPool
          .connect(pauser)
          .registerSettlementModule(ctrl, stubAddr, 2, 4, 0, 0, 0),
      ).to.be.revertedWithCustomError(
        darkPool,
        "AccessControlUnauthorizedAccount",
      );
      await register(ctrl, stubAddr, 2, 4, 0);
      await expect(
        darkPool.connect(admin).setModuleVerifier(ctrl, stubAddr),
      ).to.be.revertedWithCustomError(
        darkPool,
        "AccessControlUnauthorizedAccount",
      );
      await expect(
        darkPool.connect(upgrader).disableModule(ctrl),
      ).to.be.revertedWithCustomError(
        darkPool,
        "AccessControlUnauthorizedAccount",
      );
      await darkPool.connect(pauser).disableModule(ctrl);
      await expect(
        darkPool.connect(pauser).enableModule(ctrl),
      ).to.be.revertedWithCustomError(
        darkPool,
        "AccessControlUnauthorizedAccount",
      );
      await expect(
        darkPool.connect(upgrader).enableModule(ctrl),
      ).to.be.revertedWithCustomError(
        darkPool,
        "AccessControlUnauthorizedAccount",
      );
    });

    it("disableModule halts one module, enableModule restores it, and neither repeats", async function () {
      const ctrl = await controller.getAddress();
      await register(ctrl, stubAddr, 2, 4, 0);
      await expect(darkPool.connect(pauser).disableModule(ctrl))
        .to.emit(darkPool, "ModuleDisabled")
        .withArgs(ctrl, pauser.address);
      expect((await darkPool.settlementModule(ctrl)).active).to.equal(false);
      const pi = await moduleVector(darkPool, KAGE);
      await expect(controller.settle("0x", pi))
        .to.be.revertedWithCustomError(darkPool, "ModuleNotActive")
        .withArgs(ctrl);
      await expect(darkPool.connect(pauser).disableModule(ctrl))
        .to.be.revertedWithCustomError(darkPool, "ModuleAlreadyDisabled")
        .withArgs(ctrl);

      await expect(darkPool.connect(admin).enableModule(ctrl))
        .to.emit(darkPool, "ModuleEnabled")
        .withArgs(ctrl);
      await expect(darkPool.connect(admin).enableModule(ctrl))
        .to.be.revertedWithCustomError(darkPool, "ModuleAlreadyEnabled")
        .withArgs(ctrl);
      await expect(controller.settle("0x", pi)).to.not.be.reverted;
    });

    it("governance calls on an unregistered controller revert UnknownModule", async function () {
      const ctrl = await controller.getAddress();
      await expect(darkPool.connect(upgrader).setModuleVerifier(ctrl, stubAddr))
        .to.be.revertedWithCustomError(darkPool, "UnknownModule")
        .withArgs(ctrl);
      await expect(darkPool.connect(pauser).disableModule(ctrl))
        .to.be.revertedWithCustomError(darkPool, "UnknownModule")
        .withArgs(ctrl);
      await expect(darkPool.connect(admin).enableModule(ctrl))
        .to.be.revertedWithCustomError(darkPool, "UnknownModule")
        .withArgs(ctrl);
    });

    it("setModuleVerifier swaps the verifier the module is checked against", async function () {
      const ctrl = await controller.getAddress();
      const falseVerifier = await (
        await ethers.getContractFactory("FalseVerifier")
      ).deploy();
      const falseAddr = await falseVerifier.getAddress();
      await register(ctrl, falseAddr, 2, 4, 0);
      const pi = await moduleVector(darkPool, KAGE);
      await expect(controller.settle("0x", pi)).to.be.revertedWithCustomError(
        darkPool,
        "InvalidProof",
      );

      await expect(
        darkPool.connect(upgrader).setModuleVerifier(ctrl, ethers.ZeroAddress),
      ).to.be.revertedWithCustomError(darkPool, "ZeroAddress");
      await expect(
        darkPool.connect(upgrader).setModuleVerifier(ctrl, admin.address),
      ).to.be.revertedWithCustomError(darkPool, "VerifierHasNoCode");
      await expect(darkPool.connect(upgrader).setModuleVerifier(ctrl, stubAddr))
        .to.emit(darkPool, "ModuleVerifierUpdated")
        .withArgs(ctrl, stubAddr);
      expect((await darkPool.settlementModule(ctrl)).verifier).to.equal(
        stubAddr,
      );
      await expect(controller.settle("0x", pi)).to.not.be.reverted;
    });
  });
});
