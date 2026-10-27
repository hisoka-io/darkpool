import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture, time } from "@nomicfoundation/hardhat-network-helpers";
import { Fr } from "@hisoka/wallets";
import { newSeededTree } from "../helpers/fixtures";
import { NO_BOUND, b32 } from "../helpers/settlementFixtures";
import {
  KAGE_PROOF,
  KAGE_PUBLIC_INPUTS,
  KAGE_LEAF_A,
  KAGE_LEAF_B,
} from "../integration/kageGolden";
import {
  HOT_KEY,
  SETTLE_WINDOW,
  STRANGER_KEY,
  deployKageFixture,
  messageFor,
  publicInputsHash,
  registerSolver,
  settlementDigestTs,
  settlementTypedData,
  signSettlement,
  type KageDeployment,
} from "./kageFixtures";
import type { Erc1271SolverWallet } from "../../typechain-types";

const PI = KAGE_PUBLIC_INPUTS;
const PROOF_TS = BigInt(PI[2]);
const OUTPUT_LEAF_INDICES = [6, 15, 24, 33];

async function deadlineFromNow(): Promise<bigint> {
  return BigInt(await time.latest()) + SETTLE_WINDOW;
}

async function signedPackage(d: KageDeployment, deadline?: bigint) {
  const dl = deadline ?? (await deadlineFromNow());
  const sig = await signSettlement(HOT_KEY, await messageFor(d, PI, dl));
  return { deadline: dl, sig };
}

describe("KageSettlement", function () {
  describe("settles the real golden swap", function () {
    it("EOA solver: 2 nullifiers, 4 NewNote at the pinned indices, ModuleSettled, KageSwapSettled, no token moved", async function () {
      const d = await loadFixture(deployKageFixture);
      const { darkPool, settlement, token, stakeToken, registry, solverId } = d;
      const poolAddr = await darkPool.getAddress();
      const settlementAddr = await settlement.getAddress();
      const poolTokenBefore = await token.balanceOf(poolAddr);
      const stakeHeldBefore = await stakeToken.balanceOf(
        await registry.getAddress(),
      );
      const { deadline, sig } = await signedPackage(d);

      const receipt = await (
        await settlement.settleSwap(solverId, deadline, sig, KAGE_PROOF, PI)
      ).wait();
      console.log(`      settleSwap gasUsed (EOA solver): ${receipt!.gasUsed}`);

      expect(await darkPool.isNullifierSpent(PI[3])).to.equal(true);
      expect(await darkPool.isNullifierSpent(PI[4])).to.equal(true);
      expect(await darkPool.getNextLeafIndex()).to.equal(7n);

      const poolLogs = receipt!.logs
        .filter((l) => l.address === poolAddr)
        .map((l) => darkPool.interface.parseLog(l));
      const newNotes = poolLogs.filter((p) => p?.name === "NewNote");
      expect(newNotes.length).to.equal(4);
      newNotes.forEach((log, j) => {
        const base = OUTPUT_LEAF_INDICES[j];
        expect(log!.args.leafIndex).to.equal(3n + BigInt(j));
        expect(log!.args.commitment).to.equal(PI[base]);
      });
      const moduleSettled = poolLogs.filter((p) => p?.name === "ModuleSettled");
      expect(moduleSettled.length).to.equal(1);
      expect(moduleSettled[0]!.args.controller).to.equal(settlementAddr);
      expect(moduleSettled[0]!.args.firstLeafIndex).to.equal(3n);
      expect(moduleSettled[0]!.args.outputCount).to.equal(4n);

      const swapLogs = receipt!.logs
        .filter((l) => l.address === settlementAddr)
        .map((l) => settlement.interface.parseLog(l));
      expect(swapLogs.length).to.equal(1);
      expect(swapLogs[0]!.name).to.equal("KageSwapSettled");
      expect(swapLogs[0]!.args.solverId).to.equal(solverId);
      expect(swapLogs[0]!.args.takerNullifier).to.equal(PI[3]);
      expect(swapLogs[0]!.args.makerNullifier).to.equal(PI[4]);
      expect(receipt!.logs[receipt!.logs.length - 1].address).to.equal(
        settlementAddr,
      );

      const tree = await newSeededTree();
      for (const h of [
        KAGE_LEAF_A,
        KAGE_LEAF_B,
        ...OUTPUT_LEAF_INDICES.map((i) => PI[i]),
      ]) {
        await tree.insert(new Fr(BigInt(h)));
      }
      expect(await darkPool.getCurrentRoot()).to.equal(
        tree.getRoot().toString(),
      );

      expect(await token.balanceOf(poolAddr)).to.equal(poolTokenBefore);
      expect(await stakeToken.balanceOf(await registry.getAddress())).to.equal(
        stakeHeldBefore,
      );
      expect(await ethers.provider.getBalance(poolAddr)).to.equal(0n);
      expect(await ethers.provider.getBalance(settlementAddr)).to.equal(0n);
    });

    it("ERC-1271 solver: a contract wallet's approval settles; another key's does not", async function () {
      const d = await loadFixture(deployKageFixture);
      const wallet = (await (
        await ethers.getContractFactory("Erc1271SolverWallet")
      ).deploy(HOT_KEY.address)) as unknown as Erc1271SolverWallet;
      const walletId = await registerSolver(
        d.registry,
        d.stakeToken,
        d.stranger,
        await wallet.getAddress(),
      );
      const deadline = await deadlineFromNow();
      const digest = settlementDigestTs(
        await messageFor(d, PI, deadline, walletId),
      );
      const strangerSig = STRANGER_KEY.signingKey.sign(digest).serialized;
      await expect(
        d.settlement.settleSwap(
          walletId,
          deadline,
          strangerSig,
          KAGE_PROOF,
          PI,
        ),
      )
        .to.be.revertedWithCustomError(d.settlement, "InvalidSolverSignature")
        .withArgs(walletId);

      const ownerSig = HOT_KEY.signingKey.sign(digest).serialized;
      await expect(
        d.settlement.settleSwap(walletId, deadline, ownerSig, KAGE_PROOF, PI),
      )
        .to.emit(d.settlement, "KageSwapSettled")
        .withArgs(walletId, PI[3], PI[4]);
    });

    it("replay of a settled package reverts NullifierAlreadySpent", async function () {
      const d = await loadFixture(deployKageFixture);
      const { deadline, sig } = await signedPackage(d);
      await d.settlement.settleSwap(d.solverId, deadline, sig, KAGE_PROOF, PI);
      await expect(
        d.settlement.settleSwap(d.solverId, deadline, sig, KAGE_PROOF, PI),
      ).to.be.revertedWithCustomError(d.darkPool, "NullifierAlreadySpent");
    });
  });

  describe("registration rule (maxPast = 0)", function () {
    it("is registered (2, 4, 0, 0, NO_BOUND) with the KageVerifier", async function () {
      const d = await loadFixture(deployKageFixture);
      const m = await d.darkPool.settlementModule(
        await d.settlement.getAddress(),
      );
      expect(m.verifier).to.equal(d.kageVerifier);
      expect(m.nullifierCount).to.equal(2n);
      expect(m.outputCount).to.equal(4n);
      expect(m.extraCount).to.equal(0n);
      expect(m.maxPast).to.equal(0n);
      expect(m.maxFuture).to.equal(NO_BOUND);
      expect(m.active).to.equal(true);
    });

    it("a proof timestamp one second behind the block reverts TimestampInvalid", async function () {
      const d = await loadFixture(deployKageFixture);
      const deadline = PROOF_TS + SETTLE_WINDOW;
      const sig = await signSettlement(
        HOT_KEY,
        await messageFor(d, PI, deadline),
      );

      await time.setNextBlockTimestamp(PROOF_TS + 1n);
      await expect(
        d.settlement.settleSwap(d.solverId, deadline, sig, KAGE_PROOF, PI),
      ).to.be.revertedWithCustomError(d.darkPool, "TimestampInvalid");
      expect(await d.darkPool.isNullifierSpent(PI[3])).to.equal(false);
    });

    it("a proof timestamp equal to the block timestamp settles", async function () {
      const d = await loadFixture(deployKageFixture);
      const deadline = PROOF_TS + SETTLE_WINDOW;
      const sig = await signSettlement(
        HOT_KEY,
        await messageFor(d, PI, deadline),
      );
      await time.setNextBlockTimestamp(PROOF_TS);
      await expect(
        d.settlement.settleSwap(d.solverId, deadline, sig, KAGE_PROOF, PI),
      ).to.emit(d.settlement, "KageSwapSettled");
      expect(BigInt(await time.latest())).to.equal(PROOF_TS);
    });

    it("a disabled module reverts ModuleNotActive with the settlement address", async function () {
      const d = await loadFixture(deployKageFixture);
      const settlementAddr = await d.settlement.getAddress();
      await d.darkPool.connect(d.pauser).disableModule(settlementAddr);
      const { deadline, sig } = await signedPackage(d);
      await expect(
        d.settlement.settleSwap(d.solverId, deadline, sig, KAGE_PROOF, PI),
      )
        .to.be.revertedWithCustomError(d.darkPool, "ModuleNotActive")
        .withArgs(settlementAddr);
    });
  });

  describe("deadline", function () {
    it("deadline == block timestamp settles", async function () {
      const d = await loadFixture(deployKageFixture);
      const { deadline, sig } = await signedPackage(d);
      await time.setNextBlockTimestamp(deadline);
      await expect(
        d.settlement.settleSwap(d.solverId, deadline, sig, KAGE_PROOF, PI),
      ).to.emit(d.settlement, "KageSwapSettled");
    });

    it("one second past the deadline reverts SettlementExpired", async function () {
      const d = await loadFixture(deployKageFixture);
      const { deadline, sig } = await signedPackage(d);
      await time.setNextBlockTimestamp(deadline + 1n);
      await expect(
        d.settlement.settleSwap(d.solverId, deadline, sig, KAGE_PROOF, PI),
      )
        .to.be.revertedWithCustomError(d.settlement, "SettlementExpired")
        .withArgs(deadline);
    });
  });

  describe("signature binding", function () {
    async function expectRejected(
      d: KageDeployment,
      sig: string,
      deadline: bigint,
      solverId: bigint = d.solverId,
    ) {
      await expect(
        d.settlement.settleSwap(solverId, deadline, sig, KAGE_PROOF, PI),
      )
        .to.be.revertedWithCustomError(d.settlement, "InvalidSolverSignature")
        .withArgs(solverId);
    }

    it("rejects a signature by a key that is not the registered signer", async function () {
      const d = await loadFixture(deployKageFixture);
      const deadline = await deadlineFromNow();
      await expectRejected(
        d,
        await signSettlement(STRANGER_KEY, await messageFor(d, PI, deadline)),
        deadline,
      );
    });

    it("rejects a signature over a vector with one word changed", async function () {
      const d = await loadFixture(deployKageFixture);
      const deadline = await deadlineFromNow();
      const other = [...PI];
      other[6] = b32(BigInt(PI[6]) + 1n);
      await expectRejected(
        d,
        await signSettlement(HOT_KEY, await messageFor(d, other, deadline)),
        deadline,
      );
    });

    it("rejects a signature for another solver id that shares the key", async function () {
      const d = await loadFixture(deployKageFixture);
      const twinId = await registerSolver(
        d.registry,
        d.stakeToken,
        d.stranger,
        HOT_KEY.address,
      );
      const deadline = await deadlineFromNow();
      const sigForOne = await signSettlement(
        HOT_KEY,
        await messageFor(d, PI, deadline, d.solverId),
      );
      await expectRejected(d, sigForOne, deadline, twinId);
    });

    it("rejects a signature naming another pool", async function () {
      const d = await loadFixture(deployKageFixture);
      const deadline = await deadlineFromNow();
      const m = await messageFor(d, PI, deadline);
      m.pool = await d.registry.getAddress();
      await expectRejected(d, await signSettlement(HOT_KEY, m), deadline);
    });

    it("rejects a signature under another chain id", async function () {
      const d = await loadFixture(deployKageFixture);
      const deadline = await deadlineFromNow();
      const m = await messageFor(d, PI, deadline);
      m.chainId = 1n;
      await expectRejected(d, await signSettlement(HOT_KEY, m), deadline);
    });

    it("rejects a signature for another KageSettlement instance", async function () {
      const d = await loadFixture(deployKageFixture);
      const twin = await (
        await ethers.getContractFactory("KageSettlement")
      ).deploy(await d.darkPool.getAddress(), await d.registry.getAddress());
      const deadline = await deadlineFromNow();
      const m = await messageFor(d, PI, deadline);
      m.verifyingContract = await twin.getAddress();
      await expectRejected(d, await signSettlement(HOT_KEY, m), deadline);
    });

    it("rejects the high-s twin of a valid signature", async function () {
      const d = await loadFixture(deployKageFixture);
      const { deadline, sig } = await signedPackage(d);
      const parsed = ethers.Signature.from(sig);
      const highS = ethers.concat([
        parsed.r,
        ethers.toBeHex(ethers.N - BigInt(parsed.s), 32),
        ethers.toBeHex(parsed.v === 27 ? 28 : 27, 1),
      ]);
      await expectRejected(d, highS, deadline);
      await expect(
        d.settlement.settleSwap(d.solverId, deadline, sig, KAGE_PROOF, PI),
      ).to.emit(d.settlement, "KageSwapSettled");
    });
  });

  describe("Solidity/TypeScript EIP-712 parity", function () {
    it("settlementDigest equals ethers' TypedDataEncoder digest for the golden vector", async function () {
      const d = await loadFixture(deployKageFixture);
      const deadline = 1_900_000_000n;
      const m = await messageFor(d, PI, deadline);
      expect(
        await d.settlement.settlementDigest(d.solverId, deadline, PI),
      ).to.equal(settlementDigestTs(m));

      const t = settlementTypedData(m);
      expect(
        ethers.TypedDataEncoder.from(t.types).encodeType("KageSettlement"),
      ).to.equal(
        "KageSettlement(address pool,uint256 solverId,bytes32 publicInputsHash,uint256 deadline)",
      );
      expect(await d.settlement.SETTLEMENT_TYPEHASH()).to.equal(
        "0x7ffa2d5aad35edb790ebb58164e6295a1d3de164ece1e8683f412d87f1157fda",
      );
      // The packed hash is EIP-712's own encoding of a bytes32[] member.
      expect(
        ethers.TypedDataEncoder.from({
          V: [{ name: "w", type: "bytes32[]" }],
        }).encodeData("bytes32[]", PI),
      ).to.equal(publicInputsHash(PI));
    });
  });

  describe("constructor", function () {
    it("rejects zero and code-less pool or registry addresses", async function () {
      const d = await loadFixture(deployKageFixture);
      const F = await ethers.getContractFactory("KageSettlement");
      const pool = await d.darkPool.getAddress();
      const registry = await d.registry.getAddress();
      const eoa = d.stranger.address;
      await expect(
        F.deploy(ethers.ZeroAddress, registry),
      ).to.be.revertedWithCustomError(F, "ZeroAddress");
      await expect(
        F.deploy(pool, ethers.ZeroAddress),
      ).to.be.revertedWithCustomError(F, "ZeroAddress");
      await expect(F.deploy(eoa, registry)).to.be.revertedWithCustomError(
        F,
        "PoolHasNoCode",
      );
      await expect(F.deploy(pool, eoa)).to.be.revertedWithCustomError(
        F,
        "RegistryHasNoCode",
      );
    });
  });
});
