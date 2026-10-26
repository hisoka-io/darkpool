import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import type { EventLog } from "ethers";
import { COMPLIANCE_PK } from "../helpers/fixtures";
import {
  BN254_FR,
  NO_BOUND,
  b32,
  deployController,
  deployStubbedPool,
} from "../helpers/settlementFixtures";
import type { DarkPool, ReducingStubVerifier } from "../../typechain-types";

// The generated verifiers reject a public input >= the BN254 scalar field order, but a replacement verifier may
// reduce instead. DarkPool must then refuse the word itself, before verify, on every entrypoint.

const CIRCUIT_WITHDRAW = 1;
const BASE8_X =
  5299619240641551281634865583518297030282874472190772894086521144482721001553n;
const BASE8_Y =
  16950150798460657717958625567821834550301663161624707787222815936182638968203n;

type Entrypoint =
  | "deposit"
  | "withdraw"
  | "withdrawMultisig"
  | "privateTransfer"
  | "transferMultisig"
  | "join"
  | "joinMultisig"
  | "split"
  | "splitMultisig"
  | "publicClaim";

interface Shape {
  length: number;
  compliance: [number, number];
  root?: number;
  /** Words checked against state before verify, so a non-canonical value fails there first. */
  preChecked: number[];
}

const SHAPES: Record<Entrypoint, Shape> = {
  deposit: { length: 13, compliance: [0, 1], preChecked: [] },
  withdraw: { length: 17, compliance: [3, 4], root: 6, preChecked: [] },
  withdrawMultisig: { length: 17, compliance: [3, 4], root: 6, preChecked: [] },
  privateTransfer: { length: 24, compliance: [0, 1], root: 3, preChecked: [] },
  transferMultisig: { length: 24, compliance: [0, 1], root: 3, preChecked: [] },
  join: { length: 14, compliance: [0, 1], root: 4, preChecked: [] },
  joinMultisig: { length: 14, compliance: [0, 1], root: 4, preChecked: [] },
  split: { length: 22, compliance: [0, 1], root: 3, preChecked: [] },
  splitMultisig: { length: 22, compliance: [0, 1], root: 3, preChecked: [] },
  // [0] memoId must be a posted memo; [3] timestamp is ceilinged before verify.
  publicClaim: { length: 13, compliance: [1, 2], preChecked: [0, 3] },
};

async function fixture() {
  const pool = await deployStubbedPool();
  const { darkPool, token } = pool;
  const tx = await darkPool.publicTransfer(
    BASE8_X,
    BASE8_Y,
    await token.getAddress(),
    5n,
    0n,
    77n,
  );
  const rc = await tx.wait();
  const memoLog = rc!.logs.find(
    (l) => (l as EventLog).fragment?.name === "NewPublicMemo",
  ) as EventLog;
  return { ...pool, memoId: memoLog.args.memoId as string };
}

async function validVector(
  darkPool: DarkPool,
  entry: Entrypoint,
  tokenAddr: string,
  memoId: string,
): Promise<string[]> {
  const s = SHAPES[entry];
  const pi = Array.from({ length: s.length }, (_, i) =>
    b32(0x5000n + BigInt(i)),
  );
  pi[s.compliance[0]] = b32(COMPLIANCE_PK[0]);
  pi[s.compliance[1]] = b32(COMPLIANCE_PK[1]);
  if (s.root !== undefined) pi[s.root] = await darkPool.getCurrentRoot();
  if (entry === "deposit") {
    pi[4] = b32(1n);
    pi[5] = ethers.zeroPadValue(tokenAddr, 32);
  }
  if (entry.startsWith("withdraw")) {
    pi[0] = b32(0n);
    pi[1] = ethers.zeroPadValue((await ethers.getSigners())[5].address, 32);
    pi[7] = ethers.zeroPadValue(tokenAddr, 32);
  }
  if (entry === "publicClaim") {
    pi[0] = memoId;
    pi[3] = b32(0n);
  }
  return pi;
}

function wordsUnderTest(entry: Entrypoint): number[] {
  const s = SHAPES[entry];
  const skip = new Set<number>([...s.compliance, ...s.preChecked]);
  if (s.root !== undefined) skip.add(s.root);
  return Array.from({ length: s.length }, (_, i) => i).filter(
    (i) => !skip.has(i),
  );
}

describe("canonical-field guard on every public-input word", function () {
  for (const entry of Object.keys(SHAPES) as Entrypoint[]) {
    it(`${entry}: each word lifted by p reverts NonCanonicalField under an accept-all verifier`, async function () {
      const { darkPool, token, memoId } = await loadFixture(fixture);
      const tokenAddr = await token.getAddress();
      const base = await validVector(darkPool, entry, tokenAddr, memoId);
      for (const i of wordsUnderTest(entry)) {
        const pi = [...base];
        pi[i] = b32(BigInt(base[i]) + BN254_FR);
        await expect(
          darkPool[entry]("0x", pi),
          `${entry} word ${i}`,
        ).to.be.revertedWithCustomError(darkPool, "NonCanonicalField");
      }
      const atP = [...base];
      atP[wordsUnderTest(entry)[0]] = b32(BN254_FR);
      await expect(darkPool[entry]("0x", atP)).to.be.revertedWithCustomError(
        darkPool,
        "NonCanonicalField",
      );
      await expect(darkPool[entry]("0x", base), `${entry} canonical`).to.not.be
        .reverted;
    });
  }

  it("settle: each module word lifted by p reverts NonCanonicalField under an accept-all verifier", async function () {
    const { darkPool, stub, upgrader } = await loadFixture(fixture);
    const controller = await deployController(darkPool);
    await darkPool
      .connect(upgrader)
      .registerSettlementModule(
        await controller.getAddress(),
        await stub.getAddress(),
        2,
        4,
        1,
        NO_BOUND,
        NO_BOUND,
      );
    const base = Array.from({ length: 43 }, (_, i) => b32(0x7000n + BigInt(i)));
    base[0] = b32(COMPLIANCE_PK[0]);
    base[1] = b32(COMPLIANCE_PK[1]);
    base[5] = await darkPool.getCurrentRoot();
    for (let i = 2; i < 43; i++) {
      if (i === 5) continue;
      const pi = [...base];
      pi[i] = b32(BigInt(base[i]) + BN254_FR);
      await expect(
        controller.settle("0x", pi),
        `settle word ${i}`,
      ).to.be.revertedWithCustomError(darkPool, "NonCanonicalField");
    }
    await expect(controller.settle("0x", base)).to.not.be.reverted;
  });

  describe("under a verifier that reduces its inputs mod p", function () {
    async function reducingFixture() {
      const pool = await fixture();
      const reducing = (await (
        await ethers.getContractFactory("ReducingStubVerifier")
      ).deploy()) as unknown as ReducingStubVerifier;
      await pool.darkPool
        .connect(pool.upgrader)
        .setVerifier(CIRCUIT_WITHDRAW, await reducing.getAddress());
      const controller = await deployController(pool.darkPool);
      await pool.darkPool
        .connect(pool.upgrader)
        .registerSettlementModule(
          await controller.getAddress(),
          await reducing.getAddress(),
          2,
          4,
          0,
          NO_BOUND,
          NO_BOUND,
        );
      return { ...pool, reducing, controller };
    }

    it("a withdraw nullifier cannot be spent again as nf + p", async function () {
      const { darkPool, reducing, token, memoId } =
        await loadFixture(reducingFixture);
      const pi = await validVector(
        darkPool,
        "withdraw",
        await token.getAddress(),
        memoId,
      );
      await reducing.accept(pi);
      await darkPool.withdraw("0x", pi);
      expect(await darkPool.isNullifierSpent(pi[5])).to.equal(true);

      const alias = [...pi];
      alias[5] = b32(BigInt(pi[5]) + BN254_FR);
      expect(await reducing.verify("0x", alias)).to.equal(true);
      await expect(
        darkPool.withdraw("0x", alias),
      ).to.be.revertedWithCustomError(darkPool, "NonCanonicalField");
      expect(await darkPool.isNullifierSpent(alias[5])).to.equal(false);
    });

    it("a withdraw cannot be redirected to recipient + p", async function () {
      const { darkPool, reducing, token, memoId } =
        await loadFixture(reducingFixture);
      const pi = await validVector(
        darkPool,
        "withdraw",
        await token.getAddress(),
        memoId,
      );
      await reducing.accept(pi);
      const redirected = [...pi];
      redirected[1] = b32(BigInt(pi[1]) + BN254_FR);
      expect(await reducing.verify("0x", redirected)).to.equal(true);
      await expect(
        darkPool.withdraw("0x", redirected),
      ).to.be.revertedWithCustomError(darkPool, "NonCanonicalField");
    });

    it("a settled module nullifier cannot be spent again as nf + p", async function () {
      const { darkPool, reducing, controller } =
        await loadFixture(reducingFixture);
      const pi = Array.from({ length: 42 }, (_, i) => b32(0x9000n + BigInt(i)));
      pi[0] = b32(COMPLIANCE_PK[0]);
      pi[1] = b32(COMPLIANCE_PK[1]);
      pi[5] = await darkPool.getCurrentRoot();
      await reducing.accept(pi);
      await controller.settle("0x", pi);

      const alias = [...pi];
      alias[3] = b32(BigInt(pi[3]) + BN254_FR);
      alias[4] = b32(BigInt(pi[4]) + BN254_FR);
      expect(await reducing.verify("0x", alias)).to.equal(true);
      await expect(
        controller.settle("0x", alias),
      ).to.be.revertedWithCustomError(darkPool, "NonCanonicalField");
    });
  });
});
