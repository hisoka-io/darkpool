import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { readFileSync } from "fs";
import { resolve } from "path";
import { deployDarkPoolFixture } from "../helpers/fixtures";
import { BN254_FR } from "../helpers/merkleTree";

const VERIFIERS_DIR = resolve(process.cwd(), "contracts/verifiers");

// The public-input layout is bound into each verifier's VK and a replacement MUST accept all pre-existing notes, so it is frozen; the multisig twins share it.
const PUBLIC_INPUTS: Record<string, number> = {
  DepositVerifier: 21,
  WithdrawVerifier: 25,
  TransferVerifier: 32,
  JoinVerifier: 22,
  SplitVerifier: 30,
  PublicClaimVerifier: 21,
  WithdrawMultisigVerifier: 25,
  TransferMultisigVerifier: 32,
  SplitMultisigVerifier: 30,
  JoinMultisigVerifier: 22,
};
const TWINS: [string, string][] = [
  ["WithdrawVerifier", "WithdrawMultisigVerifier"],
  ["TransferVerifier", "TransferMultisigVerifier"],
  ["SplitVerifier", "SplitMultisigVerifier"],
  ["JoinVerifier", "JoinMultisigVerifier"],
];
// bb 5.0 --optimized verifiers name the total NUMBER_PUBLIC_INPUTS (4.x was NUMBER_OF_PUBLIC_INPUTS); the contract passes N - 8 pairing-point limbs.
// A circuit past its 2^k ceiling silently regenerates at the next LOG_N, so the pair is pinned in both directions.
const CIRCUIT_DIMS: Record<string, { size: number; logN: number }> = {
  DepositVerifier: { size: 16384, logN: 14 },
  PublicClaimVerifier: { size: 16384, logN: 14 },
  WithdrawVerifier: { size: 32768, logN: 15 },
  WithdrawMultisigVerifier: { size: 32768, logN: 15 },
  TransferVerifier: { size: 32768, logN: 15 },
  JoinVerifier: { size: 32768, logN: 15 },
  SplitVerifier: { size: 32768, logN: 15 },
  SplitMultisigVerifier: { size: 32768, logN: 15 },
  TransferMultisigVerifier: { size: 32768, logN: 15 },
  JoinMultisigVerifier: { size: 32768, logN: 15 },
  KageVerifier: { size: 1048576, logN: 20 },
};
const SIZE_RE = /constant CIRCUIT_SIZE = (\d+)/;
const LOGN_RE = /constant LOG_N = (\d+)/;

const N_RE = /constant NUMBER_PUBLIC_INPUTS = (\d+)/;
const readN = (n: string): number =>
  Number(
    readFileSync(resolve(VERIFIERS_DIR, `${n}.sol`), "utf8").match(N_RE)![1],
  );

describe("Freeze seams", function () {
  describe("public-input layout manifest", function () {
    for (const [name, expected] of Object.entries(PUBLIC_INPUTS)) {
      it(`${name}: NUMBER_PUBLIC_INPUTS == ${expected} (contract passes ${expected - 8})`, function () {
        const m = readFileSync(
          resolve(VERIFIERS_DIR, `${name}.sol`),
          "utf8",
        ).match(N_RE);
        expect(m, `NUMBER_PUBLIC_INPUTS not found in ${name}`).to.not.equal(
          null,
        );
        expect(Number(m![1])).to.equal(expected);
      });
    }
    it("standard and FROST-multisig twins share one layout", function () {
      for (const [std, ms] of TWINS)
        expect(readN(std), `${std} vs ${ms}`).to.equal(readN(ms));
    });
  });

  describe("circuit-size boundary tripwire", function () {
    for (const [name, dims] of Object.entries(CIRCUIT_DIMS)) {
      it(`${name}: CIRCUIT_SIZE == ${dims.size}, LOG_N == ${dims.logN}`, function () {
        const src = readFileSync(resolve(VERIFIERS_DIR, `${name}.sol`), "utf8");
        const size = src.match(SIZE_RE);
        const logN = src.match(LOGN_RE);
        expect(size, `CIRCUIT_SIZE not found in ${name}`).to.not.equal(null);
        expect(logN, `LOG_N not found in ${name}`).to.not.equal(null);
        expect(
          Number(size![1]),
          `${name} crossed a 2^k boundary: the circuit no longer fits its pinned size. ` +
            "Re-measure gates, confirm the change is intended, then re-baseline this table.",
        ).to.equal(dims.size);
        expect(Number(logN![1]), `${name} LOG_N moved`).to.equal(dims.logN);
      });
    }
    it("every CIRCUIT_SIZE is a power of two equal to 2^LOG_N", function () {
      for (const [name, dims] of Object.entries(CIRCUIT_DIMS)) {
        expect(2 ** dims.logN, `${name} size/LOG_N disagree`).to.equal(
          dims.size,
        );
      }
    });
  });

  describe("genesis leaf (chain-binding sentinel)", function () {
    it("domain tag = keccak256('hisoka.darkpool.genesis') % BN254_FR (pinned)", function () {
      const tag =
        BigInt(
          ethers.keccak256(ethers.toUtf8Bytes("hisoka.darkpool.genesis")),
        ) % BN254_FR;
      expect("0x" + tag.toString(16).padStart(64, "0")).to.equal(
        "0x0e900019988da19e3820a67141ab82ff80f44f2f34833360ca783945568cc35b",
      );
    });
    it("genesis root at index 0 is the pinned chain-bound sentinel (chainId 31337)", async function () {
      const { darkPool } = await loadFixture(deployDarkPoolFixture);
      expect((await ethers.provider.getNetwork()).chainId).to.equal(31337n);
      expect(await darkPool.getCurrentRoot()).to.equal(
        "0x12f144d31019d46ff993f3fe3b8a001a0d606ea4b1140525ed615a4402066372",
      );
    });
  });
});
