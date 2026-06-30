import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture, time } from "@nomicfoundation/hardhat-network-helpers";
import {
  deployDarkPoolFixture,
  COMPLIANCE_PK,
  makeDeposit,
} from "../helpers/fixtures";

const DUMMY_PROOF = new Uint8Array(32);
const randomBytes32 = () => ethers.hexlify(ethers.randomBytes(32));

describe("Adversarial: Input Validation & Pre-checks", function () {
  async function fixture() {
    const data = await deployDarkPoolFixture();
    await makeDeposit(data.darkPool, data.token, data.alice, 100n);
    return data;
  }

  // Array length checks: the "buffer overflow" guard
  describe("Input Array Lengths", function () {
    it("should reject Deposit with invalid input length", async function () {
      const { darkPool, alice } = await loadFixture(fixture);

      // Expected: 13 inputs
      const tooShort = Array(12).fill(randomBytes32());
      const tooLong = Array(14).fill(randomBytes32());

      await expect(
        darkPool.connect(alice).deposit(DUMMY_PROOF, tooShort),
      ).to.be.revertedWithCustomError(darkPool, "InvalidInputsLength");

      await expect(
        darkPool.connect(alice).deposit(DUMMY_PROOF, tooLong),
      ).to.be.revertedWithCustomError(darkPool, "InvalidInputsLength");
    });

    it("should reject Withdraw with invalid input length", async function () {
      const { darkPool, alice } = await loadFixture(fixture);

      // Expected: 17 inputs
      const tooShort = Array(16).fill(randomBytes32());

      await expect(
        darkPool.connect(alice).withdraw(DUMMY_PROOF, tooShort),
      ).to.be.revertedWithCustomError(darkPool, "InvalidInputsLength");
    });

    it("should reject Private Transfer with invalid input length", async function () {
      const { darkPool, alice } = await loadFixture(fixture);

      // Expected: 31 inputs
      const tooShort = Array(30).fill(randomBytes32());

      await expect(
        darkPool.connect(alice).privateTransfer(DUMMY_PROOF, tooShort),
      ).to.be.revertedWithCustomError(darkPool, "InvalidInputsLength");
    });

    it("should reject Join with invalid input length", async function () {
      const { darkPool, alice } = await loadFixture(fixture);
      // Expected: 16
      await expect(
        darkPool.connect(alice).join(DUMMY_PROOF, []),
      ).to.be.revertedWithCustomError(darkPool, "InvalidInputsLength");
    });

    it("should reject Split with invalid input length", async function () {
      const { darkPool, alice } = await loadFixture(fixture);
      // Expected: 24
      await expect(
        darkPool.connect(alice).split(DUMMY_PROOF, []),
      ).to.be.revertedWithCustomError(darkPool, "InvalidInputsLength");
    });
  });

  // Compliance key binding: the "spoofing" guard.
  // The contract MUST check that the proof's compliance public inputs match the
  // immutable keys stored on-chain — the circuit alone cannot enforce this.
  describe("Compliance Key Binding", function () {
    it("Deposit: should reject invalid Compliance Key X", async function () {
      const { darkPool, alice } = await loadFixture(fixture);
      const inputs = Array(13).fill(randomBytes32());

      inputs[0] = ethers.ZeroHash; // index 0 = compliance X (wrong key)

      await expect(
        darkPool.connect(alice).deposit(DUMMY_PROOF, inputs),
      ).to.be.revertedWithCustomError(darkPool, "InvalidComplianceKey");
    });

    it("Withdraw: should reject invalid Compliance Key Y", async function () {
      const { darkPool, alice } = await loadFixture(fixture);
      const inputs = Array(18).fill(randomBytes32());

      const validRoot = await darkPool.getCurrentRoot();

      inputs[2] = validRoot; // root
      inputs[3] = ethers.zeroPadValue(ethers.toBeHex(await time.latest()), 32); // timestamp

      // Withdraw compliance key at [5,6]: valid X, invalid Y
      inputs[5] = ethers.zeroPadValue(ethers.toBeHex(COMPLIANCE_PK[0]), 32);
      inputs[6] = ethers.ZeroHash;

      await expect(
        darkPool.connect(alice).withdraw(DUMMY_PROOF, inputs),
      ).to.be.revertedWithCustomError(darkPool, "InvalidComplianceKey");
    });

    it("Transfer: should reject invalid Compliance Key", async function () {
      const { darkPool, alice } = await loadFixture(fixture);
      const inputs = Array(27).fill(randomBytes32());

      inputs[0] = await darkPool.getCurrentRoot(); // pass root check
      inputs[1] = ethers.zeroPadValue(ethers.toBeHex(await time.latest()), 32); // pass time check

      // Transfer compliance key at [2,3]
      inputs[2] = ethers.ZeroHash; // invalid X

      await expect(
        darkPool.connect(alice).privateTransfer(DUMMY_PROOF, inputs),
      ).to.be.revertedWithCustomError(darkPool, "InvalidComplianceKey");
    });
  });

  // Timestamp boundaries: the "future-proof" guard
  describe("Timestamp Boundaries", function () {
    it("should reject proof timestamps too far in the future", async function () {
      const { darkPool, alice } = await loadFixture(fixture);

      const inputs = Array(18).fill(randomBytes32());
      inputs[2] = await darkPool.getCurrentRoot(); // root

      // Timestamp (index 3) at now + 2h; allowed window is +1h
      const futureTime = (await time.latest()) + 7200;
      inputs[3] = ethers.zeroPadValue(ethers.toBeHex(futureTime), 32);

      await expect(
        darkPool.connect(alice).withdraw(DUMMY_PROOF, inputs),
      ).to.be.revertedWithCustomError(darkPool, "TimestampInvalid");
    });

    it("should accept current timestamp", async function () {
      // We can't verify success without a valid proof, but we can verify
      // it PASSES the timestamp check and fails at the next check (Compliance Keys or Verifier).
      const { darkPool, alice } = await loadFixture(fixture);

      const inputs = Array(18).fill(randomBytes32());
      inputs[2] = await darkPool.getCurrentRoot();
      inputs[3] = ethers.zeroPadValue(ethers.toBeHex(await time.latest()), 32);

      // Compliance Key check is next. If it reverts with "Invalid Compliance PK",
      // we know it PASSED the timestamp check.
      await expect(
        darkPool.connect(alice).withdraw(DUMMY_PROOF, inputs),
      ).to.be.revertedWithCustomError(darkPool, "InvalidComplianceKey");
    });
  });

  // Merkle root existence: the "history" guard
  describe("Merkle Root Verification", function () {
    it("should reject unknown Merkle Roots", async function () {
      const { darkPool, alice } = await loadFixture(fixture);

      const inputs = Array(18).fill(randomBytes32());

      inputs[2] = ethers.hexlify(ethers.randomBytes(32)); // unknown root at index 2

      await expect(
        darkPool.connect(alice).withdraw(DUMMY_PROOF, inputs),
      ).to.be.revertedWithCustomError(darkPool, "InvalidRoot");
    });
  });
});
