import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture, time } from "@nomicfoundation/hardhat-network-helpers";
import {
  deployDarkPoolFixture,
  COMPLIANCE_PK,
  makeDeposit,
} from "../helpers/fixtures";

// Helpers
const DUMMY_PROOF = new Uint8Array(32); // Empty bytes for proof
const randomBytes32 = () => ethers.hexlify(ethers.randomBytes(32));

describe("Adversarial: Input Validation & Pre-checks", function () {
  async function fixture() {
    const data = await deployDarkPoolFixture();
    await makeDeposit(data.darkPool, data.token, data.alice, 100n);
    return data;
  }

  // =========================================================================
  // 1. ARRAY LENGTH CHECKS (The "Buffer Overflow" Guard)
  // =========================================================================
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

  // =========================================================================
  // 2. COMPLIANCE KEY BINDING (The "Spoofing" Guard)
  // =========================================================================
  // The circuit enforces integrity using Public Inputs. The contract MUST check
  // that those Public Inputs match the immutable keys stored on-chain.
  describe("Compliance Key Binding", function () {
    it("Deposit: should reject invalid Compliance Key X", async function () {
      const { darkPool, alice } = await loadFixture(fixture);
      const inputs = Array(13).fill(randomBytes32());

      // Index 0 is Compliance X
      inputs[0] = ethers.ZeroHash; // Wrong Key

      await expect(
        darkPool.connect(alice).deposit(DUMMY_PROOF, inputs),
      ).to.be.revertedWithCustomError(darkPool, "InvalidComplianceKey");
    });

    it("Withdraw: should reject invalid Compliance Key Y", async function () {
      const { darkPool, alice } = await loadFixture(fixture);
      const inputs = Array(18).fill(randomBytes32());

      const validRoot = await darkPool.getCurrentRoot();

      inputs[2] = validRoot; // Valid Root

      // Validation: Timestamp (Index 3) must be valid too
      inputs[3] = ethers.zeroPadValue(ethers.toBeHex(await time.latest()), 32);

      // Now mess up keys. Withdraw: Compliance at [4, 5]
      inputs[5] = ethers.zeroPadValue(ethers.toBeHex(COMPLIANCE_PK[0]), 32);
      inputs[6] = ethers.ZeroHash; // Invalid Y

      await expect(
        darkPool.connect(alice).withdraw(DUMMY_PROOF, inputs),
      ).to.be.revertedWithCustomError(darkPool, "InvalidComplianceKey");
    });

    it("Transfer: should reject invalid Compliance Key", async function () {
      const { darkPool, alice } = await loadFixture(fixture);
      const inputs = Array(31).fill(randomBytes32());

      // Pass Root check
      inputs[0] = await darkPool.getCurrentRoot();
      // Pass Time check
      inputs[1] = ethers.zeroPadValue(ethers.toBeHex(await time.latest()), 32);

      // Transfer: Compliance at [2, 3]
      inputs[2] = ethers.ZeroHash; // Invalid X

      await expect(
        darkPool.connect(alice).privateTransfer(DUMMY_PROOF, inputs),
      ).to.be.revertedWithCustomError(darkPool, "InvalidComplianceKey");
    });
  });

  // =========================================================================
  // 3. TIMESTAMP BOUNDARIES (The "Future-Proof" Guard)
  // =========================================================================
  describe("Timestamp Boundaries", function () {
    it("should reject proof timestamps too far in the future", async function () {
      const { darkPool, alice } = await loadFixture(fixture);

      // Withdraw Input Layout: [..., root, timestamp, ...]
      const inputs = Array(18).fill(randomBytes32());
      inputs[2] = await darkPool.getCurrentRoot(); // Valid Root

      // Timestamp is at Index 3
      // Current time + 2 hours (Allowed window is +1 hour)
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

  // =========================================================================
  // 4. MERKLE ROOT EXISTENCE (The "History" Guard)
  // =========================================================================
  describe("Merkle Root Verification", function () {
    it("should reject unknown Merkle Roots", async function () {
      const { darkPool, alice } = await loadFixture(fixture);

      const inputs = Array(18).fill(randomBytes32());

      // Random root at Index 2
      inputs[2] = ethers.hexlify(ethers.randomBytes(32));

      await expect(
        darkPool.connect(alice).withdraw(DUMMY_PROOF, inputs),
      ).to.be.revertedWithCustomError(darkPool, "InvalidRoot");
    });
  });
});
