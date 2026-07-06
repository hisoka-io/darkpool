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

  describe("Input Array Lengths", function () {
    it("should reject Deposit with invalid input length", async function () {
      const { darkPool, alice } = await loadFixture(fixture);

      // Expected: 14 inputs
      const tooShort = Array(13).fill(randomBytes32());
      const tooLong = Array(15).fill(randomBytes32());

      await expect(
        darkPool.connect(alice).deposit(DUMMY_PROOF, tooShort),
      ).to.be.revertedWithCustomError(darkPool, "InvalidInputsLength");

      await expect(
        darkPool.connect(alice).deposit(DUMMY_PROOF, tooLong),
      ).to.be.revertedWithCustomError(darkPool, "InvalidInputsLength");
    });

    it("should reject Withdraw with invalid input length", async function () {
      const { darkPool, alice } = await loadFixture(fixture);

      // Expected: 19 inputs
      const tooShort = Array(18).fill(randomBytes32());

      await expect(
        darkPool.connect(alice).withdraw(DUMMY_PROOF, tooShort),
      ).to.be.revertedWithCustomError(darkPool, "InvalidInputsLength");
    });

    it("should reject Private Transfer with invalid input length", async function () {
      const { darkPool, alice } = await loadFixture(fixture);

      // Expected: 27 inputs
      const tooShort = Array(26).fill(randomBytes32());

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
      // Expected: 25
      await expect(
        darkPool.connect(alice).split(DUMMY_PROOF, []),
      ).to.be.revertedWithCustomError(darkPool, "InvalidInputsLength");
    });
  });

  describe("Compliance Key Binding", function () {
    it("Deposit: should reject invalid Compliance Key X", async function () {
      const { darkPool, alice } = await loadFixture(fixture);
      const inputs = Array(14).fill(randomBytes32());

      inputs[0] = ethers.ZeroHash; // index 0 = compliance X

      await expect(
        darkPool.connect(alice).deposit(DUMMY_PROOF, inputs),
      ).to.be.revertedWithCustomError(darkPool, "ComplianceKeyStale");
    });

    it("Withdraw: should reject invalid Compliance Key Y", async function () {
      const { darkPool, alice } = await loadFixture(fixture);
      const inputs = Array(19).fill(randomBytes32());

      const validRoot = await darkPool.getCurrentRoot();

      inputs[7] = validRoot; // root
      inputs[2] = ethers.zeroPadValue(ethers.toBeHex(await time.latest()), 32); // timestamp

      // Withdraw compliance key at [4,5]: valid X, invalid Y
      inputs[4] = ethers.zeroPadValue(ethers.toBeHex(COMPLIANCE_PK[0]), 32);
      inputs[5] = ethers.ZeroHash;

      await expect(
        darkPool.connect(alice).withdraw(DUMMY_PROOF, inputs),
      ).to.be.revertedWithCustomError(darkPool, "ComplianceKeyStale");
    });

    it("Transfer: should reject invalid Compliance Key", async function () {
      const { darkPool, alice } = await loadFixture(fixture);
      const inputs = Array(27).fill(randomBytes32());

      inputs[4] = await darkPool.getCurrentRoot(); // pass root check
      inputs[0] = ethers.zeroPadValue(ethers.toBeHex(await time.latest()), 32); // pass time check

      // Transfer compliance key at [1,2]
      inputs[1] = ethers.ZeroHash; // invalid X

      await expect(
        darkPool.connect(alice).privateTransfer(DUMMY_PROOF, inputs),
      ).to.be.revertedWithCustomError(darkPool, "ComplianceKeyStale");
    });
  });

  describe("Timestamp Boundaries", function () {
    it("should reject proof timestamps too far in the future", async function () {
      const { darkPool, alice } = await loadFixture(fixture);

      const inputs = Array(19).fill(randomBytes32());
      inputs[7] = await darkPool.getCurrentRoot(); // root

      // Timestamp (index 2) at now + 2h; allowed window is +1h
      const futureTime = (await time.latest()) + 7200;
      inputs[2] = ethers.zeroPadValue(ethers.toBeHex(futureTime), 32);

      await expect(
        darkPool.connect(alice).withdraw(DUMMY_PROOF, inputs),
      ).to.be.revertedWithCustomError(darkPool, "TimestampInvalid");
    });

    it("should accept current timestamp", async function () {
      const { darkPool, alice } = await loadFixture(fixture);

      const inputs = Array(19).fill(randomBytes32());
      inputs[7] = await darkPool.getCurrentRoot();
      inputs[2] = ethers.zeroPadValue(ethers.toBeHex(await time.latest()), 32);

      // Passing the timestamp check, the next gate is the compliance-key check.
      await expect(
        darkPool.connect(alice).withdraw(DUMMY_PROOF, inputs),
      ).to.be.revertedWithCustomError(darkPool, "ComplianceKeyStale");
    });
  });

  describe("Merkle Root Verification", function () {
    it("should reject unknown Merkle Roots", async function () {
      const { darkPool, alice } = await loadFixture(fixture);

      const inputs = Array(19).fill(randomBytes32());
      inputs[7] = ethers.hexlify(ethers.randomBytes(32)); // unknown root at index 7

      await expect(
        darkPool.connect(alice).withdraw(DUMMY_PROOF, inputs),
      ).to.be.revertedWithCustomError(darkPool, "InvalidRoot");
    });
  });
});
