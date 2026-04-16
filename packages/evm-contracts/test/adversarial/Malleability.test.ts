import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { deployDarkPoolFixture, COMPLIANCE_PK } from "../helpers/fixtures";
import { toFr, addressToFr, Kdf, NotePlaintext } from "@hisoka/wallets";
import { proveDeposit, DepositInputs } from "@hisoka/prover";

describe("Adversarial: Malleability & Integrity", function () {
  // Shared setup for generating a valid proof once
  async function fixture() {
    const data = await deployDarkPoolFixture();
    const { token } = data;

    // Generate a Valid Deposit Proof (Off-chain only)
    const amount = 100n;
    const assetFr = addressToFr(await token.getAddress());
    const note: NotePlaintext = {
      value: toFr(amount),
      asset_id: assetFr,
      secret: toFr(123n),
      nullifier: toFr(456n),
      timelock: toFr(0n),
      hashlock: toFr(0n),
    };
    const ephSk = await Kdf.derive("hisoka.ephemeral", toFr(999n), toFr(1n));

    const inputs: DepositInputs = {
      notePlaintext: note,
      ephemeralSk: ephSk,
      compliancePk: COMPLIANCE_PK,
    };

    const proofData = await proveDeposit(inputs);

    return { ...data, proofData, amount };
  }

  describe("Proof Integrity", function () {
    it("should reject a proof with a single flipped bit", async function () {
      const { darkPool, alice, proofData } = await loadFixture(fixture);

      // Clone the proof
      const tamperedProof = new Uint8Array(proofData.proof);

      // Flip a bit in the middle
      const mid = Math.floor(tamperedProof.length / 2);
      tamperedProof[mid] ^= 0xff; // Invert byte

      // Convert to hex for Solidity
      const proofHex = "0x" + Buffer.from(tamperedProof).toString("hex");

      await expect(
        darkPool.connect(alice).deposit(proofHex, proofData.publicInputs),
      ).to.be.reverted;
    });

    it("should reject a truncated proof", async function () {
      const { darkPool, alice, proofData } = await loadFixture(fixture);

      // Slice off the last 32 bytes
      const truncated = proofData.proof.slice(0, proofData.proof.length - 32);
      const proofHex = "0x" + Buffer.from(truncated).toString("hex");

      // The Verifier might revert with a custom error or Panic depending on implementation
      // We just ensure it doesn't succeed.
      await expect(
        darkPool.connect(alice).deposit(proofHex, proofData.publicInputs),
      ).to.be.reverted;
    });
  });

  describe("Input Integrity (Binding)", function () {
    it("should reject if Public Input 'Value' is modified", async function () {
      const { darkPool, alice, proofData } = await loadFixture(fixture);

      // Deposit Input Layout: [0,1]Comp, [2,3]Epk, [4]Value, [5]Asset...
      const tamperedInputs = [...proofData.publicInputs];

      // Change Value from 100 -> 200
      // Note: The proof asserts the encrypted note contains 100.
      // If we tell the verifier "Value is 200", the proof must fail.
      const newValue = 200n;
      tamperedInputs[4] = ethers.zeroPadValue(ethers.toBeHex(newValue), 32);

      await expect(
        darkPool.connect(alice).deposit(proofData.proof, tamperedInputs),
      ).to.be.reverted;
    });

    it("should reject if Public Input 'Asset ID' is modified", async function () {
      const { darkPool, alice, proofData } = await loadFixture(fixture);

      const tamperedInputs = [...proofData.publicInputs];

      // Change Asset ID to random address
      const fakeAsset = addressToFr(
        "0x000000000000000000000000000000000000dead",
      );
      tamperedInputs[5] = fakeAsset.toString();

      await expect(
        darkPool.connect(alice).deposit(proofData.proof, tamperedInputs),
      ).to.be.reverted;
    });

    it("should reject if Public Input 'Ciphertext' is modified", async function () {
      const { darkPool, alice, proofData } = await loadFixture(fixture);

      const tamperedInputs = [...proofData.publicInputs];

      // Ciphertext is at [6..12]
      // Modify one field of the packed ciphertext
      tamperedInputs[6] = ethers.zeroPadValue("0xdeadbeef", 32);

      await expect(
        darkPool.connect(alice).deposit(proofData.proof, tamperedInputs),
      ).to.be.reverted;
    });
  });
});
