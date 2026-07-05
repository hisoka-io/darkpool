import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import {
  deployDarkPoolFixture,
  mintSelfNote,
  evenYEphemeral,
  COMPLIANCE_PK,
} from "../helpers/fixtures";
import { toFr, addressToFr } from "@hisoka/wallets";
import { proveDeposit, DepositInputs } from "@hisoka/prover";

describe("Adversarial: Malleability & Integrity", function () {
  async function fixture() {
    const data = await deployDarkPoolFixture();
    const { token } = data;

    const amount = 100n;
    const built = await mintSelfNote(
      evenYEphemeral(999n),
      amount,
      toFr(456n),
      addressToFr(await token.getAddress()),
    );

    const inputs: DepositInputs = {
      compliancePk: COMPLIANCE_PK,
      note: built.note,
      eph: built.eph,
    };

    const proofData = await proveDeposit(inputs);
    return { ...data, proofData, amount };
  }

  describe("Proof Integrity", function () {
    it("should reject a proof with a single flipped bit", async function () {
      const { darkPool, alice, proofData } = await loadFixture(fixture);

      const tamperedProof = new Uint8Array(proofData.proof);
      const mid = Math.floor(tamperedProof.length / 2);
      tamperedProof[mid] ^= 0xff;

      const proofHex = "0x" + Buffer.from(tamperedProof).toString("hex");

      await expect(
        darkPool.connect(alice).deposit(proofHex, proofData.publicInputs),
      ).to.be.reverted;
    });

    it("should reject a truncated proof", async function () {
      const { darkPool, alice, proofData } = await loadFixture(fixture);

      const truncated = proofData.proof.slice(0, proofData.proof.length - 32);
      const proofHex = "0x" + Buffer.from(truncated).toString("hex");

      await expect(
        darkPool.connect(alice).deposit(proofHex, proofData.publicInputs),
      ).to.be.reverted;
    });
  });

  describe("Input Integrity (Binding)", function () {
    it("should reject if Public Input 'Value' is modified", async function () {
      const { darkPool, alice, proofData } = await loadFixture(fixture);

      // Deposit layout: [0,1] compliance, [2] leaf, [3,4] eph_pub, [5] value, [6] asset, [7..13] ct.
      const tamperedInputs = [...proofData.publicInputs];
      tamperedInputs[5] = ethers.zeroPadValue(ethers.toBeHex(200n), 32);

      await expect(
        darkPool.connect(alice).deposit(proofData.proof, tamperedInputs),
      ).to.be.reverted;
    });

    it("should reject if Public Input 'Asset ID' is modified", async function () {
      const { darkPool, alice, proofData } = await loadFixture(fixture);

      const tamperedInputs = [...proofData.publicInputs];
      const fakeAsset = addressToFr(
        "0x000000000000000000000000000000000000dead",
      );
      tamperedInputs[6] = ethers.zeroPadValue(
        ethers.toBeHex(fakeAsset.toBigInt()),
        32,
      );

      await expect(
        darkPool.connect(alice).deposit(proofData.proof, tamperedInputs),
      ).to.be.reverted;
    });

    it("should reject if Public Input 'Ciphertext' is modified", async function () {
      const { darkPool, alice, proofData } = await loadFixture(fixture);

      const tamperedInputs = [...proofData.publicInputs];
      tamperedInputs[7] = ethers.zeroPadValue("0xdeadbeef", 32);

      await expect(
        darkPool.connect(alice).deposit(proofData.proof, tamperedInputs),
      ).to.be.reverted;
    });
  });
});
