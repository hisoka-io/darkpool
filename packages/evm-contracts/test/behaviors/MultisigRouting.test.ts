import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { deployDarkPoolFixture } from "../helpers/fixtures";

// No deposit_multisig id (deposit is unified); multisig spends occupy ids 6-9.
const CIRCUIT_WITHDRAW_MULTISIG = 6;
const CIRCUIT_TRANSFER_MULTISIG = 7;
const CIRCUIT_SPLIT_MULTISIG = 8;
const CIRCUIT_JOIN_MULTISIG = 9;
const CIRCUIT_COUNT = 11;

const zeros = (n: number): string[] => Array(n).fill(ethers.ZeroHash);

describe("DarkPool Behavior: Multisig Routing", function () {
  it("registers a real verifier at each multisig circuitId via initialize (no hand-patched setVerifier)", async function () {
    const { darkPool } = await loadFixture(deployDarkPoolFixture);
    for (const id of [
      CIRCUIT_WITHDRAW_MULTISIG,
      CIRCUIT_TRANSFER_MULTISIG,
      CIRCUIT_SPLIT_MULTISIG,
      CIRCUIT_JOIN_MULTISIG,
    ]) {
      expect(await darkPool.verifier(id)).to.not.equal(ethers.ZeroAddress);
    }
  });

  it("rejects setVerifier past the circuit range (circuitId == CIRCUIT_COUNT)", async function () {
    const { darkPool } = await loadFixture(deployDarkPoolFixture);
    const stub = await (
      await ethers.getContractFactory("StubVerifier")
    ).deploy();
    await stub.waitForDeployment();
    await expect(
      darkPool.setVerifier(CIRCUIT_COUNT, await stub.getAddress()),
    ).to.be.revertedWithCustomError(darkPool, "UnknownCircuitId");
  });

  it("rejects setVerifier pointing at an address with no code", async function () {
    const { darkPool, alice } = await loadFixture(deployDarkPoolFixture);
    await expect(
      darkPool.setVerifier(0, alice.address),
    ).to.be.revertedWithCustomError(darkPool, "VerifierHasNoCode");
  });

  // Multisig entrypoints share the standard twins' decode; a wrong length reverts before the verifier.
  describe("InvalidInputsLength (multisig lengths match their standard twins)", function () {
    it("withdrawMultisig requires 17 inputs", async function () {
      const { darkPool } = await loadFixture(deployDarkPoolFixture);
      await expect(
        darkPool.withdrawMultisig("0x", zeros(16)),
      ).to.be.revertedWithCustomError(darkPool, "InvalidInputsLength");
    });

    it("transferMultisig requires 24 inputs", async function () {
      const { darkPool } = await loadFixture(deployDarkPoolFixture);
      await expect(
        darkPool.transferMultisig("0x", zeros(23)),
      ).to.be.revertedWithCustomError(darkPool, "InvalidInputsLength");
    });

    it("splitMultisig requires 22 inputs", async function () {
      const { darkPool } = await loadFixture(deployDarkPoolFixture);
      await expect(
        darkPool.splitMultisig("0x", zeros(21)),
      ).to.be.revertedWithCustomError(darkPool, "InvalidInputsLength");
    });

    it("joinMultisig requires 14 inputs", async function () {
      const { darkPool } = await loadFixture(deployDarkPoolFixture);
      await expect(
        darkPool.joinMultisig("0x", zeros(13)),
      ).to.be.revertedWithCustomError(darkPool, "InvalidInputsLength");
    });
  });
});
