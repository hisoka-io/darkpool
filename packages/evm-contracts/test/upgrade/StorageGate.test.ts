import { expect } from "chai";
import { ethers, upgrades } from "hardhat";

const UUPS = { kind: "uups" as const };

// assertStorageUpgradeSafe rejects a namespace-INTERNAL layout change a bare-sequential snapshot cannot see; if it stops throwing, the gate is toothless.
describe("Storage-gate rejects namespace-internal reorders (HIGH-2)", function () {
  it("accepts an identical namespace layout", async function () {
    const base = await ethers.getContractFactory("StorageGateBaseMock");
    const same = await ethers.getContractFactory("StorageGateBaseMock");
    await upgrades.validateUpgrade(base, same, UUPS);
  });

  it("rejects a field inserted into the front of a namespace struct", async function () {
    const base = await ethers.getContractFactory("StorageGateBaseMock");
    const bad = await ethers.getContractFactory("StorageGateBadMock");

    let threw = false;
    let message = "";
    try {
      await upgrades.validateUpgrade(base, bad, UUPS);
    } catch (e: unknown) {
      threw = true;
      message = e instanceof Error ? e.message : String(e);
    }
    expect(
      threw,
      "expected validateUpgrade to reject the storage-incompatible layout",
    ).to.equal(true);
    expect(message).to.match(/incompatible|storage|inserted/i);
  });
});
