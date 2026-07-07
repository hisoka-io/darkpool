import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { anyValue } from "@nomicfoundation/hardhat-chai-matchers/withArgs";

const THRESHOLD = 3n;
const COMMITTEE_SIZE = 5n;
const ACTION_REQUESTED = 0; // enum Action.Requested
const TAG = ethers.id("note-discovery-tag");

async function deployRegistryFixture() {
  const [admin, member, outsider] = await ethers.getSigners();
  const registry = await (
    await ethers.getContractFactory("ComplianceRegistry")
  ).deploy(admin.address, THRESHOLD, COMMITTEE_SIZE);
  await registry.waitForDeployment();
  return { registry, admin, member, outsider };
}

describe("ComplianceRegistry: member-gated attestation log", function () {
  describe("recordAction access control (the ACTUAL registered-member set)", function () {
    it("lets a registered member emit ComplianceAction", async function () {
      const { registry, admin, member } = await loadFixture(
        deployRegistryFixture,
      );
      await registry.connect(admin).registerMember(member.address, "US");
      await expect(
        registry.connect(member).recordAction(ACTION_REQUESTED, TAG, "ok"),
      )
        .to.emit(registry, "ComplianceAction")
        .withArgs(member.address, ACTION_REQUESTED, TAG, anyValue, "ok");
    });

    it("reverts a non-member with CallerNotRegisteredMember(caller)", async function () {
      const { registry, outsider } = await loadFixture(deployRegistryFixture);
      await expect(
        registry.connect(outsider).recordAction(ACTION_REQUESTED, TAG, "x"),
      )
        .to.be.revertedWithCustomError(registry, "CallerNotRegisteredMember")
        .withArgs(outsider.address);
    });

    it("reverts a DEREGISTERED member (enforcement tracks the live set, not a stale grant)", async function () {
      const { registry, admin, member } = await loadFixture(
        deployRegistryFixture,
      );
      await registry.connect(admin).registerMember(member.address, "US");
      await registry.connect(admin).deregisterMember(member.address);
      await expect(
        registry.connect(member).recordAction(ACTION_REQUESTED, TAG, "x"),
      )
        .to.be.revertedWithCustomError(registry, "CallerNotRegisteredMember")
        .withArgs(member.address);
    });
  });

  describe("distinct constructor errors (one legible error per invalid arg)", function () {
    async function factory() {
      return ethers.getContractFactory("ComplianceRegistry");
    }
    it("ZeroAdmin when admin is the zero address", async function () {
      const f = await factory();
      await expect(
        f.deploy(ethers.ZeroAddress, THRESHOLD, COMMITTEE_SIZE),
      ).to.be.revertedWithCustomError(f, "ZeroAdmin");
    });
    it("ThresholdZero when t == 0", async function () {
      const [admin] = await ethers.getSigners();
      const f = await factory();
      await expect(
        f.deploy(admin.address, 0n, COMMITTEE_SIZE),
      ).to.be.revertedWithCustomError(f, "ThresholdZero");
    });
    it("CommitteeSizeZero when n == 0", async function () {
      const [admin] = await ethers.getSigners();
      const f = await factory();
      await expect(
        f.deploy(admin.address, THRESHOLD, 0n),
      ).to.be.revertedWithCustomError(f, "CommitteeSizeZero");
    });
    it("ThresholdExceedsCommittee(t, n) when t > n", async function () {
      const [admin] = await ethers.getSigners();
      const f = await factory();
      await expect(f.deploy(admin.address, 6n, COMMITTEE_SIZE))
        .to.be.revertedWithCustomError(f, "ThresholdExceedsCommittee")
        .withArgs(6n, COMMITTEE_SIZE);
    });
  });

  describe("distinct registration errors", function () {
    it("ZeroMember on registering the zero address", async function () {
      const { registry, admin } = await loadFixture(deployRegistryFixture);
      await expect(
        registry.connect(admin).registerMember(ethers.ZeroAddress, ""),
      ).to.be.revertedWithCustomError(registry, "ZeroMember");
    });
    it("MemberAlreadyRegistered(member) on a duplicate register", async function () {
      const { registry, admin, member } = await loadFixture(
        deployRegistryFixture,
      );
      await registry.connect(admin).registerMember(member.address, "US");
      await expect(registry.connect(admin).registerMember(member.address, "US"))
        .to.be.revertedWithCustomError(registry, "MemberAlreadyRegistered")
        .withArgs(member.address);
    });
    it("MemberNotRegistered(member) on deregistering a non-member", async function () {
      const { registry, admin, outsider } = await loadFixture(
        deployRegistryFixture,
      );
      await expect(registry.connect(admin).deregisterMember(outsider.address))
        .to.be.revertedWithCustomError(registry, "MemberNotRegistered")
        .withArgs(outsider.address);
    });
  });
});
