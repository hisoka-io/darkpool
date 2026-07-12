import { expect } from "chai";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { deployDarkPoolFixture } from "../helpers/fixtures";

// Input- and access-guards that gate money entrypoints but had no negative test (branch-coverage gaps).
describe("DarkPool: entrypoint input + access guards", function () {
  it("publicTransfer rejects zero and over-uint128 value", async function () {
    const { darkPool, token, alice } = await loadFixture(deployDarkPoolFixture);
    const asset = await token.getAddress();
    await expect(
      darkPool.connect(alice).publicTransfer(1n, 2n, asset, 0n, 0n, 0n),
    ).to.be.revertedWithCustomError(darkPool, "ValueZero");
    await expect(
      darkPool.connect(alice).publicTransfer(1n, 2n, asset, 2n ** 128n, 0n, 0n),
    ).to.be.revertedWithCustomError(darkPool, "ValueTooLarge");
  });

  it("setVerifier rejects a non-UPGRADER caller", async function () {
    const { darkPool, alice } = await loadFixture(deployDarkPoolFixture);
    await expect(
      darkPool.connect(alice).setVerifier(0, alice.address),
    ).to.be.revertedWithCustomError(
      darkPool,
      "AccessControlUnauthorizedAccount",
    );
  });
});
