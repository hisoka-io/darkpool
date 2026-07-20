import { expect } from "chai";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { deployDarkPoolFixture } from "../helpers/fixtures";
import { publicKey, Fr } from "@hisoka/wallets";

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

  // An off-curve or identity destination is unclaimable by anyone: public_claim asserts the claimant's derived
  // key equals this point, and MemoStorage records neither depositor nor value, so the escrow is burned with no
  // recovery. The compliance key already got this validation; the escrow destination did not.
  it("publicTransfer rejects an owner point that is not on the BabyJubJub curve", async function () {
    const { darkPool, token, alice } = await loadFixture(deployDarkPoolFixture);
    const asset = await token.getAddress();

    // (1,2) satisfies neither a*x^2 + y^2 == 1 + d*x^2*y^2 nor the identity.
    await expect(
      darkPool.connect(alice).publicTransfer(1n, 2n, asset, 100n, 0n, 0n),
    ).to.be.revertedWithCustomError(darkPool, "InvalidMemoOwnerPoint");
  });

  it("publicTransfer rejects the identity point and out-of-field coordinates", async function () {
    const { darkPool, token, alice } = await loadFixture(deployDarkPoolFixture);
    const asset = await token.getAddress();
    const BN254_FR =
      21888242871839275222246405745257275088548364400416034343698204186575808495617n;

    await expect(
      darkPool.connect(alice).publicTransfer(0n, 1n, asset, 100n, 0n, 0n),
    ).to.be.revertedWithCustomError(darkPool, "InvalidMemoOwnerPoint");

    await expect(
      darkPool.connect(alice).publicTransfer(BN254_FR, 1n, asset, 100n, 0n, 0n),
    ).to.be.revertedWithCustomError(darkPool, "InvalidMemoOwnerPoint");
  });

  it("publicTransfer accepts a real derived key (the guard is a bound, not a blanket reject)", async function () {
    const { darkPool, token, alice } = await loadFixture(deployDarkPoolFixture);
    const asset = await token.getAddress();
    const pk = publicKey(new Fr(0x2a2an));

    await token.connect(alice).approve(await darkPool.getAddress(), 100n);
    await expect(
      darkPool
        .connect(alice)
        .publicTransfer(pk[0], pk[1], asset, 100n, 0n, 777n),
    ).to.emit(darkPool, "NewPublicMemo");
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
