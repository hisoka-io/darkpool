import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { deployDarkPoolFixture } from "../helpers/fixtures";
import { publicKey, Fr } from "@hisoka/wallets";

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

  it("publicTransfer rejects a timelock above uint64 max (public_claim compares as u64)", async function () {
    const { darkPool, token, alice } = await loadFixture(deployDarkPoolFixture);
    const asset = await token.getAddress();
    // 2**64 truncates to 0 under the circuit's `as u64`, silently voiding the lock; the contract bounds it.
    await expect(
      darkPool
        .connect(alice)
        .publicTransfer(1n, 2n, asset, 100n, 2n ** 64n, 0n),
    ).to.be.revertedWithCustomError(darkPool, "TimelockTooLarge");
  });

  // An off-curve or identity destination is unclaimable by anyone, so the escrow burns with no recovery.
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

  // Both memo guards below were found by ablation to have ZERO coverage: each could be deleted with the
  // entire contract suite green. MemoInvalid is the only on-chain link between a claim and a funded escrow.
  it("publicClaim rejects a memoId that was never escrowed", async function () {
    const { darkPool, alice } = await loadFixture(deployDarkPoolFixture);

    // MemoInvalid is checked before proof verification, so a dummy proof reaches it.
    const pi: string[] = Array.from({ length: 13 }, (_, i) =>
      ethers.zeroPadValue(ethers.toBeHex(i === 0 ? 0xdeadbeefn : 0n), 32),
    );
    await expect(
      darkPool.connect(alice).publicClaim("0x", pi),
    ).to.be.revertedWithCustomError(darkPool, "MemoInvalid");
  });

  it("publicTransfer rejects a second escrow under a live memoId", async function () {
    const { darkPool, token, alice } = await loadFixture(deployDarkPoolFixture);
    const asset = await token.getAddress();
    const owner = publicKey(new Fr(42n));
    const post = () =>
      darkPool
        .connect(alice)
        .publicTransfer(owner[0], owner[1], asset, 100n, 0n, 777n);

    await token.connect(alice).approve(await darkPool.getAddress(), 1000n);
    await post();
    // Without this guard the same memoId is funded twice while only one claim can redeem it, so the second
    // payer's tokens are stranded in the pool.
    await expect(post()).to.be.revertedWithCustomError(
      darkPool,
      "MemoCollision",
    );
  });
});
