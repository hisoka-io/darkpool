import { expect } from "chai";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { deployDarkPoolFixture } from "../helpers/fixtures";

// whenNotPaused guards every money entrypoint and runs before proof verification, so a paused pool must halt
// each path regardless of the proof bytes. Without this, dropping the modifier from any single entrypoint would
// silently defeat the emergency halt on that path and no other test would notice.
describe("DarkPool: pause halts every money entrypoint", function () {
  it("reverts EnforcedPause on all spend/claim paths while paused", async function () {
    const { darkPool, deployer, alice } = await loadFixture(deployDarkPoolFixture);
    await darkPool.connect(deployer).pause();

    const p = "0x";
    const pi: bigint[] = [];
    const proofCalls: Array<() => Promise<unknown>> = [
      () => darkPool.connect(alice).deposit(p, pi),
      () => darkPool.connect(alice).withdraw(p, pi),
      () => darkPool.connect(alice).privateTransfer(p, pi),
      () => darkPool.connect(alice).split(p, pi),
      () => darkPool.connect(alice).join(p, pi),
      () => darkPool.connect(alice).publicClaim(p, pi),
      () => darkPool.connect(alice).withdrawMultisig(p, pi),
      () => darkPool.connect(alice).transferMultisig(p, pi),
      () => darkPool.connect(alice).splitMultisig(p, pi),
      () => darkPool.connect(alice).joinMultisig(p, pi),
    ];
    for (const call of proofCalls) {
      await expect(call()).to.be.revertedWithCustomError(darkPool, "EnforcedPause");
    }
    await expect(
      darkPool
        .connect(alice)
        .publicTransfer(1n, 2n, await darkPool.getAddress(), 100n, 0n, 0n),
    ).to.be.revertedWithCustomError(darkPool, "EnforcedPause");

    await darkPool.connect(deployer).unpause();
    expect(await darkPool.paused()).to.equal(false);
  });
});
