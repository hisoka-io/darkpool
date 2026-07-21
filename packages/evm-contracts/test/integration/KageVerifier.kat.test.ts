import { expect } from "chai";
import { ethers } from "hardhat";
import { KAGE_PROOF, KAGE_PUBLIC_INPUTS } from "./kageGolden";
import { HonkVerifier__factory } from "../../typechain-types/factories/contracts/verifiers/KageVerifier.sol";

/** Flip public input [idx] to a distinct field element so the recursive verifier must reject the mutated set. */
function mutate(publicInputs: string[], idx: number): string[] {
  const copy = [...publicInputs];
  copy[idx] = ethers.zeroPadValue(
    ethers.toBeHex(BigInt(publicInputs[idx]) + 1n),
    32,
  );
  return copy;
}

// Known-answer test: the REAL native-bb swap_settle proof verifies on-chain through the generated
// KageVerifier.sol (the same verifier DarkPool registers for CIRCUIT_KAGE). The golden vectors live in
// kageGolden.ts and are shared with the through-the-entrypoint e2e (KageSwapRealProof.test.ts). This suite
// exercises verify() directly; the e2e drives the same proof through kageSwap with full effects.
describe("KageVerifier (on-chain recursive-proof KAT)", function () {
  async function deployVerifier() {
    const [deployer] = await ethers.getSigners();
    return new HonkVerifier__factory(deployer).deploy();
  }

  it("verifies the real recursive proof on-chain", async function () {
    const verifier = await deployVerifier();
    expect(await verifier.verify(KAGE_PROOF, KAGE_PUBLIC_INPUTS)).to.equal(
      true,
    );
  });

  it("rejects a corrupted proof", async function () {
    const verifier = await deployVerifier();
    const bytes = ethers.getBytes(KAGE_PROOF);
    bytes[5000] ^= 0xff;
    const corrupt = ethers.hexlify(bytes);
    let ok = false;
    try {
      ok = await verifier.verify(corrupt, KAGE_PUBLIC_INPUTS);
    } catch {
      ok = false;
    }
    expect(ok).to.equal(false);
  });

  // Exhaustive per-input binding, matching RealProofE2E's assertEveryInputAndProofBound for the 10 base/multisig
  // verifiers: from the one real proof, mutating EACH public input in turn must make the deployed KageVerifier
  // reject -- no field is a free rider it ignores. verify() is called directly (no DarkPool prechecks upstream),
  // so any rejection is unambiguously the verifier. The optimized Honk verifier reverts on a bad set (it only ever
  // returns 0x01 on success), so `.to.be.reverted` is the exact rejection assertion.
  it("rejects a mutation of every public input (exhaustive binding)", async function () {
    this.timeout(120_000);
    const verifier = await deployVerifier();
    for (let i = 0; i < KAGE_PUBLIC_INPUTS.length; i++) {
      await expect(
        verifier.verify(KAGE_PROOF, mutate(KAGE_PUBLIC_INPUTS, i)),
        `public input [${i}] must be bound to the proof`,
      ).to.be.reverted;
    }
  });
});
