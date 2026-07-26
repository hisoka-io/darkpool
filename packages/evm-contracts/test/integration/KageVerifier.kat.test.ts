import { expect } from "chai";
import { ethers } from "hardhat";
import { KAGE_PROOF, KAGE_PUBLIC_INPUTS } from "./kageGolden";
import { HonkVerifier__factory } from "../../typechain-types/factories/contracts/verifiers/KageVerifier.sol";

function mutate(publicInputs: string[], idx: number): string[] {
  const copy = [...publicInputs];
  copy[idx] = ethers.zeroPadValue(
    ethers.toBeHex(BigInt(publicInputs[idx]) + 1n),
    32,
  );
  return copy;
}

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

  // The optimized Honk verifier reverts rather than returning false, so `.reverted` is exact.
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
