import { expect } from "chai";
import { ethers } from "hardhat";
import { KAGE_PROOF, KAGE_PUBLIC_INPUTS } from "./kageGolden";

// Known-answer test: the REAL native-bb swap_settle proof verifies on-chain through the generated
// KageVerifier.sol (the same verifier DarkPool registers for CIRCUIT_KAGE). The golden vectors live in
// kageGolden.ts and are shared with the through-the-entrypoint e2e (KageSwapRealProof.test.ts). This suite
// exercises verify() directly; the e2e drives the same proof through kageSwap with full effects.
describe("KageVerifier (on-chain recursive-proof KAT)", function () {
  async function deployVerifier() {
    const zkTranscriptLib = await (
      await ethers.getContractFactory(
        "contracts/verifiers/KageVerifier.sol:ZKTranscriptLib",
      )
    ).deploy();
    const verifier = await (
      await ethers.getContractFactory(
        "contracts/verifiers/KageVerifier.sol:HonkVerifier",
        {
          libraries: {
            "contracts/verifiers/KageVerifier.sol:ZKTranscriptLib":
              await zkTranscriptLib.getAddress(),
          },
        },
      )
    ).deploy();
    return verifier;
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
});
