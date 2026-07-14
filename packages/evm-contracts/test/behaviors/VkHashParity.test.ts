import { expect } from "chai";
import { readFileSync } from "fs";
import { resolve } from "path";

// Pin every verifier's committed VK_HASH to the generated manifest, so a hand-edited or half-regenerated
// verifier fails loudly here instead of silently at proof time (InvalidProof). The manifest is written by
// prover/scripts/generate_verifier.js from the same verifier string it emits.
const VERIFIERS_DIR = resolve(process.cwd(), "contracts/verifiers");

const NAME_TO_FILE: Record<string, string> = {
  deposit: "DepositVerifier.sol",
  withdraw: "WithdrawVerifier.sol",
  transfer: "TransferVerifier.sol",
  join: "JoinVerifier.sol",
  split: "SplitVerifier.sol",
  public_claim: "PublicClaimVerifier.sol",
  withdraw_multisig: "WithdrawMultisigVerifier.sol",
  transfer_multisig: "TransferMultisigVerifier.sol",
  split_multisig: "SplitMultisigVerifier.sol",
  join_multisig: "JoinMultisigVerifier.sol",
  swap_settle: "KageVerifier.sol",
};

const VK_HASH_RE = /uint256 constant VK_HASH = (0x[0-9a-fA-F]{64});/;

describe("VK-hash manifest parity", function () {
  const manifest = JSON.parse(
    readFileSync(resolve(VERIFIERS_DIR, "vk-hashes.json"), "utf8"),
  ) as Record<string, string>;

  it("manifest covers exactly the 11 verifiers", function () {
    expect(Object.keys(manifest).sort()).to.deep.equal(
      Object.keys(NAME_TO_FILE).sort(),
    );
  });

  for (const [name, file] of Object.entries(NAME_TO_FILE)) {
    it(`${name}: committed verifier VK_HASH matches the manifest`, function () {
      const match = readFileSync(resolve(VERIFIERS_DIR, file), "utf8").match(
        VK_HASH_RE,
      );
      expect(match, `VK_HASH not found in ${file}`).to.not.equal(null);
      expect(match![1]).to.equal(manifest[name]);
    });
  }
});
