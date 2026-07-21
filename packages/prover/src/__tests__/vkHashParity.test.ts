import { describe, it, expect } from "vitest";
import { readFileSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, resolve } from "path";
import { UltraHonkBackend } from "@aztec/bb.js";
import { CompiledCircuit } from "@noir-lang/noir_js";
import { ensureBBInitialized } from "../prover-base.js";
import { circuit as deposit } from "../generated/deposit_circuit.js";
import { circuit as withdraw } from "../generated/withdraw_circuit.js";
import { circuit as transfer } from "../generated/transfer_circuit.js";
import { circuit as join } from "../generated/join_circuit.js";
import { circuit as split } from "../generated/split_circuit.js";
import { circuit as public_claim } from "../generated/public_claim_circuit.js";
import { circuit as withdraw_multisig } from "../generated/withdraw_multisig_circuit.js";
import { circuit as transfer_multisig } from "../generated/transfer_multisig_circuit.js";
import { circuit as split_multisig } from "../generated/split_multisig_circuit.js";
import { circuit as join_multisig } from "../generated/join_multisig_circuit.js";
import { circuit as swap_settle } from "../generated/swap_settle_circuit.js";

// Deterministic prover<->verifier coupling. RealProofE2E proves against the DEPLOYED verifiers using the prover's
// BUNDLED circuit bytecode (src/generated/*_circuit); its green is only meaningful if that bytecode still matches
// the committed verifiers. This guard closes the drift where a circuit edit regenerates the prover bytecode but
// NOT the committed .sol verifiers (generate_verifier.js skips when native bb is absent -- CI, bb.js-only dev).
// For each of the 11 deployed circuits it re-derives the on-chain VK_HASH from the SAME bundled bytecode the
// provers ship, via the bb.js UltraHonk path prover-base uses, and asserts it equals contracts/verifiers/
// vk-hashes.json. bb.js VK == native-bb CLI VK (barretenberg #1649), so the bb.js-derived VK_HASH equals the
// committed --optimized CLI hash even though bb.js emits only the non-optimized verifier. bb.js-only -> runs in
// ordinary CI with no native bb, catching prover<->committed drift regardless of build ordering or bb presence.
const VK_HASH_RE = /uint256 constant VK_HASH = (0x[0-9a-fA-F]{64});/;
const EVM = { verifierTarget: "evm" } as const;

const MANIFEST_PATH = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../../../evm-contracts/contracts/verifiers/vk-hashes.json",
);

// Every circuit that DarkPool deploys an on-chain verifier for: the 10 bb.js base/multisig circuits plus the
// native-generated Kage swap_settle. swap_intent is inner-only (no on-chain verifier) and is excluded.
const DEPLOYED_CIRCUITS: Record<string, CompiledCircuit> = {
  deposit,
  withdraw,
  transfer,
  join,
  split,
  public_claim,
  withdraw_multisig,
  transfer_multisig,
  split_multisig,
  join_multisig,
  swap_settle,
};

async function deriveVkHash(bytecode: string): Promise<string> {
  const backend = new UltraHonkBackend(bytecode, await ensureBBInitialized());
  const vk = await backend.getVerificationKey(EVM);
  const src = await backend.getSolidityVerifier(vk, EVM);
  const match = src.match(VK_HASH_RE);
  if (!match) throw new Error("VK_HASH not found in bb.js-generated verifier");
  return match[1];
}

describe("prover<->verifier VK-hash parity (bundled bytecode vs committed manifest)", () => {
  const manifest = JSON.parse(readFileSync(MANIFEST_PATH, "utf8")) as Record<
    string,
    string
  >;

  it("manifest covers exactly the 11 bundled deployed circuits", () => {
    expect(Object.keys(manifest).sort()).toEqual(
      Object.keys(DEPLOYED_CIRCUITS).sort(),
    );
  });

  for (const [name, circuit] of Object.entries(DEPLOYED_CIRCUITS)) {
    it(`${name}: bb.js VK_HASH from bundled bytecode == committed manifest`, async () => {
      const derived = await deriveVkHash(circuit.bytecode);
      expect(
        derived,
        `bundled ${name} bytecode drifted from the committed verifier VK -- regenerate verifiers with native bb`,
      ).toBe(manifest[name]);
    }, 120000);
  }
});
