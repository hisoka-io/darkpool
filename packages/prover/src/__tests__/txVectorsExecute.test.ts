/**
 * Every golden transaction witness must satisfy its compiled circuit. Byte-identity alone pins a witness the
 * circuit could still reject; executing it (witness generation only, no proof) closes that gap.
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join as joinPath, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { Noir, type CompiledCircuit, type InputMap } from "@noir-lang/noir_js";
import {
  computePsi,
  deriveCek,
  isEvenY,
  publicKey,
  toFr,
} from "@hisoka/wallets";
import { circuit as deposit } from "../generated/deposit_circuit.js";
import { circuit as withdraw } from "../generated/withdraw_circuit.js";
import { circuit as transfer } from "../generated/transfer_circuit.js";
import { circuit as split } from "../generated/split_circuit.js";
import { circuit as join } from "../generated/join_circuit.js";
import { circuit as public_claim } from "../generated/public_claim_circuit.js";

const VECTORS = joinPath(
  dirname(fileURLToPath(import.meta.url)),
  "../../tx-vectors.json",
);

const CIRCUITS = {
  deposit,
  withdraw,
  transfer,
  split,
  join,
  public_claim,
} as const;

type CircuitName = keyof typeof CIRCUITS;

const frozen = JSON.parse(readFileSync(VECTORS, "utf8")) as Record<
  CircuitName,
  { witness: InputMap }
>;

function execute(name: CircuitName, witness: InputMap) {
  return new Noir(CIRCUITS[name] as CompiledCircuit).execute(witness);
}

describe("transaction golden vectors execute against the compiled circuits", () => {
  it.each(Object.keys(CIRCUITS) as CircuitName[])(
    "%s witness satisfies every constraint",
    async (name) => {
      const { witness } = await execute(name, frozen[name].witness);
      expect(witness.length).toBeGreaterThan(0);
    },
    120_000,
  );

  it("rejects the deposit vector re-minted under an odd-y self ephemeral", async () => {
    const vector = frozen.deposit.witness as {
      compliance_pubkey_x: string;
      compliance_pubkey_y: string;
      note: Record<string, string>;
      eph: string;
    };
    const compliancePk: [bigint, bigint] = [
      BigInt(vector.compliance_pubkey_x),
      BigInt(vector.compliance_pubkey_y),
    ];
    let scalar = BigInt(vector.eph) + 1n;
    while (isEvenY(publicKey(toFr(scalar)))) scalar += 1n;
    const odd = toFr(scalar);
    // psi is recomputed for the new ephemeral, so only the even-y assert is left to fail.
    const psi = await computePsi(deriveCek(odd, compliancePk));

    await expect(
      execute("deposit", {
        ...vector,
        note: { ...vector.note, psi: psi.toString() },
        eph: odd.toString(),
      }),
    ).rejects.toThrow(/deposit discovery tag must be even-y/);
  }, 120_000);
});
