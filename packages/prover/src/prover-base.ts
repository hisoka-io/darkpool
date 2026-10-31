import { Barretenberg, UltraHonkBackend } from "@aztec/bb.js";
import { CompiledCircuit, InputMap, Noir } from "@noir-lang/noir_js";
import { ProofData } from "./types.js";
import { ProofError, UnverifiedProofError } from "./errors.js";

const BB_THREADS = Math.max(
  1,
  parseInt(process.env.BB_THREADS ?? "16", 10) || 16,
);

let bbInitialized = false;

export async function ensureBBInitialized(): Promise<Barretenberg> {
  if (!bbInitialized) {
    await Barretenberg.initSingleton({ threads: BB_THREADS });
    bbInitialized = true;
  }
  return Barretenberg.getSingleton();
}

export async function generateProof(
  circuitName: string,
  rawCircuit: { bytecode: string; abi: unknown },
  noirInputs: InputMap,
): Promise<ProofData> {
  const circuit = rawCircuit as CompiledCircuit;
  const noir = new Noir(circuit);
  const api = await ensureBBInitialized();
  const backend = new UltraHonkBackend(circuit.bytecode, api);

  let generated: { proof: Uint8Array; publicInputs: string[] };
  let verified: boolean;
  try {
    const { witness } = await noir.execute(noirInputs);
    generated = await backend.generateProof(witness, {
      verifierTarget: "evm",
    });
    verified = await backend.verifyProof(generated, {
      verifierTarget: "evm",
    });
  } catch (err) {
    throw new ProofError(
      circuitName,
      err instanceof Error ? err.message : String(err),
      err,
    );
  }
  if (!verified) throw new UnverifiedProofError(circuitName);
  return {
    proof: generated.proof,
    publicInputs: generated.publicInputs,
    verified,
  };
}
