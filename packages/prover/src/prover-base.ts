import { Barretenberg, UltraHonkBackend } from "@aztec/bb.js";
import { CompiledCircuit, InputMap, Noir } from "@noir-lang/noir_js";
import { ProofData } from "./types.js";

const BB_THREADS = Math.max(1, parseInt(process.env.BB_THREADS ?? "16", 10) || 16);

let bbInitialized = false;

export async function ensureBBInitialized(): Promise<Barretenberg> {
  if (!bbInitialized) {
    await Barretenberg.initSingleton({ threads: BB_THREADS });
    bbInitialized = true;
  }
  return Barretenberg.getSingleton();
}

export async function generateProof(
  rawCircuit: { bytecode: string; abi: unknown },
  noirInputs: InputMap,
): Promise<ProofData> {
  const circuit = rawCircuit as CompiledCircuit;
  const noir = new Noir(circuit);
  const api = await ensureBBInitialized();
  const backend = new UltraHonkBackend(circuit.bytecode, api);

  const { witness } = await noir.execute(noirInputs);
  const { proof, publicInputs } = await backend.generateProof(witness, {
    verifierTarget: "evm-no-zk",
  });
  const verified = await backend.verifyProof(
    { proof, publicInputs },
    { verifierTarget: "evm-no-zk" },
  );

  return { proof, publicInputs, verified };
}
