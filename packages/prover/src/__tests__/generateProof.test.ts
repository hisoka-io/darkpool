import { beforeEach, describe, expect, it, vi } from "vitest";

const backend = vi.hoisted(() => ({
  verifies: true,
  generateFails: false,
}));

vi.mock("@noir-lang/noir_js", () => ({
  Noir: class {
    execute() {
      return Promise.resolve({ witness: new Uint8Array([1]) });
    }
  },
}));

vi.mock("@aztec/bb.js", () => ({
  Barretenberg: {
    initSingleton: () => Promise.resolve(),
    getSingleton: () => ({}),
  },
  UltraHonkBackend: class {
    generateProof() {
      return backend.generateFails
        ? Promise.reject(new Error("witness does not satisfy the circuit"))
        : Promise.resolve({
            proof: new Uint8Array([7, 7]),
            publicInputs: ["0x01"],
          });
    }
    verifyProof() {
      return Promise.resolve(backend.verifies);
    }
  },
}));

const { generateProof } = await import("../prover-base.js");
const { ProofError, UnverifiedProofError } = await import("../errors.js");

const CIRCUIT = { bytecode: "", abi: {} };

describe("generateProof", () => {
  beforeEach(() => {
    backend.verifies = true;
    backend.generateFails = false;
  });

  it("returns a proof that verifies locally", async () => {
    const proof = await generateProof("withdraw", CIRCUIT, {});
    expect(proof.verified).toBe(true);
    expect([...proof.proof]).toEqual([7, 7]);
    expect(proof.publicInputs).toEqual(["0x01"]);
  });

  it("throws a typed error naming the circuit when local verification fails", async () => {
    backend.verifies = false;
    const attempt = generateProof("transfer", CIRCUIT, {});
    await expect(attempt).rejects.toBeInstanceOf(UnverifiedProofError);
    await expect(attempt).rejects.toMatchObject({
      name: "UnverifiedProofError",
      circuit: "transfer",
      message: expect.stringMatching(/^proof failed for transfer: /),
    });
  });

  it("wraps a proving failure in ProofError, distinct from a verification failure", async () => {
    backend.generateFails = true;
    const attempt = generateProof("split", CIRCUIT, {});
    await expect(attempt).rejects.toBeInstanceOf(ProofError);
    await expect(attempt).rejects.not.toBeInstanceOf(UnverifiedProofError);
    await expect(attempt).rejects.toMatchObject({
      circuit: "split",
      message: expect.stringContaining("witness does not satisfy the circuit"),
    });
  });
});
