import { describe, it, expect } from "vitest";
import { Point, mulPointEscalar, Base8 } from "@zk-kit/baby-jubjub";
import { generateDLEQProof, verifyDLEQProof } from "../crypto/dleq";
import { BJJ_SUBGROUP_ORDER } from "../crypto/constants";

const subgroupOrder = BJJ_SUBGROUP_ORDER;

describe("Chaum-Pedersen DLEQ Proof", () => {
  const bob_sk = 123456789n;
  const carol_sk = 987654321n;
  const carol_pk: Point<bigint> = mulPointEscalar(
    Base8,
    carol_sk % subgroupOrder,
  );

  it("should generate a valid proof that a verifier can accept", async () => {
    const { B, P, pi } = await generateDLEQProof(bob_sk, carol_pk);
    const isValid = await verifyDLEQProof(B, carol_pk, P, pi);
    expect(isValid).toBe(true);
  });

  it("should fail verification if the intermediate point P is incorrect", async () => {
    const { B, pi } = await generateDLEQProof(bob_sk, carol_pk);
    const malicious_P = mulPointEscalar(carol_pk, 999n % subgroupOrder);
    const isValid = await verifyDLEQProof(B, carol_pk, malicious_P, pi);
    expect(isValid).toBe(false);
  });

  it("should fail verification if the proof object is tampered with", async () => {
    const { B, P, pi } = await generateDLEQProof(bob_sk, carol_pk);
    const tampered_pi = { ...pi, z: (pi.z + 1n) % subgroupOrder };
    const isValid = await verifyDLEQProof(B, carol_pk, P, tampered_pi);
    expect(isValid).toBe(false);
  });
});
