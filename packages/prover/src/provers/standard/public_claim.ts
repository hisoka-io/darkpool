import { generateProof } from "../../prover-base.js";
import { circuit } from "../../generated/public_claim_circuit.js";
import { PublicClaimInputs, ProofData } from "../../types.js";
import { marshalNote, pointHex } from "../../marshal.js";
import { toBjjScalar } from "@hisoka/wallets";

export async function provePublicClaim(
  inputs: PublicClaimInputs,
): Promise<ProofData> {
  // reduce to BJJ subgroup order; circuit asserts a canonical scalar.
  const recipientSkReduced = toBjjScalar(inputs.recipientSk);
  const c = pointHex(inputs.compliancePk);
  return generateProof("public_claim", circuit, {
    memo_id: inputs.memoId.toString(),
    compliance_pubkey_x: c.x,
    compliance_pubkey_y: c.y,
    current_timestamp: inputs.currentTimestamp.toString(),
    val: inputs.val.toString(),
    asset_id: inputs.assetId.toString(),
    timelock: inputs.timelock.toString(),
    owner_x: inputs.ownerX.toString(),
    owner_y: inputs.ownerY.toString(),
    salt: inputs.salt.toString(),
    recipient_sk: recipientSkReduced.toString(),
    note_out: marshalNote("public_claim", inputs.noteOut),
    eph: inputs.eph.toString(),
  });
}
