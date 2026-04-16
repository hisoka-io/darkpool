import { generateProof } from "../prover-base.js";
import { circuit } from "../generated/public_claim_circuit.js";
import { PublicClaimInputs, ProofData } from "../types.js";
import { toBjjScalar } from "@hisoka/wallets";

export async function provePublicClaim(
  inputs: PublicClaimInputs,
): Promise<ProofData> {
  // The public_claim circuit uses BJJ::new(recipient_sk).derive_public_key() which
  // internally converts via ScalarField<63> (max 252 bits). The IVK from
  // getIncomingViewingKey() is a BN254 field element (up to ~2^254), so we must
  // reduce mod BJJ_SUBGROUP_ORDER before passing to the circuit. This is safe
  // because BJJ scalar multiplication is modular: k*G == (k % order)*G.
  const recipientSkReduced = toBjjScalar(inputs.recipientSk);

  const noirInputs = {
    memo_id: inputs.memoId.toString(),
    compliance_pubkey_x: `0x${inputs.compliancePk[0].toString(16)}`,
    compliance_pubkey_y: `0x${inputs.compliancePk[1].toString(16)}`,
    val: inputs.val.toString(),
    asset_id: inputs.assetId.toString(),
    timelock: inputs.timelock.toString(),
    owner_x: inputs.ownerX.toString(),
    owner_y: inputs.ownerY.toString(),
    salt: inputs.salt.toString(),
    recipient_sk: recipientSkReduced.toString(),
    note_out: {
      asset_id: inputs.noteOut.asset_id.toString(),
      value: inputs.noteOut.value.toString(),
      secret: inputs.noteOut.secret.toString(),
      nullifier: inputs.noteOut.nullifier.toString(),
      timelock: inputs.noteOut.timelock.toString(),
      hashlock: inputs.noteOut.hashlock.toString(),
    },
    sk_out: inputs.skOut.toString(),
  };
  return generateProof(circuit, noirInputs);
}
