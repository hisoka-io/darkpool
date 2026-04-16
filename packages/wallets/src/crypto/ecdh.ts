import { Fr } from "@aztec/foundation/fields";
import { mulPointEscalar, Point } from "@zk-kit/baby-jubjub";
import { Poseidon } from "./Poseidon.js";
import { stringToFr } from "./fields.js";

export async function deriveSharedSecret(
  ephemeral_sk: Fr,
  compliance_pk: Point<bigint>,
): Promise<Fr> {
  if (ephemeral_sk.isZero()) {
    throw new Error("ephemeral_sk must not be zero");
  }
  const shared_point = mulPointEscalar(compliance_pk, ephemeral_sk.toBigInt());
  return new Fr(shared_point[0]); // x coord as Fr
}

export async function kdfToAesKeyIV(
  shared_ss: Fr,
): Promise<{ key: Buffer; iv: Buffer }> {
  const key_purpose = await stringToFr("hisoka.enc_key");
  const iv_purpose = await stringToFr("hisoka.enc_iv");

  const key_fr = await Poseidon.hash([shared_ss, key_purpose]);
  const iv_fr = await Poseidon.hash([shared_ss, iv_purpose]);

  return {
    key: Buffer.from(key_fr.toBuffer().slice(-16)),
    iv: Buffer.from(iv_fr.toBuffer().slice(-16)),
  };
}
