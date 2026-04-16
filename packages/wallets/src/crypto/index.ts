 import { Fr } from "@aztec/foundation/fields";
import { Point, mulPointEscalar, Base8, subOrder } from "@zk-kit/baby-jubjub";
import { Kdf } from "./Kdf.js";
import { NotePlaintext } from "./types.js";
import { deriveSharedSecret, kdfToAesKeyIV } from "./ecdh.js";
import { packNotePlaintext, unpackNotePlaintext } from "./packing.js";
import { aes128Encrypt, aes128Decrypt } from "./aes.js";
import { Poseidon } from "./Poseidon.js";

/**
 * Reduces a field element to a valid BabyJubJub scalar (< subgroup order).
 * Required because ScalarField<63> only supports scalars < 2^252.
 */
export function toBjjScalar(fr: Fr): Fr {
  return new Fr(fr.toBigInt() % subOrder);
}

export * from "./types.js";
export * from "./aes.js";
export * from "./packing.js";
export * from "./ecdh.js";
export * from "./fields.js";
export * from "./Poseidon.js";
export * from "./dleq.js";
export * from "./Kdf.js";
export * from "./nullifier.js";

export async function encryptNoteDeposit(
  sk_view: Fr,
  nonce: Fr,
  note_plain: NotePlaintext,
  compliance_pk: Point<bigint>
): Promise<{
  ciphertext: Buffer;
  ephemeralPK: Point<bigint>;
  ephemeral_sk_used: Fr;
  value_out: Fr;
  asset_id_out: Fr;
}> {
  const raw_sk = await Kdf.derive("hisoka.ephemeral", sk_view, nonce);
  const ephemeral_sk = toBjjScalar(raw_sk); // Reduce to valid BJJ scalar
  const ephemeralPK = mulPointEscalar(Base8, ephemeral_sk.toBigInt());
  const shared_ss = await deriveSharedSecret(ephemeral_sk, compliance_pk);
  const { key, iv } = await kdfToAesKeyIV(shared_ss);

  const plaintext = packNotePlaintext(note_plain);
  const ciphertext = await aes128Encrypt(plaintext, key, iv);

  return {
    ciphertext,
    ephemeralPK,
    ephemeral_sk_used: ephemeral_sk,
    value_out: note_plain.value,
    asset_id_out: note_plain.asset_id,
  };
}

export async function decryptNoteDeposit(
  ephemeral_sk: Fr,
  compliance_pk: Point<bigint>,
  ciphertext: Buffer
): Promise<NotePlaintext> {
  const shared_ss = await deriveSharedSecret(ephemeral_sk, compliance_pk);
  const { key, iv } = await kdfToAesKeyIV(shared_ss);

  const plaintext = await aes128Decrypt(ciphertext, key, iv);
  return unpackNotePlaintext(plaintext);
}

export async function complianceDecryptNote(
  compliance_sk: bigint,
  ephemeralPK: Point<bigint>,
  ciphertext: Buffer
): Promise<NotePlaintext> {
  const shared_point = mulPointEscalar(ephemeralPK, compliance_sk);
  const shared_ss = new Fr(shared_point[0]);
  const { key, iv } = await kdfToAesKeyIV(shared_ss);
  const plaintext = await aes128Decrypt(ciphertext, key, iv);
  return unpackNotePlaintext(plaintext);
}

export async function complianceDecrypt3Party(
  compliance_sk: bigint,
  intermediate_point: Point<bigint>,
  ciphertext: Buffer
): Promise<{ note: NotePlaintext; sharedSecret: Fr }> {
  const shared_point = mulPointEscalar(intermediate_point, compliance_sk);
  const shared_ss = new Fr(shared_point[0]);
  const { key, iv } = await kdfToAesKeyIV(shared_ss);
  const plaintext = await aes128Decrypt(ciphertext, key, iv);

  return {
    note: unpackNotePlaintext(plaintext),
    sharedSecret: shared_ss,
  };
}

export async function recipientDecrypt3Party(
  recipient_sk: bigint,
  intermediate_point: Point<bigint>,
  ciphertext: Buffer
): Promise<{ note: NotePlaintext; sharedSecret: Fr }> {
  const shared_point = mulPointEscalar(intermediate_point, recipient_sk);
  const shared_ss = new Fr(shared_point[0]);
  const { key, iv } = await kdfToAesKeyIV(shared_ss);
  const plaintext = await aes128Decrypt(ciphertext, key, iv);

  return {
    note: unpackNotePlaintext(plaintext),
    sharedSecret: shared_ss,
  };
}

export function unpackCiphertext(packed: Fr[]): Buffer {
  if (packed.length !== 7) {
    throw new Error(
      `Invalid packed ciphertext length. Expected 7 Fields, got ${packed.length}.`
    );
  }

  const ciphertext = Buffer.alloc(208);
  let idx = 0;

  for (let p = 0; p < 7; p++) {
    let val = packed[p]!.toBigInt();
    // Fields 0-5 hold 31 bytes. Field 6 holds the remaining 22 bytes.
    const bytesInThis = p < 6 ? 31 : 22;

    for (let i = 0; i < bytesInThis; i++) {
      if (idx >= 208) break;
      // Unpack from little-endian byte order
      ciphertext[idx] = Number(val % 256n);
      val = val / 256n;
      idx++;
    }
  }

  return ciphertext;
}

export async function calculatePublicMemoId(
  val: Fr,
  asset: Fr,
  timelock: Fr,
  ownerX: Fr,
  ownerY: Fr,
  salt: Fr
): Promise<Fr> {
  return await Poseidon.hash([val, asset, timelock, ownerX, ownerY, salt]);
}
