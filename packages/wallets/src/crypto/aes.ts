import { Aes128 } from "@aztec/foundation/crypto";
import { PaddingError, SizeError } from "./types.js";

/** AES-128-CBC encrypt. 192-byte plaintext -> 208-byte ciphertext (PKCS#7). */
export async function aes128Encrypt(
  plaintext: Buffer,
  key: Buffer,
  iv: Buffer,
): Promise<Buffer> {
  if (plaintext.length !== 192)
    throw new SizeError(192, plaintext.length, "plaintext");
  if (key.length !== 16 || iv.length !== 16)
    throw new SizeError(16, key.length || iv.length, "key/iv");

  const aes = new Aes128();
  return await aes.encryptBufferCBC(plaintext, iv, key);
}

/** AES-128-CBC decrypt. 208-byte ciphertext -> 192-byte plaintext (PKCS#7 validated). */
export async function aes128Decrypt(
  ciphertext: Buffer,
  key: Buffer,
  iv: Buffer,
): Promise<Buffer> {
  if (ciphertext.length !== 208)
    throw new SizeError(208, ciphertext.length, "ciphertext");
  if (key.length !== 16 || iv.length !== 16)
    throw new SizeError(16, key.length || iv.length, "key/iv");

  const aes = new Aes128();
  const paddedPlaintext = await aes.decryptBufferCBCKeepPadding(
    ciphertext,
    iv,
    key,
  );

  const lastByte = paddedPlaintext[paddedPlaintext.length - 1];

  if (lastByte === 0 || lastByte > 16) {
    throw new PaddingError(`padding byte out of range: ${lastByte}`);
  }

  let mismatch = 0;
  for (let i = 0; i < lastByte; i++) {
    mismatch |= paddedPlaintext[paddedPlaintext.length - 1 - i] ^ lastByte;
  }
  if (mismatch !== 0) {
    throw new PaddingError("inconsistent padding bytes");
  }

  return paddedPlaintext.slice(0, paddedPlaintext.length - lastByte);
}
