import { Aes128 } from "@aztec/foundation/crypto";
import { PaddingError, SizeError } from "./types.js";

const AES_BLOCK = 16;

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

  // The note plaintext is a fixed 192 bytes (a multiple of the 16-byte block), so PKCS#7 always
  // appends exactly one full block of 0x10. Verify it in constant time (fixed iteration count, no
  // branch on decrypted content) to deny a padding-oracle timing side-channel on relayed memos.
  const dataLen = paddedPlaintext.length - AES_BLOCK;
  let mismatch = 0;
  for (let i = 0; i < AES_BLOCK; i++) {
    mismatch |= paddedPlaintext[dataLen + i] ^ AES_BLOCK;
  }
  if (mismatch !== 0) {
    throw new PaddingError("invalid PKCS#7 padding");
  }

  return paddedPlaintext.slice(0, dataLen);
}
