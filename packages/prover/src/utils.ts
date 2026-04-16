import { Fr } from "@aztec/foundation/fields";

/** Unpacks 7 Field elements into 208-byte ciphertext buffer (matches Noir pack_ciphertext). */
export function unpackCiphertext(packed: Fr[]): Buffer {
  if (packed.length !== 7) {
    throw new Error(
      `Invalid packed ciphertext length. Expected 7 Fields, got ${packed.length}.`,
    );
  }

  const ciphertext = Buffer.alloc(208);
  let idx = 0;

  for (let p = 0; p < 7; p++) {
    let val = packed[p].toBigInt();
    const bytesInThis = p < 6 ? 31 : 22;

    for (let i = 0; i < bytesInThis; i++) {
      if (idx >= 208) break;
      ciphertext[idx] = Number(val % 256n);
      val = val / 256n;
      idx++;
    }
  }

  return ciphertext;
}
