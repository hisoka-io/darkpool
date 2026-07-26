import { Fr } from "@aztec/foundation/fields";
import { getAddress, toUtf8Bytes } from "ethers";
import { Poseidon } from "./Poseidon.js";

export { Fr };

export function toFr(value: bigint | number | string): Fr {
  return new Fr(BigInt(value));
}

/** Validates and checksums the address before conversion. */
export function addressToFr(address: string): Fr {
  return toFr(getAddress(address));
}

/** Right-aligns the UTF-8 bytes in 32 and Poseidon2-hashes; input must be <= 32 bytes. */
export async function stringToFr(text: string): Promise<Fr> {
  const bytes = toUtf8Bytes(text);
  if (bytes.length > 32) {
    throw new Error(
      "stringToFr input string is too long, must be <= 32 bytes.",
    );
  }
  const paddedBytes = Buffer.alloc(32);
  paddedBytes.set(bytes, 32 - bytes.length);
  const fieldFromBytes = Fr.fromBuffer(paddedBytes);
  return await Poseidon.hash([fieldFromBytes]);
}

/** Wide-reduce mod BN254 Fr; for >32-byte inputs (seed, signature) that would otherwise throw. */
export function toReducedFr(value: bigint | number | string): Fr {
  return new Fr(BigInt(value) % Fr.MODULUS);
}
