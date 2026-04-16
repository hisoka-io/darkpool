import { Fr } from "@aztec/foundation/fields";
import { getAddress, toUtf8Bytes } from "ethers";
import { Poseidon } from "./Poseidon.js";

export { Fr };

/** Converts to Fr field element. */
export function toFr(value: bigint | number | string): Fr {
  return new Fr(BigInt(value));
}

/** Converts an Ethereum address to Fr (validates and checksums first). */
export function addressToFr(address: string): Fr {
  return toFr(getAddress(address));
}

/** Converts a string to Fr via Poseidon hash. Input must be <= 32 bytes. */
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

/** Converts to Fr with modular reduction. */
export function toReducedFr(value: bigint | number | string): Fr {
  return new Fr(BigInt(value) % Fr.MODULUS);
}
