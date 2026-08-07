import { Collection } from "./collection.js";
import { concatBytes, u64be, utf8 } from "./codec.js";
import { PssProtocolError } from "./errors.js";

// Same injective shape as the signing preimage: a length-prefixed collection then a fixed-width version.
// The collection is bound here as well as in the signature so a ciphertext moved between collections
// fails to authenticate even if it somehow reached the other slot.
export function cellAad(collection: Collection, version: number): Uint8Array {
  const name = utf8(collection);
  if (name.length > 0xff) {
    throw new PssProtocolError(`collection name too long: ${collection}`);
  }
  return concatBytes(
    Uint8Array.of(name.length),
    name,
    u64be(version, "version"),
  );
}
