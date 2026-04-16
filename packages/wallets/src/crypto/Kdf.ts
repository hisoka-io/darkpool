import { Fr } from "@aztec/foundation/fields";
import { Poseidon } from "./Poseidon.js";
import { stringToFr } from "./fields.js";

/** Domain-separated Poseidon2 key derivation. */
export class Kdf {
  public static async derive(
    purpose: string,
    master: Fr,
    nonce?: Fr,
  ): Promise<Fr> {
    const purposeFr = await stringToFr(purpose);
    const inputs = [master, purposeFr];

    // Nonce=0 and absent nonce produce the same hash (2-input Poseidon).
    // This is intentional: the first ephemeral key (nonce=0) uses the same
    // derivation path as nonceless keys. Domain-separated purpose strings
    // prevent cross-path collisions.
    if (nonce && !nonce.isZero()) {
      inputs.push(nonce);
    }

    return await Poseidon.hash(inputs);
  }
}
