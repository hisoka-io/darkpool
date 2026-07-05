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

    // Intentional: nonce=0 and absent nonce collapse to the same 2-input hash.
    if (nonce && !nonce.isZero()) {
      inputs.push(nonce);
    }

    return await Poseidon.hash(inputs);
  }
}
