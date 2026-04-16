import { poseidon2Hash } from "@aztec/foundation/crypto";
import { Fr } from "@aztec/foundation/fields";

export class Poseidon {
  public static async hash(inputs: Fr[]): Promise<Fr> {
    if (!inputs || inputs.length === 0) {
      throw new Error("Poseidon hash requires at least one input.");
    }
    return poseidon2Hash(inputs);
  }

  public static async hashScalar(input: Fr): Promise<Fr> {
    return this.hash([input]);
  }
}
