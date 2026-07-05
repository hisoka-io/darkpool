import { Fr } from "@aztec/foundation/fields";
import { subOrder } from "@zk-kit/baby-jubjub";
import { Poseidon } from "./Poseidon.js";

// ScalarField<63> only supports scalars < 2^252, so reduce below the BabyJubJub subgroup order before use.
export function toBjjScalar(fr: Fr): Fr {
  return new Fr(fr.toBigInt() % subOrder);
}

export * from "./fields.js";
export * from "./Poseidon.js";
export * from "./dem.js";
export * from "./kem.js";
export * from "./Kdf.js";
export * from "./constants.js";

// Byte-identical to DarkPool.publicTransfer and the public_claim circuit (6 fields, no claimer owner).
export async function calculatePublicMemoId(
  val: Fr,
  asset: Fr,
  timelock: Fr,
  ownerX: Fr,
  ownerY: Fr,
  salt: Fr,
): Promise<Fr> {
  return Poseidon.hash([val, asset, timelock, ownerX, ownerY, salt]);
}
