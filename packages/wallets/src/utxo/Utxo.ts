import { Fr } from "@aztec/foundation/fields";
import { IUTXO } from "../interfaces.js";
import { Note } from "../note/note.js";
import { computeNullifier } from "../note/nullifier.js";

const TWO_POW_128 = 1n << 128n;
// 32-byte Fr minus 20-byte EVM address leaves 12 leading zero bytes.
const FR_TO_ADDRESS_OFFSET = 12;

export class Utxo implements IUTXO {
  constructor(public readonly note: Note) {
    if (note.value < 0n || note.value >= TWO_POW_128) {
      throw new Error("Note value out of u128 range.");
    }
    if (note.owner.isZero()) {
      throw new Error("Note owner (spend-key commitment) must be non-zero.");
    }

    // The circuit constrains asset_id to an EVM address, so the only failure this can see is a field
    // wider than 160 bits. Validating the low 20 bytes cannot detect that (every 20-byte string is a
    // well-formed address); the high 12 bytes are what carries the invariant.
    const high = note.assetId.toBuffer().subarray(0, FR_TO_ADDRESS_OFFSET);
    if (high.some((b) => b !== 0)) {
      throw new Error(
        `Invalid assetID: ${note.assetId.toString()} exceeds 160 bits (not an EVM address).`,
      );
    }
  }

  public async getNullifierHash(
    psi: Fr,
    leafIndex: number | bigint,
  ): Promise<Fr> {
    return computeNullifier(psi, new Fr(BigInt(leafIndex)));
  }
}
