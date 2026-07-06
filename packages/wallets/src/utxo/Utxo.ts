import { Fr } from "@aztec/foundation/fields";
import { getAddress } from "ethers";
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

    const addressBytes = note.assetId.toBuffer().slice(FR_TO_ADDRESS_OFFSET);
    const addressString = "0x" + Buffer.from(addressBytes).toString("hex");
    try {
      getAddress(addressString);
    } catch {
      throw new Error("Invalid assetID");
    }
  }

  public async getNullifierHash(
    psi: Fr,
    leafIndex: number | bigint,
  ): Promise<Fr> {
    return computeNullifier(psi, new Fr(BigInt(leafIndex)));
  }
}
