import { Fr } from "@aztec/foundation/fields";
import { deriveNullifier } from "../crypto/nullifier.js";
import { IUTXO } from "../interfaces.js";
import { getAddress } from "ethers";
import { NotePlaintext } from "../crypto/index.js";

export class Note implements IUTXO {
  constructor(public readonly plaintext: NotePlaintext) {
    if (plaintext.value.toBigInt() < 0n) {
      throw new Error("Note value cannot be negative.");
    }

    if (plaintext.owner.isZero()) {
      throw new Error("Note owner (spend-key commitment) must be non-zero.");
    }

    const fullBuffer = plaintext.asset_id.toBuffer();
    // 32-byte Fr field element minus 20-byte EVM address = 12 leading zero bytes
    const FR_TO_ADDRESS_OFFSET = 12;
    const addressBytes = fullBuffer.slice(FR_TO_ADDRESS_OFFSET);
    const addressString = "0x" + Buffer.from(addressBytes).toString("hex");

    try {
      getAddress(addressString);
    } catch {
      throw new Error("Invalid assetID");
    }
  }

  public async getNullifierHash(
    nk: Fr,
    commitment: Fr,
    leafIndex: number | bigint,
  ): Promise<Fr> {
    return await deriveNullifier(nk, commitment, leafIndex);
  }
}
