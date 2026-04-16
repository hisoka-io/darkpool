import { Fr } from "@aztec/foundation/fields";
import { Poseidon } from "../crypto/Poseidon.js";
import { IUTXO } from "../interfaces.js";
import { getAddress } from "ethers";
import { NotePlaintext } from "../crypto/index.js";

export class Note implements IUTXO {
  constructor(public readonly plaintext: NotePlaintext) {
    if (plaintext.value.toBigInt() < 0n) {
      throw new Error("Note value cannot be negative.");
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

  public async getNullifierHash(): Promise<Fr> {
    return await Poseidon.hashScalar(this.plaintext.nullifier);
  }
}
