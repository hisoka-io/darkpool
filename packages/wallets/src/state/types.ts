import { Fr } from "@aztec/foundation/fields";
import { NotePlaintext } from "../crypto/types.js";

export interface WalletNote {
  note: NotePlaintext;
  commitment: Fr;
  leafIndex: number;
  nullifier: Fr;
  spendingSecret: Fr;
  isTransfer: boolean;
  derivationIndex: number;
  spent: boolean;
}

export interface KeyPair {
  index: number;
  privateKey: Fr;
  publicKey: { x: bigint; y: bigint }; // Point structure
}
