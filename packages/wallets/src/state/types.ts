import { Fr } from "@aztec/foundation/fields";
import { NoteV2 } from "../note/noteV2.js";

export interface WalletNote {
  note: NoteV2;
  commitment: Fr;
  leafIndex: number;
  nullifier: Fr;
  spendScalar: Fr;
  isIncoming: boolean;
  derivationIndex: number | bigint;
  spent: boolean;
}

export interface KeyPair {
  index: number;
  privateKey: Fr;
  publicKey: { x: bigint; y: bigint };
}
