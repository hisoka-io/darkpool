import { Fr } from "@aztec/foundation/fields";
import { Note } from "../note/note.js";

export interface WalletNote {
  note: Note;
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
