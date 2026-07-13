import { WalletNote } from "../state/types.js";

export interface UnprocessedEvent {
  type: "NEW_NOTE" | "NEW_MEMO";
  blockNumber: number;
  txHash: string;
  args: {
    leafIndex: bigint;
    commitment: string;
    ephemeralX: bigint;
    packedCiphertext: string[];
    // NEW_MEMO only: tag == in_pub_j.x, cekWrap wraps the content key to the recipient.
    tag?: bigint;
    cekWrap?: bigint;
  };
}

export interface SyncResult {
  newNotes: WalletNote[];
  lastBlockProcessed: number;
}
