import { WalletNote } from "../state/types.js";

export interface UnprocessedEvent {
  type: "NEW_NOTE" | "NEW_MEMO";
  blockNumber: number;
  txHash: string;
  args: {
    leafIndex: bigint;
    commitment: string;

    epkX: bigint;
    epkY: bigint;
    packedCiphertext: string[];
    tag?: bigint;
    intermediateBobX?: bigint;
    intermediateBobY?: bigint;
  };
}

export interface SyncResult {
  newNotes: WalletNote[];
  lastBlockProcessed: number;
}
