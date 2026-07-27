import { Fr } from "@aztec/foundation/fields";
import { Point } from "@zk-kit/baby-jubjub";
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

/** A `publicTransfer` escrow recognised as payable to this wallet, carrying the public_claim witness. */
export interface DiscoveredPublicMemo {
  memoId: Fr;
  ownerIndex: bigint;
  ownerPub: Point<bigint>;
  recipientSk: Fr;
  asset: string;
  assetId: Fr;
  value: bigint;
  timelock: bigint;
  salt: Fr;
  spent: boolean;
  matured: boolean;
  claimable: boolean;
  blockNumber: number;
  logIndex: number;
  txHash: string;
}
