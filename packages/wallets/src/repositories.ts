import { Fr } from "@aztec/foundation/fields";
import { WalletNote } from "./state/types.js";

export interface IKeyRepository {
  readonly ephemeralIndex: number;
  readonly incomingIndex: number;

  nextEphemeralParams(): Promise<{ sk: Fr; nonce: Fr }>;
  advanceEphemeralKeys(count?: number): Promise<void>;
  advanceIncomingKeys(count?: number): Promise<void>;

  tryMatchDeposit(
    epkX: bigint | string,
    epkY: bigint | string,
  ): { key: Fr; index: number } | null;
  tryMatchTransfer(
    tagPx: bigint | string,
  ): { key: bigint; index: number } | null;

  getAllTags(): string[];
}

export interface IUtxoRepository {
  addNote(note: WalletNote): Promise<void>;
  markSpent(nullifier: string | Fr): boolean;
  getUnspentNotes(): WalletNote[];
  getAllNotes(): WalletNote[];
  getBalance(assetId?: string): bigint;
}
