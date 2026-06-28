import { Fr } from "@aztec/foundation/fields";
import { WalletNote } from "./state/types.js";

export interface KeyRepoState {
  nextEphemeralNonce: number;
  ephemeralIndex: number;
  incomingIndex: number;
  highestMatchedEphemeral: number;
  highestMatchedIncoming: number;
}

export interface IKeyRepository {
  readonly ephemeralIndex: number;
  readonly incomingIndex: number;

  getNullifyingKey(): Promise<Fr>;
  nextEphemeralParams(): Promise<{ sk: Fr; nonce: Fr }>;
  advanceEphemeralKeys(count?: number): Promise<void>;
  advanceIncomingKeys(count?: number): Promise<void>;

  ensureEphemeralLookahead(window: number): Promise<boolean>;
  ensureIncomingLookahead(window: number): Promise<boolean>;

  tryMatchDeposit(
    epkX: bigint | string,
    epkY: bigint | string,
  ): { key: Fr; index: number } | null;
  tryMatchTransfer(
    tagPx: bigint | string,
  ): { key: bigint; index: number } | null;

  getAllTags(): string[];

  getState(): KeyRepoState;
  restore(state: KeyRepoState): Promise<void>;
}

export interface IUtxoRepository {
  addNote(note: WalletNote): Promise<void>;
  markSpent(nullifier: string | Fr): boolean;
  getUnspentNotes(): WalletNote[];
  getAllNotes(): WalletNote[];
  getBalance(assetId?: Fr | bigint | string): bigint;
}
