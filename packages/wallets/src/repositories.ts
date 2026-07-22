import { Fr } from "@aztec/foundation/fields";
import { Point } from "@zk-kit/baby-jubjub";
import { WalletNote } from "./state/types.js";

export interface KeyRepoState {
  // Persist before mint: a reused self-eph index is a two-time-pad on the DEM keystream.
  selfMintCounter: number;
  selfScanIndex: number;
  incomingIssueCounter: number;
  incomingScanIndex: number;
  highestMatchedSelf: number;
  highestMatchedIncoming: number;
}

export interface SelfEphemeral {
  eph: Fr;
  ephPub: Point<bigint>;
  index: number;
}

export interface IncomingAddress {
  inKey: Fr;
  inPub: Point<bigint>;
  index: number;
}

export interface IKeyRepository {
  readonly selfScanIndex: number;
  readonly incomingScanIndex: number;

  nextSelfEphemeral(): Promise<SelfEphemeral>;
  nextIncomingAddress(): Promise<IncomingAddress>;

  getSelfSpendScalar(): Promise<Fr>;
  getSelfSpendPub(): Promise<Point<bigint>>;

  ensureSelfLookahead(window: number): Promise<boolean>;
  ensureIncomingLookahead(window: number): Promise<boolean>;

  matchSelfTag(tag: bigint | string): { eph: Fr; index: number } | null;
  matchIncomingTag(tag: bigint | string): { inKey: Fr; index: number } | null;
  recordIncomingMatch(index: number): void;

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
