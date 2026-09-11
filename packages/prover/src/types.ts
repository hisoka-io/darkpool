import type { DerivedEph } from "@hisoka/wallets";
import { Fr } from "@aztec/foundation/fields";
import { Point } from "@zk-kit/baby-jubjub";

export interface NoteInput {
  noteVersion: Fr;
  assetId: Fr;
  noteType: Fr;
  conditionsHash: Fr;
  value: Fr; // u128 range-checked at the marshal boundary
  owner: Fr;
  psi: Fr;
  parents: Fr;
}

export interface DepositInputs {
  readonly compliancePk: Point<bigint>;
  readonly note: NoteInput;
  readonly eph: DerivedEph;
}

export interface WithdrawInputs {
  readonly withdrawValue: Fr;
  readonly recipient: Fr;
  readonly intentHash: Fr;
  readonly compliancePk: Point<bigint>;

  readonly oldNote: NoteInput;
  readonly spendScalar: Fr;
  readonly oldNoteIndex: number;
  readonly oldNotePath: readonly Fr[];

  readonly changeNote: NoteInput;
  readonly changeEph: DerivedEph;
}

// gpk's scalar is t-of-n shared and cannot ECDH, so viewPub carries discovery and decryption.
export interface MultisigMemoRecipient {
  gpk: Point<bigint>;
  viewPub: Point<bigint>;
}

export interface TransferInputs {
  readonly compliancePk: Point<bigint>;
  readonly recipientInPub?: Point<bigint>;
  readonly recipientMultisig?: MultisigMemoRecipient;

  readonly oldNote: NoteInput;
  readonly spendScalar: Fr;
  readonly oldNoteIndex: number;
  readonly oldNotePath: readonly Fr[];

  readonly memoNote: NoteInput;
  readonly memoEph: Fr;

  readonly changeNote: NoteInput;
  readonly changeEph: DerivedEph;
}

export interface SplitInputs {
  readonly compliancePk: Point<bigint>;

  readonly noteIn: NoteInput;
  readonly spendScalar: Fr;
  readonly indexIn: number;
  readonly pathIn: readonly Fr[];

  readonly noteOut1: NoteInput;
  readonly eph1: DerivedEph;

  readonly noteOut2: NoteInput;
  readonly eph2: DerivedEph;
}

export interface JoinInputs {
  readonly compliancePk: Point<bigint>;

  readonly noteA: NoteInput;
  readonly spendScalarA: Fr;
  readonly indexA: number;
  readonly pathA: readonly Fr[];

  readonly noteB: NoteInput;
  readonly spendScalarB: Fr;
  readonly indexB: number;
  readonly pathB: readonly Fr[];

  readonly noteOut: NoteInput;
  readonly ephOut: DerivedEph;
}

export interface PublicClaimInputs {
  readonly memoId: Fr;
  readonly compliancePk: Point<bigint>;
  readonly currentTimestamp: number;

  readonly val: Fr;
  readonly assetId: Fr;
  readonly timelock: Fr;
  readonly ownerX: Fr;
  readonly ownerY: Fr;
  readonly salt: Fr;

  readonly recipientSk: Fr;
  readonly noteOut: NoteInput;
  readonly eph: DerivedEph;
}

export interface ProofData {
  proof: Uint8Array;
  publicInputs: string[];
  verified: boolean;
}

export interface SwapIntentInputs {
  compliancePk: Point<bigint>;

  noteIn: NoteInput;
  spendScalar: Fr;
  indexIn: number;
  pathIn: Fr[];

  changeNote: NoteInput;
  changeEph: DerivedEph;

  receivedNote: NoteInput;
  receivedEph: DerivedEph;

  toAsset: Fr;
  fromAmount: Fr;
  expiry: Fr;
}

export interface SwapIntentProof {
  proof: Uint8Array;
  proofAsFields: string[];
  publicInputs: string[];
  vkAsFields: string[];
  vkHash: string;
  verified: boolean;
}

export interface SwapSettleInputs {
  compliancePk: Point<bigint>;
  currentTimestamp: Fr;

  intent: SwapIntentProof;

  makerNoteIn: NoteInput;
  makerSpendScalar: Fr;
  makerIndex: number;
  makerPath: Fr[];

  makerReceived: NoteInput;
  makerReceivedEph: DerivedEph;

  makerChange: NoteInput;
  makerChangeEph: DerivedEph;
}
