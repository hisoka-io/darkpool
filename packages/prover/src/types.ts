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
  compliancePk: Point<bigint>;
  note: NoteInput;
  eph: DerivedEph;
}

export interface WithdrawInputs {
  withdrawValue: Fr;
  recipient: Fr;
  intentHash: Fr;
  compliancePk: Point<bigint>;

  oldNote: NoteInput;
  spendScalar: Fr;
  oldNoteIndex: number;
  oldNotePath: Fr[];

  changeNote: NoteInput;
  changeEph: DerivedEph;
}

// gpk's scalar is t-of-n shared and cannot ECDH, so viewPub carries discovery and decryption.
export interface MultisigMemoRecipient {
  gpk: Point<bigint>;
  viewPub: Point<bigint>;
}

export interface TransferInputs {
  compliancePk: Point<bigint>;
  recipientInPub?: Point<bigint>;
  recipientMultisig?: MultisigMemoRecipient;

  oldNote: NoteInput;
  spendScalar: Fr;
  oldNoteIndex: number;
  oldNotePath: Fr[];

  memoNote: NoteInput;
  memoEph: Fr;

  changeNote: NoteInput;
  changeEph: DerivedEph;
}

export interface SplitInputs {
  compliancePk: Point<bigint>;

  noteIn: NoteInput;
  spendScalar: Fr;
  indexIn: number;
  pathIn: Fr[];

  noteOut1: NoteInput;
  eph1: DerivedEph;

  noteOut2: NoteInput;
  eph2: DerivedEph;
}

export interface JoinInputs {
  compliancePk: Point<bigint>;

  noteA: NoteInput;
  spendScalarA: Fr;
  indexA: number;
  pathA: Fr[];

  noteB: NoteInput;
  spendScalarB: Fr;
  indexB: number;
  pathB: Fr[];

  noteOut: NoteInput;
  ephOut: DerivedEph;
}

export interface PublicClaimInputs {
  memoId: Fr;
  compliancePk: Point<bigint>;
  currentTimestamp: number;

  val: Fr;
  assetId: Fr;
  timelock: Fr;
  ownerX: Fr;
  ownerY: Fr;
  salt: Fr;

  recipientSk: Fr;
  noteOut: NoteInput;
  eph: DerivedEph;
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
