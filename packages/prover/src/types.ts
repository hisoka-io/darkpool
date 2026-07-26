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
  eph: Fr;
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
  changeEph: Fr;
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
  changeEph: Fr;
}

export interface SplitInputs {
  compliancePk: Point<bigint>;

  noteIn: NoteInput;
  spendScalar: Fr;
  indexIn: number;
  pathIn: Fr[];

  noteOut1: NoteInput;
  eph1: Fr;

  noteOut2: NoteInput;
  eph2: Fr;
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
  ephOut: Fr;
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
  eph: Fr;
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
  changeEph: Fr;

  receivedNote: NoteInput;
  receivedEph: Fr;

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
  makerReceivedEph: Fr;

  makerChange: NoteInput;
  makerChangeEph: Fr;
}
