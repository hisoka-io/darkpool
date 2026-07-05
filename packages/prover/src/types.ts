import { Fr } from "@aztec/foundation/fields";
import { Point } from "@zk-kit/baby-jubjub";

// Marshaled to the circuit's note_v2::Note struct.
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
  currentTimestamp: number;
  intentHash: Fr;
  compliancePk: Point<bigint>;

  oldNote: NoteInput;
  spendScalar: Fr;
  oldNoteIndex: number;
  oldNotePath: Fr[];

  changeNote: NoteInput;
  changeEph: Fr;
}

export interface TransferInputs {
  currentTimestamp: number;
  compliancePk: Point<bigint>;
  recipientInPub: Point<bigint>;

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
  currentTimestamp: number;
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
  currentTimestamp: number;
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
