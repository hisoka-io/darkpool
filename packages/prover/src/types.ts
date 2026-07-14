import { Fr } from "@aztec/foundation/fields";
import { Point } from "@zk-kit/baby-jubjub";

// Marshaled to the circuit's note::Note struct.
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

export interface TransferInputs {
  compliancePk: Point<bigint>;
  // recipientInPub is the single owner+view+discovery key; paying a MULTISIG account (owner != view) is
  // deferred, so one key binds all three.
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

// Kage taker half (swap_intent, inner): spend the taker input, mint the taker's change + received self-notes.
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
  fromAmount: Fr; // u128 range-checked at the marshal boundary
  expiry: Fr;
}

// swap_intent's recursion artifacts, consumed as witness by swap_settle's std::verify_proof_with_type.
export interface SwapIntentProof {
  proof: Uint8Array;
  proofAsFields: string[]; // INTENT_PROOF_LEN
  publicInputs: string[]; // INTENT_PI_LEN
  vkAsFields: string[]; // INTENT_VK_LEN
  vkHash: string;
  verified: boolean;
}

// Kage maker half (swap_settle, outer): verify the taker's proof inside, spend the maker input, mint the maker's
// received + change self-notes.
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
