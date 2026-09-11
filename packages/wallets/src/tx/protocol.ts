import {
  fieldHexFromBigInt,
  parseUint32Decimal,
  parseUint64Decimal,
  parseUint128Decimal,
} from "@hisoka/howl-protocol";
import type {
  NoteWitnessDto,
  PointWitnessDto,
  StandardCircuitId,
  StandardWitnessByCircuit,
} from "@hisoka/howl-protocol/proving";
import { Fr } from "@aztec/foundation/fields";
import type { Point } from "@zk-kit/baby-jubjub";
import { toBjjScalar } from "../crypto/index.js";
import { NOTE_TYPE_MULTISIG } from "../note/note.js";
import type {
  ProverNoteInput,
  PublicClaimWitness,
} from "../public/publicClaim.js";
import type { DerivedEph } from "../types/ephemeral.js";

export interface DepositWitness {
  readonly compliancePk: Point<bigint>;
  readonly note: ProverNoteInput;
  readonly eph: DerivedEph;
}

export interface WithdrawWitness {
  readonly withdrawValue: Fr;
  readonly recipient: Fr;
  readonly intentHash: Fr;
  readonly compliancePk: Point<bigint>;
  readonly oldNote: ProverNoteInput;
  readonly spendScalar: Fr;
  readonly oldNoteIndex: number;
  readonly oldNotePath: readonly Fr[];
  readonly changeNote: ProverNoteInput;
  readonly changeEph: DerivedEph;
}

export interface MultisigMemoRecipient {
  readonly gpk: Point<bigint>;
  readonly viewPub: Point<bigint>;
}

export interface TransferWitness {
  readonly compliancePk: Point<bigint>;
  readonly recipientInPub?: Point<bigint>;
  readonly recipientMultisig?: MultisigMemoRecipient;
  readonly oldNote: ProverNoteInput;
  readonly spendScalar: Fr;
  readonly oldNoteIndex: number;
  readonly oldNotePath: readonly Fr[];
  readonly memoNote: ProverNoteInput;
  readonly memoEph: Fr;
  readonly changeNote: ProverNoteInput;
  readonly changeEph: DerivedEph;
}

export type AssembledTransferWitness = Omit<
  TransferWitness,
  "recipientInPub" | "recipientMultisig"
> & {
  readonly recipientInPub: Point<bigint>;
  readonly recipientMultisig?: never;
};

export interface SplitWitness {
  readonly compliancePk: Point<bigint>;
  readonly noteIn: ProverNoteInput;
  readonly spendScalar: Fr;
  readonly indexIn: number;
  readonly pathIn: readonly Fr[];
  readonly noteOut1: ProverNoteInput;
  readonly eph1: DerivedEph;
  readonly noteOut2: ProverNoteInput;
  readonly eph2: DerivedEph;
}

export interface JoinWitness {
  readonly compliancePk: Point<bigint>;
  readonly noteA: ProverNoteInput;
  readonly spendScalarA: Fr;
  readonly indexA: number;
  readonly pathA: readonly Fr[];
  readonly noteB: ProverNoteInput;
  readonly spendScalarB: Fr;
  readonly indexB: number;
  readonly pathB: readonly Fr[];
  readonly noteOut: ProverNoteInput;
  readonly ephOut: DerivedEph;
}

export interface NativeStandardWitnessByCircuit {
  readonly deposit: DepositWitness;
  readonly withdraw: WithdrawWitness;
  readonly transfer: TransferWitness;
  readonly split: SplitWitness;
  readonly join: JoinWitness;
  readonly public_claim: PublicClaimWitness;
}

function field(value: Fr) {
  return fieldHexFromBigInt(value.toBigInt());
}

function point(value: Point<bigint>): PointWitnessDto {
  return {
    x: fieldHexFromBigInt(value[0]),
    y: fieldHexFromBigInt(value[1]),
  };
}

function note(value: ProverNoteInput): NoteWitnessDto {
  return {
    note_version: field(value.noteVersion),
    asset_id: field(value.assetId),
    note_type: field(value.noteType),
    conditions_hash: field(value.conditionsHash),
    value: parseUint128Decimal(value.value.toBigInt().toString()),
    owner: field(value.owner),
    psi: field(value.psi),
    parents: field(value.parents),
  };
}

function path(value: readonly Fr[]) {
  return value.map(field);
}

function depositDto(witness: DepositWitness) {
  const compliance = point(witness.compliancePk);
  return {
    compliance_pubkey_x: compliance.x,
    compliance_pubkey_y: compliance.y,
    note: note(witness.note),
    eph: field(witness.eph),
  };
}

function withdrawDto(witness: WithdrawWitness) {
  const compliance = point(witness.compliancePk);
  return {
    withdraw_value: parseUint128Decimal(
      witness.withdrawValue.toBigInt().toString(),
    ),
    _recipient: field(witness.recipient),
    _intent_hash: field(witness.intentHash),
    compliance_pubkey_x: compliance.x,
    compliance_pubkey_y: compliance.y,
    old_note: note(witness.oldNote),
    spend_scalar: field(witness.spendScalar),
    old_note_index: parseUint32Decimal(witness.oldNoteIndex.toString()),
    old_note_path: path(witness.oldNotePath),
    change_note: note(witness.changeNote),
    change_eph: field(witness.changeEph),
  };
}

function transferRecipient(witness: TransferWitness): {
  readonly spend: Point<bigint>;
  readonly view: Point<bigint>;
} {
  const wantsMultisig =
    witness.memoNote.noteType.toBigInt() === NOTE_TYPE_MULTISIG;
  if (witness.recipientMultisig !== undefined) {
    if (witness.recipientInPub !== undefined) {
      throw new Error(
        "invalid input for transfer: memo recipient: pass recipientInPub or recipientMultisig, never both",
      );
    }
    if (!wantsMultisig) {
      throw new Error(
        "invalid input for transfer: memo recipient: recipientMultisig requires the memo note_type to be MULTISIG",
      );
    }
    if (
      witness.recipientMultisig.gpk[0] === witness.recipientMultisig.viewPub[0]
    ) {
      throw new Error(
        "invalid input for transfer: memo recipient: recipientMultisig gpk and viewPub must not share x, a MULTISIG memo decouples spend from view",
      );
    }
    return {
      spend: witness.recipientMultisig.gpk,
      view: witness.recipientMultisig.viewPub,
    };
  }
  if (witness.recipientInPub === undefined) {
    throw new Error(
      "invalid input for transfer: memo recipient: recipientInPub or recipientMultisig is required",
    );
  }
  if (wantsMultisig) {
    throw new Error(
      "invalid input for transfer: memo recipient: a MULTISIG memo requires recipientMultisig (owner and view must decouple)",
    );
  }
  return { spend: witness.recipientInPub, view: witness.recipientInPub };
}

function transferDto(witness: TransferWitness) {
  const compliance = point(witness.compliancePk);
  const recipient = transferRecipient(witness);
  return {
    compliance_pubkey_x: compliance.x,
    compliance_pubkey_y: compliance.y,
    recipient_spend_pub: point(recipient.spend),
    recipient_view_pub: point(recipient.view),
    old_note: note(witness.oldNote),
    spend_scalar: field(witness.spendScalar),
    old_note_index: parseUint32Decimal(witness.oldNoteIndex.toString()),
    old_note_path: path(witness.oldNotePath),
    memo_note: note(witness.memoNote),
    memo_eph: field(witness.memoEph),
    change_note: note(witness.changeNote),
    change_eph: field(witness.changeEph),
  };
}

function splitDto(witness: SplitWitness) {
  const compliance = point(witness.compliancePk);
  return {
    compliance_pubkey_x: compliance.x,
    compliance_pubkey_y: compliance.y,
    note_in: note(witness.noteIn),
    spend_scalar: field(witness.spendScalar),
    index_in: parseUint32Decimal(witness.indexIn.toString()),
    path_in: path(witness.pathIn),
    note_out_1: note(witness.noteOut1),
    eph_1: field(witness.eph1),
    note_out_2: note(witness.noteOut2),
    eph_2: field(witness.eph2),
  };
}

function joinDto(witness: JoinWitness) {
  const compliance = point(witness.compliancePk);
  return {
    compliance_pubkey_x: compliance.x,
    compliance_pubkey_y: compliance.y,
    note_a: note(witness.noteA),
    spend_scalar_a: field(witness.spendScalarA),
    index_a: parseUint32Decimal(witness.indexA.toString()),
    path_a: path(witness.pathA),
    note_b: note(witness.noteB),
    spend_scalar_b: field(witness.spendScalarB),
    index_b: parseUint32Decimal(witness.indexB.toString()),
    path_b: path(witness.pathB),
    note_out: note(witness.noteOut),
    eph_out: field(witness.ephOut),
  };
}

function publicClaimDto(witness: PublicClaimWitness) {
  const compliance = point(witness.compliancePk);
  return {
    memo_id: field(witness.memoId),
    compliance_pubkey_x: compliance.x,
    compliance_pubkey_y: compliance.y,
    current_timestamp: parseUint64Decimal(witness.currentTimestamp.toString()),
    val: parseUint128Decimal(witness.val.toBigInt().toString()),
    asset_id: field(witness.assetId),
    timelock: parseUint64Decimal(witness.timelock.toBigInt().toString()),
    owner_x: field(witness.ownerX),
    owner_y: field(witness.ownerY),
    salt: field(witness.salt),
    recipient_sk: field(toBjjScalar(witness.recipientSk)),
    note_out: note(witness.noteOut),
    eph: field(witness.eph),
  };
}

export function toStandardWitnessDto<C extends StandardCircuitId>(
  circuit: C,
  witness: NativeStandardWitnessByCircuit[C],
): StandardWitnessByCircuit[C];
export function toStandardWitnessDto(
  circuit: StandardCircuitId,
  witness: NativeStandardWitnessByCircuit[StandardCircuitId],
): StandardWitnessByCircuit[StandardCircuitId] {
  switch (circuit) {
    case "deposit":
      return depositDto(witness as DepositWitness);
    case "withdraw":
      return withdrawDto(witness as WithdrawWitness);
    case "transfer":
      return transferDto(witness as TransferWitness);
    case "split":
      return splitDto(witness as SplitWitness);
    case "join":
      return joinDto(witness as JoinWitness);
    case "public_claim":
      return publicClaimDto(witness as PublicClaimWitness);
    default:
      throw new Error("invalid standard circuit for native witness conversion");
  }
}
