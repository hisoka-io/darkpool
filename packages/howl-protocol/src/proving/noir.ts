import { fieldHexFromBigInt, type FieldHex } from "../primitives.js";
import { parseStandardCircuitIdAtPath } from "../internal/circuits.js";
import type { StandardCircuitId } from "./circuits.js";
import { parseStandardWitnessDto } from "./parse.js";
import type {
  DepositWitnessDto,
  JoinWitnessDto,
  NoteWitnessDto,
  PointWitnessDto,
  PublicClaimWitnessDto,
  SplitWitnessDto,
  StandardWitnessByCircuit,
  TransferWitnessDto,
  WithdrawWitnessDto,
} from "./witnesses.js";

type NoirInputValue =
  | string
  | number
  | boolean
  | NoirInputMap
  | NoirInputValue[];

interface NoirInputMap {
  readonly [key: string]: NoirInputValue;
}

interface NoirPointInput extends NoirInputMap {
  readonly x: string;
  readonly y: string;
}

interface NoirNoteInput extends NoirInputMap {
  readonly note_version: string;
  readonly asset_id: string;
  readonly note_type: string;
  readonly conditions_hash: string;
  readonly value: string;
  readonly owner: string;
  readonly psi: string;
  readonly parents: string;
}

interface DepositNoirInput extends NoirInputMap {
  readonly compliance_pubkey_x: string;
  readonly compliance_pubkey_y: string;
  readonly note: NoirNoteInput;
  readonly eph: string;
}

interface WithdrawNoirInput extends NoirInputMap {
  readonly withdraw_value: string;
  readonly _recipient: string;
  readonly _intent_hash: string;
  readonly compliance_pubkey_x: string;
  readonly compliance_pubkey_y: string;
  readonly old_note: NoirNoteInput;
  readonly spend_scalar: string;
  readonly old_note_index: string;
  readonly old_note_path: string[];
  readonly change_note: NoirNoteInput;
  readonly change_eph: string;
}

interface TransferNoirInput extends NoirInputMap {
  readonly compliance_pubkey_x: string;
  readonly compliance_pubkey_y: string;
  readonly recipient_spend_pub: NoirPointInput;
  readonly recipient_view_pub: NoirPointInput;
  readonly old_note: NoirNoteInput;
  readonly spend_scalar: string;
  readonly old_note_index: string;
  readonly old_note_path: string[];
  readonly memo_note: NoirNoteInput;
  readonly memo_eph: string;
  readonly change_note: NoirNoteInput;
  readonly change_eph: string;
}

interface SplitNoirInput extends NoirInputMap {
  readonly compliance_pubkey_x: string;
  readonly compliance_pubkey_y: string;
  readonly note_in: NoirNoteInput;
  readonly spend_scalar: string;
  readonly index_in: string;
  readonly path_in: string[];
  readonly note_out_1: NoirNoteInput;
  readonly eph_1: string;
  readonly note_out_2: NoirNoteInput;
  readonly eph_2: string;
}

interface JoinNoirInput extends NoirInputMap {
  readonly compliance_pubkey_x: string;
  readonly compliance_pubkey_y: string;
  readonly note_a: NoirNoteInput;
  readonly spend_scalar_a: string;
  readonly index_a: string;
  readonly path_a: string[];
  readonly note_b: NoirNoteInput;
  readonly spend_scalar_b: string;
  readonly index_b: string;
  readonly path_b: string[];
  readonly note_out: NoirNoteInput;
  readonly eph_out: string;
}

interface PublicClaimNoirInput extends NoirInputMap {
  readonly memo_id: string;
  readonly compliance_pubkey_x: string;
  readonly compliance_pubkey_y: string;
  readonly current_timestamp: string;
  readonly val: string;
  readonly asset_id: string;
  readonly timelock: string;
  readonly owner_x: string;
  readonly owner_y: string;
  readonly salt: string;
  readonly recipient_sk: string;
  readonly note_out: NoirNoteInput;
  readonly eph: string;
}

export interface StandardNoirInputByCircuit {
  readonly deposit: DepositNoirInput;
  readonly withdraw: WithdrawNoirInput;
  readonly transfer: TransferNoirInput;
  readonly split: SplitNoirInput;
  readonly join: JoinNoirInput;
  readonly public_claim: PublicClaimNoirInput;
}

function decimalField(value: string): FieldHex {
  return fieldHexFromBigInt(BigInt(value));
}

function pointCoordinate(value: FieldHex): string {
  return `0x${BigInt(value).toString(16)}`;
}

function noirPoint(point: PointWitnessDto): NoirPointInput {
  return {
    x: pointCoordinate(point.x),
    y: pointCoordinate(point.y),
  };
}

function noirNote(note: NoteWitnessDto): NoirNoteInput {
  return {
    note_version: note.note_version,
    asset_id: note.asset_id,
    note_type: note.note_type,
    conditions_hash: note.conditions_hash,
    value: decimalField(note.value),
    owner: note.owner,
    psi: note.psi,
    parents: note.parents,
  };
}

function depositNoirInput(witness: DepositWitnessDto): DepositNoirInput {
  return {
    compliance_pubkey_x: pointCoordinate(witness.compliance_pubkey_x),
    compliance_pubkey_y: pointCoordinate(witness.compliance_pubkey_y),
    note: noirNote(witness.note),
    eph: witness.eph,
  };
}

function withdrawNoirInput(witness: WithdrawWitnessDto): WithdrawNoirInput {
  return {
    withdraw_value: decimalField(witness.withdraw_value),
    _recipient: witness._recipient,
    _intent_hash: witness._intent_hash,
    compliance_pubkey_x: pointCoordinate(witness.compliance_pubkey_x),
    compliance_pubkey_y: pointCoordinate(witness.compliance_pubkey_y),
    old_note: noirNote(witness.old_note),
    spend_scalar: witness.spend_scalar,
    old_note_index: witness.old_note_index,
    old_note_path: [...witness.old_note_path],
    change_note: noirNote(witness.change_note),
    change_eph: witness.change_eph,
  };
}

function transferNoirInput(witness: TransferWitnessDto): TransferNoirInput {
  return {
    compliance_pubkey_x: pointCoordinate(witness.compliance_pubkey_x),
    compliance_pubkey_y: pointCoordinate(witness.compliance_pubkey_y),
    recipient_spend_pub: noirPoint(witness.recipient_spend_pub),
    recipient_view_pub: noirPoint(witness.recipient_view_pub),
    old_note: noirNote(witness.old_note),
    spend_scalar: witness.spend_scalar,
    old_note_index: witness.old_note_index,
    old_note_path: [...witness.old_note_path],
    memo_note: noirNote(witness.memo_note),
    memo_eph: witness.memo_eph,
    change_note: noirNote(witness.change_note),
    change_eph: witness.change_eph,
  };
}

function splitNoirInput(witness: SplitWitnessDto): SplitNoirInput {
  return {
    compliance_pubkey_x: pointCoordinate(witness.compliance_pubkey_x),
    compliance_pubkey_y: pointCoordinate(witness.compliance_pubkey_y),
    note_in: noirNote(witness.note_in),
    spend_scalar: witness.spend_scalar,
    index_in: witness.index_in,
    path_in: [...witness.path_in],
    note_out_1: noirNote(witness.note_out_1),
    eph_1: witness.eph_1,
    note_out_2: noirNote(witness.note_out_2),
    eph_2: witness.eph_2,
  };
}

function joinNoirInput(witness: JoinWitnessDto): JoinNoirInput {
  return {
    compliance_pubkey_x: pointCoordinate(witness.compliance_pubkey_x),
    compliance_pubkey_y: pointCoordinate(witness.compliance_pubkey_y),
    note_a: noirNote(witness.note_a),
    spend_scalar_a: witness.spend_scalar_a,
    index_a: witness.index_a,
    path_a: [...witness.path_a],
    note_b: noirNote(witness.note_b),
    spend_scalar_b: witness.spend_scalar_b,
    index_b: witness.index_b,
    path_b: [...witness.path_b],
    note_out: noirNote(witness.note_out),
    eph_out: witness.eph_out,
  };
}

function publicClaimNoirInput(
  witness: PublicClaimWitnessDto,
): PublicClaimNoirInput {
  return {
    memo_id: witness.memo_id,
    compliance_pubkey_x: pointCoordinate(witness.compliance_pubkey_x),
    compliance_pubkey_y: pointCoordinate(witness.compliance_pubkey_y),
    current_timestamp: witness.current_timestamp,
    val: decimalField(witness.val),
    asset_id: witness.asset_id,
    timelock: decimalField(witness.timelock),
    owner_x: witness.owner_x,
    owner_y: witness.owner_y,
    salt: witness.salt,
    recipient_sk: witness.recipient_sk,
    note_out: noirNote(witness.note_out),
    eph: witness.eph,
  };
}

type StandardNoirInput = StandardNoirInputByCircuit[StandardCircuitId];

function unsupportedStandardCircuit(circuit: never): never {
  void circuit;
  throw new Error("unreachable standard circuit dispatch");
}

export function standardWitnessDtoToNoirInput<C extends StandardCircuitId>(
  circuit: C,
  witness: StandardWitnessByCircuit[C],
): StandardNoirInputByCircuit[C];
export function standardWitnessDtoToNoirInput(
  circuit: StandardCircuitId,
  witness: StandardWitnessByCircuit[StandardCircuitId],
): StandardNoirInput {
  const validatedCircuit = parseStandardCircuitIdAtPath(circuit, "$");
  switch (validatedCircuit) {
    case "deposit":
      return depositNoirInput(parseStandardWitnessDto("deposit", witness));
    case "withdraw":
      return withdrawNoirInput(parseStandardWitnessDto("withdraw", witness));
    case "transfer":
      return transferNoirInput(parseStandardWitnessDto("transfer", witness));
    case "split":
      return splitNoirInput(parseStandardWitnessDto("split", witness));
    case "join":
      return joinNoirInput(parseStandardWitnessDto("join", witness));
    case "public_claim":
      return publicClaimNoirInput(
        parseStandardWitnessDto("public_claim", witness),
      );
    default:
      return unsupportedStandardCircuit(validatedCircuit);
  }
}
