import type {
  FieldHex,
  Uint128Decimal,
  Uint32Decimal,
  Uint64Decimal,
} from "../primitives.js";

export interface PointWitnessDto {
  readonly x: FieldHex;
  readonly y: FieldHex;
}

export interface NoteWitnessDto {
  readonly note_version: FieldHex;
  readonly asset_id: FieldHex;
  readonly note_type: FieldHex;
  readonly conditions_hash: FieldHex;
  readonly value: Uint128Decimal;
  readonly owner: FieldHex;
  readonly psi: FieldHex;
  readonly parents: FieldHex;
}

export type MerklePathDto = readonly FieldHex[];

export interface DepositWitnessDto {
  readonly compliance_pubkey_x: FieldHex;
  readonly compliance_pubkey_y: FieldHex;
  readonly note: NoteWitnessDto;
  readonly eph: FieldHex;
}

export interface WithdrawWitnessDto {
  readonly withdraw_value: Uint128Decimal;
  readonly _recipient: FieldHex;
  readonly _intent_hash: FieldHex;
  readonly compliance_pubkey_x: FieldHex;
  readonly compliance_pubkey_y: FieldHex;
  readonly old_note: NoteWitnessDto;
  readonly spend_scalar: FieldHex;
  readonly old_note_index: Uint32Decimal;
  readonly old_note_path: MerklePathDto;
  readonly change_note: NoteWitnessDto;
  readonly change_eph: FieldHex;
}

export interface TransferWitnessDto {
  readonly compliance_pubkey_x: FieldHex;
  readonly compliance_pubkey_y: FieldHex;
  readonly recipient_spend_pub: PointWitnessDto;
  readonly recipient_view_pub: PointWitnessDto;
  readonly old_note: NoteWitnessDto;
  readonly spend_scalar: FieldHex;
  readonly old_note_index: Uint32Decimal;
  readonly old_note_path: MerklePathDto;
  readonly memo_note: NoteWitnessDto;
  readonly memo_eph: FieldHex;
  readonly change_note: NoteWitnessDto;
  readonly change_eph: FieldHex;
}

export interface SplitWitnessDto {
  readonly compliance_pubkey_x: FieldHex;
  readonly compliance_pubkey_y: FieldHex;
  readonly note_in: NoteWitnessDto;
  readonly spend_scalar: FieldHex;
  readonly index_in: Uint32Decimal;
  readonly path_in: MerklePathDto;
  readonly note_out_1: NoteWitnessDto;
  readonly eph_1: FieldHex;
  readonly note_out_2: NoteWitnessDto;
  readonly eph_2: FieldHex;
}

export interface JoinWitnessDto {
  readonly compliance_pubkey_x: FieldHex;
  readonly compliance_pubkey_y: FieldHex;
  readonly note_a: NoteWitnessDto;
  readonly spend_scalar_a: FieldHex;
  readonly index_a: Uint32Decimal;
  readonly path_a: MerklePathDto;
  readonly note_b: NoteWitnessDto;
  readonly spend_scalar_b: FieldHex;
  readonly index_b: Uint32Decimal;
  readonly path_b: MerklePathDto;
  readonly note_out: NoteWitnessDto;
  readonly eph_out: FieldHex;
}

export interface PublicClaimWitnessDto {
  readonly memo_id: FieldHex;
  readonly compliance_pubkey_x: FieldHex;
  readonly compliance_pubkey_y: FieldHex;
  readonly current_timestamp: Uint64Decimal;
  readonly val: Uint128Decimal;
  readonly asset_id: FieldHex;
  readonly timelock: Uint64Decimal;
  readonly owner_x: FieldHex;
  readonly owner_y: FieldHex;
  readonly salt: FieldHex;
  readonly recipient_sk: FieldHex;
  readonly note_out: NoteWitnessDto;
  readonly eph: FieldHex;
}

export interface StandardWitnessByCircuit {
  readonly deposit: DepositWitnessDto;
  readonly withdraw: WithdrawWitnessDto;
  readonly transfer: TransferWitnessDto;
  readonly split: SplitWitnessDto;
  readonly join: JoinWitnessDto;
  readonly public_claim: PublicClaimWitnessDto;
}
