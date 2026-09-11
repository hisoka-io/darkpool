import {
  parseAtPath,
  readExactArray,
  readExactObject,
} from "../internal/exact-object.js";
import { parseStandardCircuitIdAtPath } from "../internal/circuits.js";
import {
  parseFieldHexAtPath,
  parseUint128Decimal,
  parseUint32Decimal,
  parseUint64Decimal,
} from "../primitives.js";
import type { StandardCircuitId } from "./circuits.js";
import type {
  DepositWitnessDto,
  JoinWitnessDto,
  MerklePathDto,
  NoteWitnessDto,
  PointWitnessDto,
  PublicClaimWitnessDto,
  SplitWitnessDto,
  StandardWitnessByCircuit,
  TransferWitnessDto,
  WithdrawWitnessDto,
} from "./witnesses.js";

const TREE_DEPTH = 32;

const POINT_KEYS = ["x", "y"] as const;
const NOTE_KEYS = [
  "note_version",
  "asset_id",
  "note_type",
  "conditions_hash",
  "value",
  "owner",
  "psi",
  "parents",
] as const;

function parseUint32AtPath(value: unknown, path: string) {
  return parseAtPath(parseUint32Decimal, value, path);
}

function parseUint64AtPath(value: unknown, path: string) {
  return parseAtPath(parseUint64Decimal, value, path);
}

function parseUint128AtPath(value: unknown, path: string) {
  return parseAtPath(parseUint128Decimal, value, path);
}

function parsePoint(value: unknown, path: string): PointWitnessDto {
  const point = readExactObject(value, POINT_KEYS, path);
  return {
    x: parseFieldHexAtPath(point.x, `${path}.x`),
    y: parseFieldHexAtPath(point.y, `${path}.y`),
  };
}

function parseNote(value: unknown, path: string): NoteWitnessDto {
  const note = readExactObject(value, NOTE_KEYS, path);
  return {
    note_version: parseFieldHexAtPath(
      note.note_version,
      `${path}.note_version`,
    ),
    asset_id: parseFieldHexAtPath(note.asset_id, `${path}.asset_id`),
    note_type: parseFieldHexAtPath(note.note_type, `${path}.note_type`),
    conditions_hash: parseFieldHexAtPath(
      note.conditions_hash,
      `${path}.conditions_hash`,
    ),
    value: parseUint128AtPath(note.value, `${path}.value`),
    owner: parseFieldHexAtPath(note.owner, `${path}.owner`),
    psi: parseFieldHexAtPath(note.psi, `${path}.psi`),
    parents: parseFieldHexAtPath(note.parents, `${path}.parents`),
  };
}

function parseMerklePath(value: unknown, path: string): MerklePathDto {
  const entries = readExactArray(value, path, {
    expectedLength: TREE_DEPTH,
    errorCode: "INVALID_MERKLE_PATH",
    errorMessage: `expected exactly ${TREE_DEPTH} field elements`,
  });
  return entries.map((entry, index) =>
    parseFieldHexAtPath(entry, `${path}[${index}]`),
  );
}

function parseDeposit(value: unknown): DepositWitnessDto {
  const witness = readExactObject(
    value,
    ["compliance_pubkey_x", "compliance_pubkey_y", "note", "eph"],
    "$",
  );
  return {
    compliance_pubkey_x: parseFieldHexAtPath(
      witness.compliance_pubkey_x,
      "$.compliance_pubkey_x",
    ),
    compliance_pubkey_y: parseFieldHexAtPath(
      witness.compliance_pubkey_y,
      "$.compliance_pubkey_y",
    ),
    note: parseNote(witness.note, "$.note"),
    eph: parseFieldHexAtPath(witness.eph, "$.eph"),
  };
}

function parseWithdraw(value: unknown): WithdrawWitnessDto {
  const witness = readExactObject(
    value,
    [
      "withdraw_value",
      "_recipient",
      "_intent_hash",
      "compliance_pubkey_x",
      "compliance_pubkey_y",
      "old_note",
      "spend_scalar",
      "old_note_index",
      "old_note_path",
      "change_note",
      "change_eph",
    ],
    "$",
  );
  return {
    withdraw_value: parseUint128AtPath(
      witness.withdraw_value,
      "$.withdraw_value",
    ),
    _recipient: parseFieldHexAtPath(witness._recipient, "$._recipient"),
    _intent_hash: parseFieldHexAtPath(witness._intent_hash, "$._intent_hash"),
    compliance_pubkey_x: parseFieldHexAtPath(
      witness.compliance_pubkey_x,
      "$.compliance_pubkey_x",
    ),
    compliance_pubkey_y: parseFieldHexAtPath(
      witness.compliance_pubkey_y,
      "$.compliance_pubkey_y",
    ),
    old_note: parseNote(witness.old_note, "$.old_note"),
    spend_scalar: parseFieldHexAtPath(witness.spend_scalar, "$.spend_scalar"),
    old_note_index: parseUint32AtPath(
      witness.old_note_index,
      "$.old_note_index",
    ),
    old_note_path: parseMerklePath(witness.old_note_path, "$.old_note_path"),
    change_note: parseNote(witness.change_note, "$.change_note"),
    change_eph: parseFieldHexAtPath(witness.change_eph, "$.change_eph"),
  };
}

function parseTransfer(value: unknown): TransferWitnessDto {
  const witness = readExactObject(
    value,
    [
      "compliance_pubkey_x",
      "compliance_pubkey_y",
      "recipient_spend_pub",
      "recipient_view_pub",
      "old_note",
      "spend_scalar",
      "old_note_index",
      "old_note_path",
      "memo_note",
      "memo_eph",
      "change_note",
      "change_eph",
    ],
    "$",
  );
  return {
    compliance_pubkey_x: parseFieldHexAtPath(
      witness.compliance_pubkey_x,
      "$.compliance_pubkey_x",
    ),
    compliance_pubkey_y: parseFieldHexAtPath(
      witness.compliance_pubkey_y,
      "$.compliance_pubkey_y",
    ),
    recipient_spend_pub: parsePoint(
      witness.recipient_spend_pub,
      "$.recipient_spend_pub",
    ),
    recipient_view_pub: parsePoint(
      witness.recipient_view_pub,
      "$.recipient_view_pub",
    ),
    old_note: parseNote(witness.old_note, "$.old_note"),
    spend_scalar: parseFieldHexAtPath(witness.spend_scalar, "$.spend_scalar"),
    old_note_index: parseUint32AtPath(
      witness.old_note_index,
      "$.old_note_index",
    ),
    old_note_path: parseMerklePath(witness.old_note_path, "$.old_note_path"),
    memo_note: parseNote(witness.memo_note, "$.memo_note"),
    memo_eph: parseFieldHexAtPath(witness.memo_eph, "$.memo_eph"),
    change_note: parseNote(witness.change_note, "$.change_note"),
    change_eph: parseFieldHexAtPath(witness.change_eph, "$.change_eph"),
  };
}

function parseSplit(value: unknown): SplitWitnessDto {
  const witness = readExactObject(
    value,
    [
      "compliance_pubkey_x",
      "compliance_pubkey_y",
      "note_in",
      "spend_scalar",
      "index_in",
      "path_in",
      "note_out_1",
      "eph_1",
      "note_out_2",
      "eph_2",
    ],
    "$",
  );
  return {
    compliance_pubkey_x: parseFieldHexAtPath(
      witness.compliance_pubkey_x,
      "$.compliance_pubkey_x",
    ),
    compliance_pubkey_y: parseFieldHexAtPath(
      witness.compliance_pubkey_y,
      "$.compliance_pubkey_y",
    ),
    note_in: parseNote(witness.note_in, "$.note_in"),
    spend_scalar: parseFieldHexAtPath(witness.spend_scalar, "$.spend_scalar"),
    index_in: parseUint32AtPath(witness.index_in, "$.index_in"),
    path_in: parseMerklePath(witness.path_in, "$.path_in"),
    note_out_1: parseNote(witness.note_out_1, "$.note_out_1"),
    eph_1: parseFieldHexAtPath(witness.eph_1, "$.eph_1"),
    note_out_2: parseNote(witness.note_out_2, "$.note_out_2"),
    eph_2: parseFieldHexAtPath(witness.eph_2, "$.eph_2"),
  };
}

function parseJoin(value: unknown): JoinWitnessDto {
  const witness = readExactObject(
    value,
    [
      "compliance_pubkey_x",
      "compliance_pubkey_y",
      "note_a",
      "spend_scalar_a",
      "index_a",
      "path_a",
      "note_b",
      "spend_scalar_b",
      "index_b",
      "path_b",
      "note_out",
      "eph_out",
    ],
    "$",
  );
  return {
    compliance_pubkey_x: parseFieldHexAtPath(
      witness.compliance_pubkey_x,
      "$.compliance_pubkey_x",
    ),
    compliance_pubkey_y: parseFieldHexAtPath(
      witness.compliance_pubkey_y,
      "$.compliance_pubkey_y",
    ),
    note_a: parseNote(witness.note_a, "$.note_a"),
    spend_scalar_a: parseFieldHexAtPath(
      witness.spend_scalar_a,
      "$.spend_scalar_a",
    ),
    index_a: parseUint32AtPath(witness.index_a, "$.index_a"),
    path_a: parseMerklePath(witness.path_a, "$.path_a"),
    note_b: parseNote(witness.note_b, "$.note_b"),
    spend_scalar_b: parseFieldHexAtPath(
      witness.spend_scalar_b,
      "$.spend_scalar_b",
    ),
    index_b: parseUint32AtPath(witness.index_b, "$.index_b"),
    path_b: parseMerklePath(witness.path_b, "$.path_b"),
    note_out: parseNote(witness.note_out, "$.note_out"),
    eph_out: parseFieldHexAtPath(witness.eph_out, "$.eph_out"),
  };
}

function parsePublicClaim(value: unknown): PublicClaimWitnessDto {
  const witness = readExactObject(
    value,
    [
      "memo_id",
      "compliance_pubkey_x",
      "compliance_pubkey_y",
      "current_timestamp",
      "val",
      "asset_id",
      "timelock",
      "owner_x",
      "owner_y",
      "salt",
      "recipient_sk",
      "note_out",
      "eph",
    ],
    "$",
  );
  return {
    memo_id: parseFieldHexAtPath(witness.memo_id, "$.memo_id"),
    compliance_pubkey_x: parseFieldHexAtPath(
      witness.compliance_pubkey_x,
      "$.compliance_pubkey_x",
    ),
    compliance_pubkey_y: parseFieldHexAtPath(
      witness.compliance_pubkey_y,
      "$.compliance_pubkey_y",
    ),
    current_timestamp: parseUint64AtPath(
      witness.current_timestamp,
      "$.current_timestamp",
    ),
    val: parseUint128AtPath(witness.val, "$.val"),
    asset_id: parseFieldHexAtPath(witness.asset_id, "$.asset_id"),
    timelock: parseUint64AtPath(witness.timelock, "$.timelock"),
    owner_x: parseFieldHexAtPath(witness.owner_x, "$.owner_x"),
    owner_y: parseFieldHexAtPath(witness.owner_y, "$.owner_y"),
    salt: parseFieldHexAtPath(witness.salt, "$.salt"),
    recipient_sk: parseFieldHexAtPath(witness.recipient_sk, "$.recipient_sk"),
    note_out: parseNote(witness.note_out, "$.note_out"),
    eph: parseFieldHexAtPath(witness.eph, "$.eph"),
  };
}

function unsupportedStandardCircuit(circuit: never): never {
  void circuit;
  throw new Error("unreachable standard circuit dispatch");
}

type StandardWitnessDto = StandardWitnessByCircuit[StandardCircuitId];

export function parseStandardWitnessDto<C extends StandardCircuitId>(
  circuit: C,
  value: unknown,
): StandardWitnessByCircuit[C];
export function parseStandardWitnessDto(
  circuit: StandardCircuitId,
  value: unknown,
): StandardWitnessDto {
  const validatedCircuit = parseStandardCircuitIdAtPath(circuit, "$");
  switch (validatedCircuit) {
    case "deposit":
      return parseDeposit(value);
    case "withdraw":
      return parseWithdraw(value);
    case "transfer":
      return parseTransfer(value);
    case "split":
      return parseSplit(value);
    case "join":
      return parseJoin(value);
    case "public_claim":
      return parsePublicClaim(value);
    default:
      return unsupportedStandardCircuit(validatedCircuit);
  }
}
