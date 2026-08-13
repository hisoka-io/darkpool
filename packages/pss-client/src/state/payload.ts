import { PSS_SCHEMA_VERSION, PLATFORM_MAX_CHARS } from "../wire/constants.js";
import {
  AMOUNT_SHAPE,
  ASSET_ID_SHAPE,
  COUNTER_SCOPE_SHAPE,
  MAX_COUNTER_SCOPES,
  INSTALL_ID_SHAPE,
  IssuedAddress,
  MAX_NOTE_AMOUNT,
  NULLIFIER_SHAPE,
  NullifierCheckpoint,
  ParsedStatePayload,
  PssStatePayload,
  STATE_PAYLOAD_KNOWN_KEYS,
  SyncCursor,
  UnspentNote,
} from "../wire/payload.js";
import { PssSchemaError, PssStateError } from "./errors.js";

function record(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new PssStateError(`${label} must be a JSON object`);
  }
  return value as Record<string, unknown>;
}

function count(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new PssStateError(
      `${label} must be a non-negative safe integer, got ${String(value)}`,
    );
  }
  return value;
}

function shaped(value: unknown, shape: RegExp, label: string): string {
  if (typeof value !== "string" || !shape.test(value)) {
    throw new PssStateError(`${label} is malformed: ${String(value)}`);
  }
  return value;
}

function array(value: unknown, label: string): unknown[] {
  if (!Array.isArray(value)) {
    throw new PssStateError(`${label} must be an array`);
  }
  return value;
}

function parseIssuedAddress(value: unknown): IssuedAddress {
  const raw = record(value, "issuedAddresses entry");
  return { index: count(raw.index, "issuedAddresses[].index") };
}

function parseUnspentNote(value: unknown): UnspentNote {
  const raw = record(value, "unspentNotes entry");
  const amount = shaped(raw.amount, AMOUNT_SHAPE, "unspentNotes[].amount");
  if (BigInt(amount) > MAX_NOTE_AMOUNT) {
    throw new PssStateError(
      `unspentNotes[].amount ${amount} exceeds the u128 range a note can hold`,
    );
  }
  return {
    leafIndex: count(raw.leafIndex, "unspentNotes[].leafIndex"),
    assetId: shaped(raw.assetId, ASSET_ID_SHAPE, "unspentNotes[].assetId"),
    amount,
    nullifier: shaped(
      raw.nullifier,
      NULLIFIER_SHAPE,
      "unspentNotes[].nullifier",
    ),
  };
}

function parseSyncCursor(value: unknown): SyncCursor {
  const raw = record(value, "syncCursor");
  return {
    block: count(raw.block, "syncCursor.block"),
    logIndex: count(raw.logIndex, "syncCursor.logIndex"),
  };
}

function parseCheckpoint(value: unknown): NullifierCheckpoint {
  const raw = record(value, "nullifierCheckedAt");
  return { block: count(raw.block, "nullifierCheckedAt.block") };
}

function platform(value: unknown): string {
  if (typeof value !== "string" || value.length > PLATFORM_MAX_CHARS) {
    throw new PssStateError(
      `platform must be a string of at most ${PLATFORM_MAX_CHARS} characters`,
    );
  }
  return value;
}

/**
 * Attacker-controlled: the server chooses this whole object. A bad key is a scope a future reserve()
 * could collide with, and a bad value is a high-water that could regress and reissue an index, so the
 * key shape, the value bound and the entry count are all checked rather than trusted.
 *
 * Absent is legal and means an empty map: a v1 payload has no such field, and a client that threw on it
 * could never read the state it wrote before upgrading.
 */
function parseEphemeralCounters(value: unknown): Record<string, number> {
  if (value === undefined || value === null) return {};
  const raw = record(value, "ephemeralCounters");
  const entries = Object.entries(raw);
  if (entries.length > MAX_COUNTER_SCOPES) {
    throw new PssStateError(
      `ephemeralCounters carries ${entries.length} scopes, above the ${MAX_COUNTER_SCOPES} cap`,
    );
  }
  const counters: Record<string, number> = {};
  for (const [scope, high] of entries) {
    if (!COUNTER_SCOPE_SHAPE.test(scope)) {
      throw new PssStateError(`ephemeralCounters scope is malformed: ${scope}`);
    }
    counters[scope] = count(high, `ephemeralCounters[${scope}]`);
  }
  return counters;
}

export function parseStatePayload(value: unknown): ParsedStatePayload {
  const raw = record(value, "payload");
  const schema = count(raw.schema, "schema");
  if (schema > PSS_SCHEMA_VERSION) {
    throw new PssSchemaError(schema, PSS_SCHEMA_VERSION);
  }
  const known: PssStatePayload = {
    schema,
    installId: shaped(raw.installId, INSTALL_ID_SHAPE, "installId"),
    platform: platform(raw.platform),
    updatedAt: count(raw.updatedAt, "updatedAt"),
    selfEphHighwater: count(raw.selfEphHighwater, "selfEphHighwater"),
    incomingIssueHighwater: count(
      raw.incomingIssueHighwater,
      "incomingIssueHighwater",
    ),
    issuedAddresses: array(raw.issuedAddresses, "issuedAddresses").map(
      parseIssuedAddress,
    ),
    unspentNotes: array(raw.unspentNotes, "unspentNotes").map(parseUnspentNote),
    syncCursor: parseSyncCursor(raw.syncCursor),
    nullifierCheckedAt: parseCheckpoint(raw.nullifierCheckedAt),
    ephemeralCounters: parseEphemeralCounters(raw.ephemeralCounters),
  };
  const extra: Record<string, unknown> = {};
  for (const [key, entry] of Object.entries(raw)) {
    if (!(STATE_PAYLOAD_KNOWN_KEYS as readonly string[]).includes(key)) {
      extra[key] = entry;
    }
  }
  return { known, extra };
}

// Unknown fields are written back before the known ones so a future field can never shadow a field this
// build is responsible for; the round trip preserves them either way.
export function serializeStatePayload(payload: ParsedStatePayload): string {
  return JSON.stringify({ ...payload.extra, ...payload.known });
}

export function decodeStatePayload(json: string): ParsedStatePayload {
  let value: unknown;
  try {
    value = JSON.parse(json);
  } catch {
    throw new PssStateError("payload is not valid JSON");
  }
  return parseStatePayload(value);
}

export function emptyStatePayload(
  installId: string,
  platformName: string,
  updatedAt: number,
): ParsedStatePayload {
  return {
    known: {
      schema: PSS_SCHEMA_VERSION,
      installId: shaped(installId, INSTALL_ID_SHAPE, "installId"),
      platform: platform(platformName),
      updatedAt,
      selfEphHighwater: 0,
      incomingIssueHighwater: 0,
      issuedAddresses: [],
      unspentNotes: [],
      syncCursor: { block: 0, logIndex: 0 },
      nullifierCheckedAt: { block: 0 },
      ephemeralCounters: {},
    },
    extra: {},
  };
}
