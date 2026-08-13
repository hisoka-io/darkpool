export const ASSET_ID_SHAPE = /^0x[0-9a-f]{40}$/;
export const NULLIFIER_SHAPE = /^0x[0-9a-f]{64}$/;
export const AMOUNT_SHAPE = /^(0|[1-9][0-9]*)$/;
export const INSTALL_ID_SHAPE = /^0x[0-9a-f]{32}$/;

// The two scope families that exist: the standard path's single "self" line, and one multisig line per
// (view secret, member). The multisig segment is a field element rendered as 0x hex, not decimal.
//
// Pinned rather than loosened because this is attacker-controlled JSON: the server can put anything in
// this map, and every key it plants is a scope some future reserve() could collide with. Adding a scope
// family means updating this deliberately, which is the intended cost.
export const COUNTER_SCOPE_SHAPE =
  /^(self|msSelf:0x[0-9a-f]{64}:(0|[1-9][0-9]*))$/;

// A wallet holds one standard scope plus one per (group, member). The cap bounds what a hostile payload
// can make a client carry and re-upload, and 64 is far above any real group count.
export const MAX_COUNTER_SCOPES = 64;

// Note values are u128 in-circuit; a decimal string wider than that could never have come from a note.
export const MAX_NOTE_AMOUNT = (1n << 128n) - 1n;

export interface IssuedAddress {
  readonly index: number;
}

export interface UnspentNote {
  readonly leafIndex: number;
  readonly assetId: string;
  readonly amount: string;
  readonly nullifier: string;
}

export interface SyncCursor {
  readonly block: number;
  readonly logIndex: number;
}

export interface NullifierCheckpoint {
  readonly block: number;
}

export interface PssStatePayload {
  readonly schema: number;
  readonly installId: string;
  readonly platform: string;
  readonly updatedAt: number;
  readonly selfEphHighwater: number;
  readonly incomingIssueHighwater: number;
  readonly issuedAddresses: readonly IssuedAddress[];
  readonly unspentNotes: readonly UnspentNote[];
  readonly syncCursor: SyncCursor;
  readonly nullifierCheckedAt: NullifierCheckpoint;
  /**
   * Durable ephemeral-index high-water marks, keyed by counter scope.
   *
   * This is the only field whose REGRESSION is a money-path defect rather than a stale cache: an index
   * handed out twice reuses the CEK and two-time-pads the note DEM, which publicly links both notes to
   * one wallet. It therefore merges by per-key max and by union, never last-writer-wins.
   */
  readonly ephemeralCounters: Readonly<Record<string, number>>;
}

// Fields this build does not know are carried verbatim so an older client cannot silently drop a newer
// one's data on a merge. They are kept beside the typed view rather than in an index signature, which
// would widen every known field to `unknown`.
export interface ParsedStatePayload {
  readonly known: PssStatePayload;
  readonly extra: Readonly<Record<string, unknown>>;
}

export const STATE_PAYLOAD_KNOWN_KEYS: readonly (keyof PssStatePayload)[] = [
  "schema",
  "installId",
  "platform",
  "updatedAt",
  "selfEphHighwater",
  "incomingIssueHighwater",
  "issuedAddresses",
  "unspentNotes",
  "syncCursor",
  "nullifierCheckedAt",
  "ephemeralCounters",
];
