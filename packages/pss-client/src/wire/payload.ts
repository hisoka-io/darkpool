export const ASSET_ID_SHAPE = /^0x[0-9a-f]{40}$/;
export const NULLIFIER_SHAPE = /^0x[0-9a-f]{64}$/;
export const AMOUNT_SHAPE = /^(0|[1-9][0-9]*)$/;
export const INSTALL_ID_SHAPE = /^0x[0-9a-f]{32}$/;

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
];
