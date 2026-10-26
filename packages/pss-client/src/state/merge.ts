import { PSS_SCHEMA_VERSION } from "../wire/constants.js";
import {
  DroppedNote,
  IssuedAddress,
  MAX_DROPPED_NOTES,
  NullifierCheckpoint,
  ParsedStatePayload,
  SyncCursor,
  UnspentNote,
} from "../wire/payload.js";
import { PssStateError } from "./errors.js";

// A cursor may only be carried forward by a payload that still holds the whole note list it scanned.
// This is a constructor argument rather than a payload field because the frozen payload has no way to
// say "my note list was truncated", and a truncated list merged under a higher cursor silently skips a
// block range forever. Making the caller state it means the unsafe merge cannot be expressed.
export interface MergeInput {
  readonly payload: ParsedStatePayload;
  readonly noteListComplete: boolean;
}

function cursorAtLeast(a: SyncCursor, b: SyncCursor): SyncCursor {
  if (a.block !== b.block) return a.block > b.block ? a : b;
  return a.logIndex >= b.logIndex ? a : b;
}

function mergeIssuedAddresses(inputs: readonly MergeInput[]): IssuedAddress[] {
  const byIndex = new Map<number, IssuedAddress>();
  for (const input of inputs) {
    for (const address of input.payload.known.issuedAddresses) {
      byIndex.set(address.index, address);
    }
  }
  return [...byIndex.values()].sort((a, b) => a.index - b.index);
}

function tombstoneKey(note: {
  readonly leafIndex: number;
  readonly nullifier: string;
  readonly blockHash: string;
}): string {
  return `${note.leafIndex}:${note.nullifier}:${note.blockHash}`;
}

function byBlockThenKey(a: DroppedNote, b: DroppedNote): number {
  if (a.block !== b.block) return a.block - b.block;
  const ka = tombstoneKey(a);
  const kb = tombstoneKey(b);
  return ka < kb ? -1 : ka > kb ? 1 : 0;
}

/**
 * Union of every input's tombstones. Over the cap the lowest blocks go first: the oldest reorgs are the
 * least likely to still be held by a stale device, and a resurrected note is re-verified against the
 * chain before use anyway.
 */
function mergeDroppedNotes(inputs: readonly MergeInput[]): DroppedNote[] {
  const byKey = new Map<string, DroppedNote>();
  for (const input of inputs) {
    for (const dropped of input.payload.known.droppedNotes) {
      const key = tombstoneKey(dropped);
      const seen = byKey.get(key);
      if (seen === undefined || dropped.block > seen.block) {
        byKey.set(key, dropped);
      }
    }
  }
  const all = [...byKey.values()].sort(byBlockThenKey);
  return all.slice(Math.max(0, all.length - MAX_DROPPED_NOTES));
}

function sameNote(a: UnspentNote, b: UnspentNote): boolean {
  return (
    a.leafIndex === b.leafIndex &&
    a.assetId === b.assetId &&
    a.amount === b.amount &&
    a.nullifier === b.nullifier &&
    a.block === b.block &&
    a.blockHash === b.blockHash
  );
}

interface MergedNotes {
  readonly notes: UnspentNote[];
  /** Lowest inclusion block among notes dropped because two inputs disagreed about their leaf. */
  readonly lowestDisputedBlock: number | null;
}

/**
 * Union by leaf index of every note no input has tombstoned.
 *
 * Two surviving entries that disagree about one leaf mean a reorg past the PSS write depth left two
 * devices holding different notes there. Neither is kept and the merge goes on: the wallet re-derives the
 * truth from the chain, while a throw here would fail every counter reservation (each one pulls and
 * merges first) and wedge the account until someone repaired the blob by hand.
 */
function mergeUnspentNotes(
  inputs: readonly MergeInput[],
  dropped: ReadonlySet<string>,
): MergedNotes {
  const byLeaf = new Map<number, UnspentNote | null>();
  const firstAt = new Map<number, UnspentNote>();
  let lowestDisputedBlock: number | null = null;
  for (const input of inputs) {
    for (const note of input.payload.known.unspentNotes) {
      if (dropped.has(tombstoneKey(note))) continue;
      const first = firstAt.get(note.leafIndex);
      if (first === undefined) {
        firstAt.set(note.leafIndex, note);
        byLeaf.set(note.leafIndex, note);
      } else if (!sameNote(first, note)) {
        byLeaf.set(note.leafIndex, null);
        const low = Math.min(first.block, note.block);
        lowestDisputedBlock =
          lowestDisputedBlock === null
            ? low
            : Math.min(lowestDisputedBlock, low);
      }
    }
  }
  return {
    notes: [...byLeaf.values()]
      .filter((note): note is UnspentNote => note !== null)
      .sort((a, b) => a.leafIndex - b.leafIndex),
    lowestDisputedBlock,
  };
}

/**
 * Per-key max over the UNION of every input's scopes.
 *
 * Union, not intersection, and this is the load-bearing part: a scope present in only one input must
 * survive. Dropping it rewinds that counter to 0, and the next reserve() reissues indices that were
 * already used, which reuses the CEK and two-time-pads the note DEM. That is the exact failure this
 * whole field exists to prevent, so an intersection here would be worse than having no field at all.
 */
export function mergeEphemeralCounterSnapshots(
  snapshots: readonly Readonly<Record<string, number>>[],
): Record<string, number> {
  const merged: Record<string, number> = {};
  for (const snapshot of snapshots) {
    for (const [scope, high] of Object.entries(snapshot)) {
      merged[scope] = Math.max(merged[scope] ?? 0, high);
    }
  }
  return merged;
}

function newest(inputs: readonly MergeInput[]): MergeInput {
  return inputs.reduce((best, input) =>
    input.payload.known.updatedAt > best.payload.known.updatedAt ? input : best,
  );
}

export function mergeStatePayloads(
  inputs: readonly MergeInput[],
): ParsedStatePayload {
  if (inputs.length === 0) {
    throw new PssStateError("merge needs at least one payload");
  }
  const complete = inputs.filter((input) => input.noteListComplete);
  const latest = newest(inputs);
  const droppedNotes = mergeDroppedNotes(inputs);
  // Filtered by every tombstone any input carries, not only the ones that survive the cap.
  const droppedKeys = new Set(
    inputs.flatMap((input) =>
      input.payload.known.droppedNotes.map(tombstoneKey),
    ),
  );

  let cursor: SyncCursor = { block: 0, logIndex: 0 };
  let checkedAt: NullifierCheckpoint = { block: 0 };
  for (const input of complete) {
    cursor = cursorAtLeast(cursor, input.payload.known.syncCursor);
    checkedAt = {
      block: Math.max(
        checkedAt.block,
        input.payload.known.nullifierCheckedAt.block,
      ),
    };
  }
  const unspent = mergeUnspentNotes(inputs, droppedKeys);
  // The merged list no longer holds a disputed note, so the cursor may not claim to have scanned its
  // block: it moves back below the lowest one, and the next scan finds whichever note is canonical.
  if (
    unspent.lowestDisputedBlock !== null &&
    cursor.block >= unspent.lowestDisputedBlock
  ) {
    cursor = {
      block: Math.max(0, unspent.lowestDisputedBlock - 1),
      logIndex: 0,
    };
  }

  const extra: Record<string, unknown> = {};
  for (const input of [...inputs].sort(
    (a, b) => a.payload.known.updatedAt - b.payload.known.updatedAt,
  )) {
    Object.assign(extra, input.payload.extra);
  }

  return {
    known: {
      schema: PSS_SCHEMA_VERSION,
      installId: latest.payload.known.installId,
      platform: latest.payload.known.platform,
      updatedAt: Math.max(
        ...inputs.map((input) => input.payload.known.updatedAt),
      ),
      selfEphHighwater: Math.max(
        ...inputs.map((input) => input.payload.known.selfEphHighwater),
      ),
      incomingIssueHighwater: Math.max(
        ...inputs.map((input) => input.payload.known.incomingIssueHighwater),
      ),
      issuedAddresses: mergeIssuedAddresses(inputs),
      unspentNotes: unspent.notes,
      droppedNotes,
      syncCursor: cursor,
      nullifierCheckedAt: checkedAt,
      ephemeralCounters: mergeEphemeralCounterSnapshots(
        inputs.map((input) => input.payload.known.ephemeralCounters),
      ),
    },
    extra,
  };
}
