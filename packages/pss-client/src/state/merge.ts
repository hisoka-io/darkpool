import { PSS_SCHEMA_VERSION } from "../wire/constants.js";
import {
  IssuedAddress,
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

// Two payloads disagreeing about the same leaf means one of them is corrupt, and picking either would
// hide that. PSS is advisory, so refusing the merge costs a resync rather than a wrong balance.
function mergeUnspentNotes(inputs: readonly MergeInput[]): UnspentNote[] {
  const byLeaf = new Map<number, UnspentNote>();
  for (const input of inputs) {
    for (const note of input.payload.known.unspentNotes) {
      const seen = byLeaf.get(note.leafIndex);
      if (seen === undefined) {
        byLeaf.set(note.leafIndex, note);
        continue;
      }
      if (
        seen.assetId !== note.assetId ||
        seen.amount !== note.amount ||
        seen.nullifier !== note.nullifier
      ) {
        throw new PssStateError(
          `two payloads disagree about leaf ${note.leafIndex}; refusing to merge a corrupt note set`,
        );
      }
    }
  }
  return [...byLeaf.values()].sort((a, b) => a.leafIndex - b.leafIndex);
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
      unspentNotes: mergeUnspentNotes(inputs),
      syncCursor: cursor,
      nullifierCheckedAt: checkedAt,
      ephemeralCounters: mergeEphemeralCounterSnapshots(
        inputs.map((input) => input.payload.known.ephemeralCounters),
      ),
    },
    extra,
  };
}
