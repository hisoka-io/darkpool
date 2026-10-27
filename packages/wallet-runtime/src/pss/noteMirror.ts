import {
  mergeDroppedNoteLists,
  type DroppedNote,
  type ParsedStatePayload,
  type SyncState,
  type UnspentNote,
} from "@hisoka/pss-client";
import type { BlockId } from "../chain/rpc.js";
import { describeCause, WalletRuntimeError } from "../errors.js";
import {
  noteKey,
  nullifierHex,
  type NoteStore,
  type StoredNote,
} from "../store/noteStore.js";

/** The part of pss-client's `StateSync` the runtime drives. */
export interface PssStatePort {
  current(): ParsedStatePayload;
  readonly state: Pick<SyncState, "mode" | "heldBy">;
  update(
    change: (current: ParsedStatePayload) => ParsedStatePayload,
  ): Promise<void>;
  mutateAsWriterDurably<T>(
    change: (current: ParsedStatePayload) => {
      readonly payload: ParsedStatePayload;
      readonly value: T;
    },
  ): Promise<T>;
}

const ADDRESS_LIMIT = 1n << 160n;

function assetAddress(note: StoredNote): string {
  const asset = note.note.assetId.toBigInt();
  if (asset >= ADDRESS_LIMIT) {
    throw new WalletRuntimeError(
      "PSS_UNAVAILABLE",
      `note at leaf ${note.leafIndex} carries asset ${asset} wider than an address; it cannot be mirrored`,
      { operation: "mirror" },
    );
  }
  return `0x${asset.toString(16).padStart(40, "0")}`;
}

function toUnspent(note: StoredNote): UnspentNote {
  return {
    leafIndex: note.leafIndex,
    assetId: assetAddress(note),
    amount: note.note.value.toString(),
    nullifier: nullifierHex(note.nullifier),
    block: note.block.number,
    blockHash: note.block.hash,
  };
}

/** Fails closed with the holder's platform, and never takes over on its own. */
export function requireWriter(pss: Pick<PssStatePort, "state">): void {
  if (pss.state.mode === "writer") return;
  throw new WalletRuntimeError(
    "NOT_WRITER",
    `this install is read-only: the account is active on ${pss.state.heldBy?.platform ?? "another device"}; confirm takeover there or here before minting`,
    { heldByPlatform: pss.state.heldBy?.platform ?? "" },
  );
}

export interface MirrorResult {
  readonly written: boolean;
  readonly notes: number;
  readonly tombstones: number;
}

/**
 * Writes the confirmed, verified note set into PSS and moves its cursor and nullifier checkpoint to `pssHead`
 * and no further, so a reorg shallower than the PSS write depth never reaches PSS. Notes a rollback dropped
 * after they were mirrored go out as tombstones in the same write. An unverified note is never written. A
 * read-only install writes nothing.
 */
export async function mirrorNotes(
  pss: PssStatePort,
  notes: NoteStore,
  pssHead: BlockId,
): Promise<MirrorResult> {
  if (pss.state.mode !== "writer") {
    return { written: false, notes: 0, tombstones: 0 };
  }
  const checkedAt = Math.min(notes.sweptThrough, pssHead.number);
  const eligible = notes.notes.filter(
    (n) =>
      n.verification === "verified" &&
      n.block.number <= pssHead.number &&
      (n.spent === null || n.spent.block.number > checkedAt),
  );
  const tombstones = [...notes.pendingTombstones];
  const unspent = eligible.map(toUnspent);
  try {
    await pss.update((p) => ({
      known: {
        ...p.known,
        unspentNotes: unspent,
        droppedNotes: mergeDroppedNoteLists([p.known.droppedNotes, tombstones]),
        syncCursor: { block: pssHead.number, logIndex: 0 },
        nullifierCheckedAt: { block: Math.max(0, checkedAt) },
      },
      extra: p.extra,
    }));
  } catch (cause) {
    throw new WalletRuntimeError(
      "PSS_UNAVAILABLE",
      `writing ${unspent.length} notes and ${tombstones.length} tombstones to PSS failed: ${describeCause(cause)}`,
      { operation: "mirror" },
      cause,
    );
  }
  await notes.markMirrored(eligible.map(noteKey), tombstones);
  return {
    written: true,
    notes: unspent.length,
    tombstones: tombstones.length,
  };
}

/** A note PSS holds that the device has not yet re-derived from the chain. */
export type HintCheck =
  | { readonly kind: "confirmed"; readonly note: StoredNote }
  | { readonly kind: "rejected"; readonly reason: string }
  /** The chain view does not reach the hint's block yet: neither kept nor tombstoned. */
  | { readonly kind: "pending" };

/**
 * PSS notes are hints. Each one not already in the store is re-opened from the chain at its leaf index by
 * `check`; it enters the store only when that yields the same nullifier in the same block, is left alone
 * while the chain view has not reached its block, and is tombstoned otherwise so the next write removes it
 * for every device.
 */
export async function reverifyPssHints(
  pss: Pick<PssStatePort, "current">,
  notes: NoteStore,
  check: (hint: UnspentNote) => Promise<HintCheck>,
): Promise<{ readonly confirmed: number; readonly rejected: number }> {
  const held = new Set(
    notes.notes.map((n) => `${n.leafIndex}:${nullifierHex(n.nullifier)}`),
  );
  let confirmed = 0;
  let rejected = 0;
  const found: StoredNote[] = [];
  for (const hint of pss.current().known.unspentNotes) {
    if (held.has(`${hint.leafIndex}:${hint.nullifier}`)) continue;
    const result = await check(hint);
    if (result.kind === "pending") continue;
    if (
      result.kind === "confirmed" &&
      result.note.leafIndex === hint.leafIndex &&
      nullifierHex(result.note.nullifier) === hint.nullifier &&
      result.note.block.hash === hint.blockHash
    ) {
      found.push({ ...result.note, mirrored: true });
      confirmed += 1;
      continue;
    }
    const tombstone: DroppedNote = {
      leafIndex: hint.leafIndex,
      nullifier: hint.nullifier,
      block: hint.block,
      blockHash: hint.blockHash,
    };
    await notes.discard(null, tombstone);
    rejected += 1;
  }
  if (found.length > 0) await notes.record(found, null);
  return { confirmed, rejected };
}
