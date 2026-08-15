import { Fr } from "@aztec/foundation/fields";
import type { EphemeralCounterStore } from "../state/EphemeralCounterStore.js";
import type { DiscoverySource } from "./types.js";

// Discovery and index allocation are separate state machines: a wallet can restore, discover every note it
// owns, report a correct balance, and still hold a counter that never heard of them. Reusing an index
// repeats the CEK and publishes a byte-identical `ephemeralPK_x` in two events, which links them for any
// observer with no cryptography at all.
//
// MONOTONE FORWARD throughout. Raven lags the chain and is untrusted, so "I see nothing" carries no
// information, and lowering on a not-found is how a recoverable gap becomes a reused index.

/** A derived self tag paired with the index it came from, which is what makes reconciliation possible. */
export interface IndexedTag {
  readonly index: number;
  readonly tag: Fr;
}

/** `reserve` with no commit is the store's ABANDON semantic: the span is burned, which is what we want. */
export async function ratchetCounter(
  store: EphemeralCounterStore,
  scope: string,
  toExclusive: number,
): Promise<number> {
  if (!Number.isInteger(toExclusive) || toExclusive < 0) {
    throw new Error(
      `ratchet target ${toExclusive} is not a non-negative integer`,
    );
  }
  const current = await store.highWater(scope);
  if (toExclusive <= current) return current;
  await store.reserve(scope, toExclusive - current);
  return toExclusive;
}

/**
 * The predicate is OCCUPANCY, not openability. A row that exists but does not open is still a consumed
 * index: possibly this wallet's own note under a rotated compliance key. "Did not open" is not "free".
 */
export async function occupiedTags(
  source: DiscoverySource,
  tags: readonly IndexedTag[],
): Promise<ReadonlySet<number>> {
  if (tags.length === 0) return new Set();
  const probed = await source.probeFirst(tags.map((t) => t.tag));
  const byTag = new Map(tags.map((t) => [t.tag.toString(), t.index]));
  const occupied = new Set<number>();
  for (const entry of probed) {
    if (entry.occurrenceCount <= 0) continue;
    const index = byTag.get(entry.tag.toString());
    if (index !== undefined) occupied.add(index);
  }
  return occupied;
}

/**
 * Call after a restore and before the first mint. A LAGGING indicator, never an interlock: it cannot see a
 * transaction in a relayer queue or a second device that reserved but has not broadcast. It shrinks the
 * collision window; only a single writer closes it.
 */
export async function reconcileCounterWithChain(
  source: DiscoverySource,
  store: EphemeralCounterStore,
  scope: string,
  candidates: readonly IndexedTag[],
): Promise<{ highWater: number; occupied: readonly number[] }> {
  const occupied = await occupiedTags(source, candidates);
  const sorted = [...occupied].sort((a, b) => a - b);
  const highest = sorted.length === 0 ? -1 : sorted[sorted.length - 1];
  const highWater = await ratchetCounter(store, scope, highest + 1);
  return { highWater, occupied: sorted };
}
