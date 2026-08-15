import { Fr } from "@aztec/foundation/fields";
import type { EphemeralCounterStore } from "../state/EphemeralCounterStore.js";
import type { DiscoverySource } from "./types.js";

/**
 * The edge between what the CHAIN knows and what the durable counter knows.
 *
 * Discovery and index allocation are two separate state machines. A wallet can restore from a stale blob,
 * discover every note it owns, report a correct balance, and still hold a counter that has never heard of
 * them. The next mint then reuses an index that is already on chain, which reuses the CEK, which repeats
 * the DEM keystream AND publishes a byte-identical `ephemeralPK_x` in two events. The second half is the
 * expensive one: it links the two notes for any observer with an archive node and no cryptography at all.
 *
 * Everything here is MONOTONE FORWARD. A discovery answer may raise the counter and may never lower it,
 * because the discovery service lags the chain and is not trusted, so "I see nothing" carries no
 * information. Lowering on a not-found is how a recoverable gap becomes a reused index.
 */

/** A derived self tag paired with the index it came from, which is what makes reconciliation possible. */
export interface IndexedTag {
  readonly index: number;
  readonly tag: Fr;
}

/**
 * Raises `scope` to `toExclusive` if it is behind, and returns the resulting high-water.
 *
 * Implemented with `reserve` and no matching commit, which is the store's existing ABANDON semantic: the
 * span is burned and can never be reissued. That is exactly right here, because every index being skipped
 * is one the chain has already seen.
 */
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
 * Asks the discovery service which of these tags already have a row.
 *
 * The predicate is OCCUPANCY, not openability. A row that exists but does not open is still an index the
 * chain has consumed: it may be a note this wallet minted under a compliance key that has since rotated, or
 * a cuckoo probe collision. Treating "did not open" as "free" is how the check hands back an index that is
 * already spent.
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
 * Probes a window of candidate indices and ratchets the counter past every one the chain has consumed.
 *
 * Call this after a restore and before the first mint. It is a LAGGING indicator, never an interlock: it
 * cannot see a transaction still in a relayer queue, a transaction in the mempool, or a second device that
 * has reserved but not yet broadcast. It shrinks the window in which a collision is possible; it does not
 * close it. Only a single writer closes it.
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
