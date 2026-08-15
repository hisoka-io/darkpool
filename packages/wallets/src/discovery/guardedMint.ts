import { Fr } from "@aztec/foundation/fields";
import { Point } from "@zk-kit/baby-jubjub";
import { discoveryTag } from "../note/keys.js";
import type { EphemeralCounterStore } from "../state/EphemeralCounterStore.js";
import { occupiedTags, ratchetCounter } from "./reconcile.js";
import type { DiscoverySource } from "./types.js";

/**
 * Optimistic fire-and-ratchet acquisition of a self ephemeral.
 *
 * The collision check costs a discovery round trip, and putting it in front of proving would add that to
 * the critical path of every spend. It does not need to be there. Proving is reversible; BROADCAST is not.
 * So the probe is fired the moment the index is reserved, proving runs concurrently, and `confirm()` is
 * awaited immediately before broadcast.
 *
 * On the rare collision the only loss is a discarded proof, and the counter has already ratcheted past the
 * occupied index so the retry cannot repeat it.
 *
 * The check is a LAGGING indicator: it cannot see a transaction in a relayer queue or a sibling device that
 * has reserved without broadcasting. It shrinks the collision window; a single writer is what closes it.
 */

export interface GuardedEphemeral {
  readonly eph: Fr;
  readonly ephPub: Point<bigint>;
  readonly index: number;
  /**
   * Await immediately before broadcasting. Resolves when the index is confirmed unused; rejects, having
   * already ratcheted the counter past it, when the chain has consumed it.
   */
  confirm(): Promise<void>;
}

export interface SelfEphemeralSource {
  nextSelfEphemeral(): Promise<{
    eph: Fr;
    ephPub: Point<bigint>;
    index: number;
  }>;
}

export class EphemeralCollisionError extends Error {
  constructor(readonly index: number) {
    super(
      `self ephemeral index ${index} is already on chain; the counter was behind and has been ratcheted past it`,
    );
    this.name = "EphemeralCollisionError";
  }
}

export async function acquireSelfEphemeral(
  keys: SelfEphemeralSource,
  source: DiscoverySource,
  store: EphemeralCounterStore,
  scope: string,
): Promise<GuardedEphemeral> {
  const { eph, ephPub, index } = await keys.nextSelfEphemeral();
  const tag = discoveryTag(ephPub);

  // Fired here, awaited at confirm(): the caller proves in the gap.
  const probe = occupiedTags(source, [{ index, tag }]).then(
    (occupied) => occupied.has(index),
    // A discovery service that is down must not block a spend. Absence of an answer is absence of
    // evidence, and the counter is already durable, so proceeding is the same risk as before this guard.
    () => false,
  );

  return {
    eph,
    ephPub,
    index,
    confirm: async () => {
      if (!(await probe)) return;
      await ratchetCounter(store, scope, index + 1);
      throw new EphemeralCollisionError(index);
    },
  };
}
