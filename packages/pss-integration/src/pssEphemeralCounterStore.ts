import {
  PersistentEphemeralCounterStore,
  type CounterPersistence,
  type CounterSnapshot,
} from "@hisoka/wallets";
import type { ParsedStatePayload } from "@hisoka/pss-client";

/**
 * The durable side of the counter: read and write the scope high-water map inside the PSS state payload.
 *
 * Kept as a narrow port rather than taking `StateSync` directly, so the store can be driven by a plain
 * local cache in a test and by the real sync loop in production without changing this file.
 */
export interface CounterPayloadPort {
  current(): ParsedStatePayload;
  /** MUST resolve only once the new payload is durable. */
  update(
    change: (current: ParsedStatePayload) => ParsedStatePayload,
  ): Promise<void>;
}

function withCounters(
  payload: ParsedStatePayload,
  next: CounterSnapshot,
): ParsedStatePayload {
  return {
    known: { ...payload.known, ephemeralCounters: next },
    extra: payload.extra,
  };
}

/** Binds the shared durable counter to the PSS state payload. All reservation logic lives in wallets. */
export function pssCounterPersistence(
  port: CounterPayloadPort,
): CounterPersistence {
  return {
    read: () => port.current().known.ephemeralCounters,
    write: (change) =>
      port.update((payload) =>
        withCounters(payload, change(payload.known.ephemeralCounters)),
      ),
  };
}

/**
 * An `EphemeralCounterStore` whose durable medium is the PSS state payload.
 *
 * The seam that makes the ephemeral workstream real: without it both mint paths run on an in-memory counter
 * that forgets on restart, and a restarted wallet reissues index 0.
 */
export class PssEphemeralCounterStore extends PersistentEphemeralCounterStore {
  constructor(port: CounterPayloadPort) {
    super(pssCounterPersistence(port));
  }
}
