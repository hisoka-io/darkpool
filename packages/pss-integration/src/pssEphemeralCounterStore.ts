import type {
  EphemeralCounterStore,
  EphemeralReservation,
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
  scope: string,
  high: number,
): ParsedStatePayload {
  return {
    known: {
      ...payload.known,
      ephemeralCounters: { ...payload.known.ephemeralCounters, [scope]: high },
    },
    extra: payload.extra,
  };
}

/**
 * An `EphemeralCounterStore` whose durable medium is the PSS state payload.
 *
 * This is the seam that makes the whole ephemeral workstream real: without it both mint paths run on an
 * in-memory counter that forgets everything on restart, and a restarted wallet reissues index 0.
 *
 * It satisfies the `EphemeralReservation` contract exactly: `reserve` awaits the durable write before
 * returning, both trims are conditional on the high-water still being the one this reservation set, and
 * `release` rewinds to base. Callers on a deterministic derivation must abandon rather than release; see
 * that contract.
 */
export class PssEphemeralCounterStore implements EphemeralCounterStore {
  readonly #port: CounterPayloadPort;
  // Serialises read-modify-write, because the payload is a single document and two concurrent reserves
  // would otherwise each read the same high-water and hand out the same base.
  #lock: Promise<unknown> = Promise.resolve();

  constructor(port: CounterPayloadPort) {
    this.#port = port;
  }

  reserve(scope: string, span: number): Promise<EphemeralReservation> {
    if (!Number.isInteger(span) || span <= 0) {
      return Promise.reject(
        new Error(
          `ephemeral reserve: span must be a positive integer (got ${span})`,
        ),
      );
    }
    return this.#withLock(async () => {
      const base = this.#read(scope);
      // Persisted BEFORE the reservation is returned. A crash after this point burns the span, which is
      // harmless; a crash before it means no index was ever handed out.
      await this.#port.update((payload) =>
        withCounters(payload, scope, base + span),
      );
      return this.#reservation(scope, base, span);
    });
  }

  highWater(scope: string): Promise<number> {
    return this.#withLock(() => Promise.resolve(this.#read(scope)));
  }

  #read(scope: string): number {
    return this.#port.current().known.ephemeralCounters[scope] ?? 0;
  }

  #reservation(
    scope: string,
    base: number,
    span: number,
  ): EphemeralReservation {
    return {
      base,
      span,
      commit: (usedThrough: number): Promise<void> => {
        if (
          !Number.isInteger(usedThrough) ||
          usedThrough < base ||
          usedThrough >= base + span
        ) {
          return Promise.reject(
            new Error(
              `ephemeral commit: usedThrough ${usedThrough} out of reserved span [${base}, ${base + span})`,
            ),
          );
        }
        return this.#trim(scope, base, span, usedThrough + 1);
      },
      release: (): Promise<void> => this.#trim(scope, base, span, base),
    };
  }

  // Conditional on the high-water still being the one this reservation set, so a concurrent reserve that
  // already moved it is never clobbered.
  #trim(scope: string, base: number, span: number, to: number): Promise<void> {
    return this.#withLock(async () => {
      if (this.#read(scope) !== base + span) return;
      await this.#port.update((payload) => withCounters(payload, scope, to));
    });
  }

  #withLock<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.#lock.then(fn, fn);
    this.#lock = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }
}
