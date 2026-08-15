import type {
  CounterSnapshot,
  EphemeralCounterStore,
  EphemeralReservation,
} from "./EphemeralCounterStore.js";

/**
 * The durable medium behind the counter, injected rather than imported.
 *
 * Keeping this a port is what lets `@hisoka/wallets` stay free of workspace dependencies: PSS supplies the
 * binding from outside, and a different backend can supply another without touching the crypto core.
 */
export interface CounterPersistence {
  /** The current durable high-water map. Must reflect the last resolved `write`. */
  read(): CounterSnapshot;
  /** MUST resolve only once the change is durable, or the two-time-pad guarantee is void. */
  write(change: (current: CounterSnapshot) => CounterSnapshot): Promise<void>;
}

/**
 * An `EphemeralCounterStore` over any durable medium.
 *
 * Without a durable counter both mint paths run on memory that forgets on restart, and a restarted wallet
 * reissues index 0: same index, same CEK, repeated DEM keystream, and a byte-identical `ephemeralPK_x` in
 * two events.
 */
export class PersistentEphemeralCounterStore implements EphemeralCounterStore {
  readonly #persistence: CounterPersistence;
  // Serialises read-modify-write: the map is one document, so two concurrent reserves would otherwise read
  // the same high-water and hand out the same base.
  #lock: Promise<unknown> = Promise.resolve();

  constructor(persistence: CounterPersistence) {
    this.#persistence = persistence;
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
      // Persisted BEFORE the reservation is returned: a crash after this burns the span, which is harmless;
      // a crash before it means no index was ever handed out.
      await this.#persistence.write((current) => ({
        ...current,
        [scope]: base + span,
      }));
      return this.#reservation(scope, base, span);
    });
  }

  highWater(scope: string): Promise<number> {
    return this.#withLock(() => Promise.resolve(this.#read(scope)));
  }

  #read(scope: string): number {
    return this.#persistence.read()[scope] ?? 0;
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
      await this.#persistence.write((current) => ({ ...current, [scope]: to }));
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
