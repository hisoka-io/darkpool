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
  /** The current durable high-water map. Must reflect the last resolved `reserve`. */
  read(): CounterSnapshot;
  /** Selects and advances the scope in one durable transaction, returning the selected base. */
  reserve(scope: string, span: number): Promise<number>;
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
    return this.#persistence.reserve(scope, span).then((base) => {
      if (
        !Number.isSafeInteger(base) ||
        base < 0 ||
        !Number.isSafeInteger(base + span)
      ) {
        throw new Error(
          `ephemeral reserve: persistence returned invalid base ${base} for span ${span}`,
        );
      }
      return this.#reservation(base, span);
    });
  }

  highWater(scope: string): Promise<number> {
    return Promise.resolve(this.#persistence.read()[scope] ?? 0);
  }

  #reservation(base: number, span: number): EphemeralReservation {
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
        return Promise.resolve();
      },
      release: (): Promise<void> => Promise.resolve(),
    };
  }
}
