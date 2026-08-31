// A reused index reuses the CEK => two-time-pad on the DEM keystream, so reserve() raises the durable
// high-water before handing out an index: a crash skips indices but never reissues one.

/**
 * A reserved block of ephemeral indices, and the contract every backend must satisfy.
 *
 * The whole point is that an index is never handed out twice: a reissued index reuses the CEK and
 * two-time-pads the note DEM keystream, which publicly links both notes to one wallet.
 *
 * - `reserve(scope, span)` MUST persist the advance BEFORE returning. On return, the durable high-water
 *   is already `base + span`. A backend that returns first and writes later can reissue after a crash.
 * - `commit(usedThrough)` validates which part of the span was used but never lowers the high-water.
 * - `release()` abandons the whole span without lowering the high-water.
 *
 * Durability boundary, stated per gap:
 * - crash between `reserve` and `commit`: the whole reserved span is burned. Never reissued.
 * - crash between `commit` and the next `reserve`: the next base remains `base + span`.
 * - crash during `reserve` itself: either the advance is durable or the call rejected. A backend must
 *   never leave a third state where an index was returned but not persisted.
 *
 * Commit and release burn unused indices because no backend may make a reserved index reusable.
 */
export interface EphemeralReservation {
  readonly base: number;
  readonly span: number;
  commit(usedThrough: number): Promise<void>;
  release(): Promise<void>;
}

export interface EphemeralCounterStore {
  // Advances the scope high-water by span, returning the old high-water as base; REJECTS if the durable write fails.
  reserve(scope: string, span: number): Promise<EphemeralReservation>;
  highWater(scope: string): Promise<number>;
}

export type CounterSnapshot = Record<string, number>;

// Reference store, NOT durable across restart; a real backend implements the same contract.
export class InMemoryEphemeralCounterStore implements EphemeralCounterStore {
  readonly #highWater: Map<string, number>;
  #lock: Promise<unknown> = Promise.resolve();
  #failNextWrite = false;

  constructor(snapshot: CounterSnapshot = {}) {
    this.#highWater = new Map(Object.entries(snapshot));
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
      if (this.#failNextWrite) {
        this.#failNextWrite = false;
        throw new Error("ephemeral reserve: durable write failed");
      }
      const base = this.#highWater.get(scope) ?? 0;
      this.#highWater.set(scope, base + span);
      return this.#makeReservation(base, span);
    });
  }

  highWater(scope: string): Promise<number> {
    return this.#withLock(async () => this.#highWater.get(scope) ?? 0);
  }

  snapshot(): CounterSnapshot {
    return Object.fromEntries(this.#highWater);
  }

  failNextWrite(): void {
    this.#failNextWrite = true;
  }

  #makeReservation(base: number, span: number): EphemeralReservation {
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

  #withLock<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.#lock.then(fn, fn);
    this.#lock = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }
}

// Fail-closed default: reserve() rejects so minting refuses without a durable counter (two-time-pad hazard).
export class SealedEphemeralCounterStore implements EphemeralCounterStore {
  reserve(): Promise<EphemeralReservation> {
    return Promise.reject(
      new Error(
        "no durable ephemeral counter configured: pass an EphemeralCounterStore backend " +
          "(or an explicit InMemoryEphemeralCounterStore for tests) to KeyRepository; minting without one " +
          "risks self-eph index reuse (two-time-pad on the note DEM keystream)",
      ),
    );
  }

  highWater(): Promise<number> {
    return Promise.resolve(0);
  }
}
