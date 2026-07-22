// Durable single-writer index reservation. A reused index reuses the CEK => two-time-pad on the DEM keystream.
// reserve() raises the high-water before handing out an index, so a crash skips (safe) but never reissues.

export interface EphemeralReservation {
  // First index of the durably-reserved span. [base, base+span) is persisted the moment this object exists.
  readonly base: number;
  readonly span: number;
  // Reclaim the unused tail to usedThrough+1 iff still top of high-water. usedThrough in [base, base+span).
  commit(usedThrough: number): Promise<void>;
  // Abandon the whole span without using it (reclaim to base) IF still the top of the high-water.
  release(): Promise<void>;
}

export interface EphemeralCounterStore {
  // Durably advance the scope's high-water by span (single-writer, flush-before-resolve) and return the old
  // high-water as base. REJECTS (so the caller refuses to mint) if the durable write fails. Distinct scopes
  // namespace independent monotonic counters over one backend (e.g. "self" and "ms:<memberId>").
  reserve(scope: string, span: number): Promise<EphemeralReservation>;
  // The next never-reserved index for a scope; drives scan lookahead + restore reconciliation.
  highWater(scope: string): Promise<number>;
}

export type CounterSnapshot = Record<string, number>;

// In-memory reference store: not durable across restart on its own; a real backend implements the same contract.
// reserve() advances the high-water before resolving, so a post-reserve snapshot() reflects every handed-out index.
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
      return this.#makeReservation(scope, base, span);
    });
  }

  highWater(scope: string): Promise<number> {
    return this.#withLock(async () => this.#highWater.get(scope) ?? 0);
  }

  // Durable image; a real backend persists this. Reconstructing a store from a snapshot models a crash/restart.
  snapshot(): CounterSnapshot {
    return Object.fromEntries(this.#highWater);
  }

  // Test hook: force the next reserve() to reject, modelling disk-full / quota / txn abort (mint must refuse).
  failNextWrite(): void {
    this.#failNextWrite = true;
  }

  #makeReservation(
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

  #trim(scope: string, base: number, span: number, to: number): Promise<void> {
    return this.#withLock(async () => {
      // Only reclaim if no later reserve advanced past this reservation; never rewind below a subsequent base.
      if (this.#highWater.get(scope) === base + span)
        this.#highWater.set(scope, to);
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
