// Durable, single-writer self-ephemeral index reservation (WC-1 / I-1). A reused self-eph index reuses the
// CEK, hence the additive Poseidon2 DEM keystream, which is a two-time-pad on the note plaintext (and collides
// psi/tag). The security barrier is reserve(): it durably raises the high-water BEFORE any index is handed out,
// so a crash after reserve() can never reissue. Skipping indices is harmless; reusing one is catastrophic, so
// every uncertain path burns forward and never rewinds below a subsequent writer's base.

export interface EphemeralReservation {
  // First index of the durably-reserved span. [base, base+span) is persisted the moment this object exists.
  readonly base: number;
  readonly span: number;
  // Finalize: reclaim the unused tail down to usedThrough+1 (keeps indices dense) IF no later reserve advanced
  // past this span. usedThrough must lie in [base, base+span). Never rewinds below base.
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

// Reference in-memory store for tests and the default SDK backend. NOT durable across a process restart on its
// own: a browser IndexedDB or node-file backend implements the same contract for real persistence (the SDK stays
// storage-agnostic). The single writer is the promise-chain lock; reserve() advances the high-water
// synchronously (write-ahead) before resolving, so a snapshot() taken after any resolved reserve() already
// reflects every handed-out index, which is what makes the crash test pass.
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

// Fail-closed default for a KeyRepository with no configured counter: refuse to hand out an index rather than
// silently reuse self-eph indices from a non-durable counter (the WC-1 two-time-pad hazard). Production passes a
// durable backend; tests pass an explicit InMemoryEphemeralCounterStore. reserve() rejects, so nextSelfEphemeral
// throws instead of minting.
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
