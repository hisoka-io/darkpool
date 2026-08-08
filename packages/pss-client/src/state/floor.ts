import { Collection } from "../wire/collection.js";
import { PssRollbackError, PssStateError } from "./errors.js";
import { PssStore, floorKey } from "./store.js";

const CANONICAL_DECIMAL = /^(0|[1-9][0-9]*)$/;

// The store is async, so a check-then-act across the await would let the debounced writer and the
// periodic flush interleave and each accept a version the other has already superseded. The lock
// serialises this instance only: two VersionFloor objects over one account drive the floor backwards,
// because neither sees the other's chain. Exactly one instance per (accountId, collection) per realm is
// therefore a wiring precondition the caller owes, not something this class can enforce.
export class VersionFloor {
  readonly #store: PssStore;
  readonly #accountId: string;
  #lock: Promise<unknown> = Promise.resolve();

  constructor(store: PssStore, accountId: string) {
    this.#store = store;
    this.#accountId = accountId;
  }

  current(collection: Collection): Promise<number> {
    return this.#withLock(() => this.#read(collection));
  }

  /** Raises the floor to `version`, or throws if the server offered something already superseded. */
  accept(collection: Collection, version: number): Promise<number> {
    return this.#withLock(async () => {
      const floor = await this.#read(collection);
      if (version < floor) {
        throw new PssRollbackError(collection, floor, version);
      }
      if (version > floor) await this.#write(collection, version);
      return version;
    });
  }

  /**
   * Raises the floor to the highest version this install has durable evidence of, before any served
   * value is trusted. Never lowers.
   *
   * After a true reinstall that evidence is 0, because no chain quantity yields a blob version. Rollback
   * protection then rests on rechecking the chain before minting, not on this floor.
   */
  bootstrap(collection: Collection, chainFloor: number): Promise<number> {
    return this.#withLock(async () => {
      const floor = await this.#read(collection);
      const raised = Math.max(floor, this.#validate(chainFloor, "chainFloor"));
      if (raised > floor) await this.#write(collection, raised);
      return raised;
    });
  }

  async #read(collection: Collection): Promise<number> {
    const raw = await this.#store.get(floorKey(this.#accountId, collection));
    if (raw === null) return 0;
    // Number() reads hex, binary, exponent, fractional, signed-zero and whitespace-padded spellings, so
    // it turns most corruption into a plausible floor instead of an error. The store is injected by the
    // embedder, so this is a third-party boundary and it fails closed.
    if (!CANONICAL_DECIMAL.test(raw)) {
      throw new PssStateError(
        `stored version floor for ${collection} is corrupt: ${raw}`,
      );
    }
    const parsed = Number(raw);
    if (!Number.isSafeInteger(parsed) || parsed < 0) {
      throw new PssStateError(
        `stored version floor for ${collection} is corrupt: ${raw}`,
      );
    }
    return parsed;
  }

  async #write(collection: Collection, version: number): Promise<void> {
    await this.#store.set(
      floorKey(this.#accountId, collection),
      String(this.#validate(version, "version")),
    );
  }

  #validate(value: number, label: string): number {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new PssStateError(
        `${label} must be a non-negative safe integer, got ${value}`,
      );
    }
    return value;
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
