import { Collection } from "../wire/collection.js";
import { PssRollbackError, PssStateError } from "./errors.js";
import { PssStore, floorKey } from "./store.js";

// The store is async, so a check-then-act across the await would let the debounced writer and the
// periodic flush interleave and each accept a version the other has already superseded. Every read and
// write of the floor is serialised through this chain, and `accept` is the only way to move it, so the
// unsafe sequence is not reachable from outside.
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
   * R3a. Local storage is gone after a reinstall, which reopens the rollback window, so the floor is
   * seeded from the wallet's own on-chain notes before any PSS value is trusted. Never lowers.
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
