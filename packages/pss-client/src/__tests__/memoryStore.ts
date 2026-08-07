import { PssStore } from "../state/store.js";

// Test substrate only. `delayMs` models the await that every real store (chrome.storage.local,
// AsyncStorage) forces between a read and the write that depends on it, which is the window a
// check-then-act floor update would lose to.
export class MemoryPssStore implements PssStore {
  readonly #cells = new Map<string, string>();
  readonly #delayMs: number;

  constructor(delayMs = 0) {
    this.#delayMs = delayMs;
  }

  async get(key: string): Promise<string | null> {
    await this.#tick();
    return this.#cells.get(key) ?? null;
  }

  async set(key: string, value: string): Promise<void> {
    await this.#tick();
    this.#cells.set(key, value);
  }

  async remove(key: string): Promise<void> {
    await this.#tick();
    this.#cells.delete(key);
  }

  snapshot(): Record<string, string> {
    return Object.fromEntries(this.#cells);
  }

  #tick(): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, this.#delayMs));
  }
}
