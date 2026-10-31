import type { RuntimeStore } from "../../store/runtimeStore.js";

export class MemoryStore implements RuntimeStore {
  readonly data = new Map<string, string>();
  async get(key: string): Promise<string | null> {
    return this.data.get(key) ?? null;
  }
  async set(key: string, value: string): Promise<void> {
    this.data.set(key, value);
  }
  async setMany(
    entries: readonly (readonly [string, string | null])[],
  ): Promise<void> {
    for (const [k, v] of entries) {
      if (v === null) this.data.delete(k);
      else this.data.set(k, v);
    }
  }
}
