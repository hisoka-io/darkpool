import { describe, expect, it } from "vitest";
import { DarkAccount } from "../keys/DarkAccount.js";
import { KeyRepository } from "../state/KeyRepository.js";
import {
  InMemoryEphemeralCounterStore,
  PersistentEphemeralCounterStore,
  type CounterSnapshot,
} from "../index.js";
import {
  acquireSelfEphemeral,
  EphemeralCollisionError,
} from "../discovery/guardedMint.js";
import { discoveryTag, publicKey } from "../note/keys.js";
import type { DiscoverySource, FirstOccurrence } from "../discovery/types.js";

const MNEMONIC = "test test test test test test test test test test test junk";
const SCOPE = "self";

function sourceOccupying(tags: readonly string[]): DiscoverySource {
  return {
    probeFirst: async (asked): Promise<FirstOccurrence[]> =>
      asked.map((tag) => ({
        tag,
        record: null,
        occurrenceCount: tags.includes(tag.toString()) ? 1 : 0,
      })),
    fetchOccurrences: async (r) => r.map(() => null),
    fetchLeafBlock: async () => [],
  };
}

describe("fire-and-ratchet acquisition", () => {
  it("does not block on the probe: the index is available before confirm resolves", async () => {
    const account = await DarkAccount.fromMnemonic(MNEMONIC);
    const store = new InMemoryEphemeralCounterStore();
    const keys = new KeyRepository(account, store);

    let released!: () => void;
    const gate = new Promise<void>((r) => (released = r));
    const slow: DiscoverySource = {
      probeFirst: async (asked) => {
        await gate;
        return asked.map((tag) => ({ tag, record: null, occurrenceCount: 0 }));
      },
      fetchOccurrences: async (r) => r.map(() => null),
      fetchLeafBlock: async () => [],
    };

    const acquired = await acquireSelfEphemeral(keys, slow, store, SCOPE);
    // The caller can already prove with this: the probe has not answered yet.
    expect(acquired.index).toBeGreaterThanOrEqual(0);
    released();
    await expect(acquired.confirm()).resolves.toBeUndefined();
  });

  it("rejects at confirm when the index is already on chain, and ratchets past it", async () => {
    const account = await DarkAccount.fromMnemonic(MNEMONIC);
    const store = new InMemoryEphemeralCounterStore();
    const keys = new KeyRepository(account, store);

    const peek = await new KeyRepository(
      account,
      new InMemoryEphemeralCounterStore(),
    ).nextSelfEphemeral();
    const source = sourceOccupying([
      discoveryTag(publicKey(peek.eph)).toString(),
    ]);

    const acquired = await acquireSelfEphemeral(keys, source, store, SCOPE);
    expect(acquired.index).toBe(peek.index);
    await expect(acquired.confirm()).rejects.toBeInstanceOf(
      EphemeralCollisionError,
    );

    // Ratcheted, so the retry cannot repeat the occupied index.
    const retry = await new KeyRepository(account, store).nextSelfEphemeral();
    expect(retry.index).toBeGreaterThan(peek.index);
  });

  it("a discovery service that is down must not block a spend", async () => {
    const account = await DarkAccount.fromMnemonic(MNEMONIC);
    const store = new InMemoryEphemeralCounterStore();
    const keys = new KeyRepository(account, store);
    const down: DiscoverySource = {
      probeFirst: async () => {
        throw new Error("raven unreachable");
      },
      fetchOccurrences: async (r) => r.map(() => null),
      fetchLeafBlock: async () => [],
    };
    const acquired = await acquireSelfEphemeral(keys, down, store, SCOPE);
    await expect(acquired.confirm()).resolves.toBeUndefined();
  });
});

describe("PersistentEphemeralCounterStore", () => {
  it("survives a restart, because reserve persists before it returns", async () => {
    let disk: CounterSnapshot = {};
    const persistence = {
      read: () => disk,
      write: async (change: (c: CounterSnapshot) => CounterSnapshot) => {
        disk = change(disk);
      },
    };
    const account = await DarkAccount.fromMnemonic(MNEMONIC);

    const before = new PersistentEphemeralCounterStore(persistence);
    const first = await new KeyRepository(account, before).nextSelfEphemeral();

    // Process dies. Only `disk` survives.
    const after = new PersistentEphemeralCounterStore({
      read: () => disk,
      write: persistence.write,
    });
    const second = await new KeyRepository(account, after).nextSelfEphemeral();
    expect(second.index).toBeGreaterThan(first.index);
  });

  it("refuses to hand out an index when the durable write fails", async () => {
    const store = new PersistentEphemeralCounterStore({
      read: () => ({}),
      write: async () => {
        throw new Error("disk full");
      },
    });
    await expect(store.reserve(SCOPE, 1)).rejects.toThrow(/disk full/);
  });

  it("serialises concurrent reserves so no two callers get the same base", async () => {
    let disk: CounterSnapshot = {};
    const store = new PersistentEphemeralCounterStore({
      read: () => disk,
      write: async (change) => {
        await new Promise((r) => setTimeout(r, 1));
        disk = change(disk);
      },
    });
    const bases = (
      await Promise.all([1, 1, 1, 1].map(() => store.reserve(SCOPE, 1)))
    ).map((r) => r.base);
    expect(new Set(bases).size).toBe(4);
  });
});
