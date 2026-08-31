import { describe, expect, it } from "vitest";
import { DarkAccount } from "@hisoka/wallets";
import { KeyRepository } from "@hisoka/wallets/reference";
import {
  type ParsedStatePayload,
  emptyStatePayload,
  mergeStatePayloads,
  decodeStatePayload,
  serializeStatePayload,
  DEFAULT_SYNC_CONFIG,
  type PssStore,
  type PssTransport,
  StateSync,
  VersionFloor,
  deriveKeys,
  nobleBackend,
  toHexRaw,
} from "@hisoka/pss-client";
import {
  type CounterPayloadPort,
  PssEphemeralCounterStore,
} from "../pssEphemeralCounterStore.js";

const MNEMONIC = "test test test test test test test test test test test junk";
const INSTALL = "0x11111111111111111111111111111111";

class ReverseCompletionStore implements PssStore {
  readonly #cells = new Map<string, string>();
  #payloadWrites = 0;
  #releaseFirst: (() => void) | null = null;
  readonly firstPayloadWrite = new Promise<void>((resolve) => {
    this.#releaseFirst = resolve;
  });

  get(key: string): Promise<string | null> {
    return Promise.resolve(this.#cells.get(key) ?? null);
  }

  async set(key: string, value: string): Promise<void> {
    if (!key.includes(".payload.")) {
      this.#cells.set(key, value);
      return;
    }
    this.#payloadWrites += 1;
    if (this.#payloadWrites === 1) {
      await this.firstPayloadWrite;
    }
    this.#cells.set(key, value);
  }

  remove(key: string): Promise<void> {
    this.#cells.delete(key);
    return Promise.resolve();
  }

  releaseFirstWrite(): void {
    const release = this.#releaseFirst;
    if (release === null) throw new Error("first payload write is not held");
    this.#releaseFirst = null;
    release();
  }
}

function memoryTransport(): PssTransport {
  let blob: Awaited<ReturnType<PssTransport["getBlob"]>> = null;
  return {
    getBlob: () => Promise.resolve(blob),
    putBlob: (_account, _collection, body) => {
      blob = { ...body, serverTime: body.timestamp };
      return Promise.resolve();
    },
    deleteAccount: () => Promise.resolve(),
  };
}

/**
 * A durable medium that survives a simulated restart: the payload is held as SERIALISED JSON, exactly as
 * PSS stores it, so a restart is re-parsing that string rather than reusing an object.
 */
class JsonPayloadPort implements CounterPayloadPort {
  #json: string;
  #tail: Promise<void> = Promise.resolve();

  constructor(json?: string) {
    this.#json =
      json ?? serializeStatePayload(emptyStatePayload(INSTALL, "web", 1));
  }

  current(): ParsedStatePayload {
    return decodeStatePayload(this.#json);
  }

  mutateAsWriterDurably<T>(
    change: (current: ParsedStatePayload) => {
      readonly payload: ParsedStatePayload;
      readonly value: T;
    },
  ): Promise<T> {
    const mutate = (): T => {
      const mutation = change(this.current());
      this.#json = serializeStatePayload(mutation.payload);
      return mutation.value;
    };
    const run = this.#tail.then(mutate, mutate);
    this.#tail = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  /** What a restart reads back. */
  snapshot(): string {
    return this.#json;
  }
}

describe("the PSS-backed ephemeral counter", () => {
  it("keeps a resolved reservation when an older payload write completes last", async () => {
    const account = await DarkAccount.fromMnemonic(MNEMONIC);
    const keys = await deriveKeys(
      nobleBackend,
      Uint8Array.from((await account.getStateKey()).toBuffer()),
    );
    const store = new ReverseCompletionStore();
    const transport = memoryTransport();
    const open = (): Promise<StateSync> =>
      StateSync.open({
        store,
        floor: new VersionFloor(store, toHexRaw(keys.accountId)),
        transport,
        oracle: { spentBetween: () => Promise.resolve(new Set<string>()) },
        backend: nobleBackend,
        keys,
        config: DEFAULT_SYNC_CONFIG,
        platform: "test",
        now: () => 1_800_000_000_000,
        invite: "test-create",
      });
    const firstSync = await open();
    const oldUpdate = firstSync.update((payload) => ({
      known: { ...payload.known, incomingIssueHighwater: 9 },
      extra: payload.extra,
    }));
    await Promise.resolve();
    const pull = firstSync.pull();
    const prune = firstSync.pruneSpent(0, 0);

    const firstRepo = new KeyRepository(
      account,
      new PssEphemeralCounterStore(firstSync),
    );
    const firstMint = firstRepo.nextSelfEphemeral();
    await Promise.resolve();
    store.releaseFirstWrite();
    const first = await firstMint;
    expect(firstSync.current().known.ephemeralCounters.self).toBeGreaterThan(
      first.index,
    );
    await pull;
    await prune;
    await oldUpdate;
    await firstSync.stop();

    const restartedSync = await open();
    const restartedRepo = new KeyRepository(
      account,
      new PssEphemeralCounterStore(restartedSync),
    );
    const second = await restartedRepo.nextSelfEphemeral();
    expect(second.index).toBeGreaterThan(first.index);
    expect(second.eph.equals(first.eph)).toBe(false);
    await restartedSync.stop();
  });

  it("persists the advance before the reservation is returned", async () => {
    const port = new JsonPayloadPort();
    const store = new PssEphemeralCounterStore(port);

    const reservation = await store.reserve("self", 1);
    // Durable already, not on commit: a crash here must burn the index, never reissue it.
    expect(
      decodeStatePayload(port.snapshot()).known.ephemeralCounters.self,
    ).toBe(1);
    expect(reservation.base).toBe(0);

    await reservation.commit(0);
    expect(await store.highWater("self")).toBe(1);
  });

  it("burns unused indices so commits and releases cannot rewind", async () => {
    const port = new JsonPayloadPort();
    const store = new PssEphemeralCounterStore(port);

    const a = await store.reserve("self", 16);
    await a.commit(3);
    expect(await store.highWater("self")).toBe(16);

    const b = await store.reserve("self", 16);
    expect(b.base).toBe(16);
    await b.release();
    expect(await store.highWater("self")).toBe(32);
  });

  it("hands two concurrent reservations different bases", async () => {
    const port = new JsonPayloadPort();
    const left = new PssEphemeralCounterStore(port);
    const right = new PssEphemeralCounterStore(port);
    const [a, b] = await Promise.all([
      left.reserve("self", 4),
      right.reserve("self", 4),
    ]);
    expect(a.base).not.toBe(b.base);
    expect(Math.abs(a.base - b.base)).toBe(4);
  });

  // A merge that dropped a scope would rewind it to 0 and reissue every index it had handed out.
  it("keeps a counter that only one device knows about, through a merge", async () => {
    const account = await DarkAccount.fromMnemonic(MNEMONIC);
    const local = new JsonPayloadPort();
    await new KeyRepository(
      account,
      new PssEphemeralCounterStore(local),
    ).nextSelfEphemeral();

    const mine = decodeStatePayload(local.snapshot());
    const theirs = emptyStatePayload(INSTALL, "web", 2);
    const merged = mergeStatePayloads([
      { payload: mine, noteListComplete: true },
      { payload: theirs, noteListComplete: true },
    ]);

    expect(merged.known.ephemeralCounters.self).toBe(
      mine.known.ephemeralCounters.self,
    );
    expect(merged.known.ephemeralCounters.self).toBeGreaterThan(0);
  });
});
