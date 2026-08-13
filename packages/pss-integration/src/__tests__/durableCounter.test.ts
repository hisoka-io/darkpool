import { describe, expect, it } from "vitest";
import { DarkAccount } from "@hisoka/wallets";
import { KeyRepository } from "@hisoka/wallets/reference";
import {
  type ParsedStatePayload,
  emptyStatePayload,
  mergeStatePayloads,
  decodeStatePayload,
  serializeStatePayload,
} from "@hisoka/pss-client";
import {
  type CounterPayloadPort,
  PssEphemeralCounterStore,
} from "../pssEphemeralCounterStore.js";

const MNEMONIC = "test test test test test test test test test test test junk";
const INSTALL = "0x11111111111111111111111111111111";

/**
 * A durable medium that survives a simulated restart: the payload is held as SERIALISED JSON, exactly as
 * PSS stores it, so a restart is re-parsing that string rather than reusing an object.
 */
class JsonPayloadPort implements CounterPayloadPort {
  #json: string;

  constructor(json?: string) {
    this.#json =
      json ?? serializeStatePayload(emptyStatePayload(INSTALL, "web", 1));
  }

  current(): ParsedStatePayload {
    return decodeStatePayload(this.#json);
  }

  update(
    change: (current: ParsedStatePayload) => ParsedStatePayload,
  ): Promise<void> {
    this.#json = serializeStatePayload(change(this.current()));
    return Promise.resolve();
  }

  /** What a restart reads back. */
  snapshot(): string {
    return this.#json;
  }
}

describe("the PSS-backed ephemeral counter", () => {
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

  it("trims the unused tail on commit and rewinds the whole span on release", async () => {
    const port = new JsonPayloadPort();
    const store = new PssEphemeralCounterStore(port);

    const a = await store.reserve("self", 16);
    await a.commit(3);
    expect(await store.highWater("self")).toBe(4);

    const b = await store.reserve("self", 16);
    expect(b.base).toBe(4);
    await b.release();
    // Rewound to base, which is exactly why a deterministic derivation must abandon instead.
    expect(await store.highWater("self")).toBe(4);
  });

  // The property the whole seam exists for.
  it("a highwater survives a simulated restart through the real PSS path", async () => {
    const account = await DarkAccount.fromMnemonic(MNEMONIC);

    const port = new JsonPayloadPort();
    const first = await new KeyRepository(
      account,
      new PssEphemeralCounterStore(port),
    ).nextSelfEphemeral();

    // The process dies. Everything in memory is gone; only the serialised payload survives.
    const restarted = new JsonPayloadPort(port.snapshot());
    const second = await new KeyRepository(
      account,
      new PssEphemeralCounterStore(restarted),
    ).nextSelfEphemeral();

    expect(second.index).toBeGreaterThan(first.index);
    expect(second.eph.toString()).not.toBe(first.eph.toString());
  });

  it("hands two concurrent reservations different bases", async () => {
    const store = new PssEphemeralCounterStore(new JsonPayloadPort());
    const [a, b] = await Promise.all([
      store.reserve("self", 4),
      store.reserve("self", 4),
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
