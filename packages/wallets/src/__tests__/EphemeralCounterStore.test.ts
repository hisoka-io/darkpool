import { describe, it, expect } from "vitest";
import { InMemoryEphemeralCounterStore } from "../state/EphemeralCounterStore.js";
import { DarkAccount } from "../keys/DarkAccount.js";
import { KeyRepository } from "../state/KeyRepository.js";

// WC-1 / I-1: a reused self-eph index reuses the CEK -> the additive Poseidon2 DEM keystream = two-time-pad.
// The store's job is to make that structurally impossible: reserve() durably advances the high-water before any
// index is handed out.
describe("EphemeralCounterStore (WC-1)", () => {
  it("monotonic: sequential reserves have strictly increasing base", async () => {
    const s = new InMemoryEphemeralCounterStore();
    const a = await s.reserve("self", 4);
    const b = await s.reserve("self", 4);
    expect(a.base).toBe(0);
    expect(b.base).toBe(4);
  });

  it("commit reclaims the unused tail so indices stay dense", async () => {
    const s = new InMemoryEphemeralCounterStore();
    const r = await s.reserve("self", 256);
    await r.commit(3);
    expect(await s.highWater("self")).toBe(4);
    expect((await s.reserve("self", 256)).base).toBe(4);
  });

  it("release reclaims the whole span when still the top", async () => {
    const s = new InMemoryEphemeralCounterStore();
    await (await s.reserve("self", 10)).release();
    expect(await s.highWater("self")).toBe(0);
  });

  it("commit never rewinds below a later reserve (no reuse under interleaving)", async () => {
    const s = new InMemoryEphemeralCounterStore();
    const r1 = await s.reserve("self", 256);
    const r2 = await s.reserve("self", 256);
    await r1.commit(3);
    expect(await s.highWater("self")).toBe(512);
    await r2.commit(300);
    expect(await s.highWater("self")).toBe(301);
  });

  it("CRASH between reserve and use cannot reissue (write-ahead is persisted)", async () => {
    const s = new InMemoryEphemeralCounterStore();
    const r = await s.reserve("self", 256);
    const restarted = new InMemoryEphemeralCounterStore(s.snapshot());
    const after = await restarted.reserve("self", 256);
    expect(after.base).toBeGreaterThanOrEqual(r.base + r.span);
  });

  it("concurrent reserves never collide", async () => {
    const s = new InMemoryEphemeralCounterStore();
    const bases = (
      await Promise.all(Array.from({ length: 50 }, () => s.reserve("self", 1)))
    ).map((r) => r.base);
    expect(new Set(bases).size).toBe(bases.length);
    expect(await s.highWater("self")).toBe(50);
  });

  it("refuses (rejects) on a durable-write failure, high-water unchanged", async () => {
    const s = new InMemoryEphemeralCounterStore();
    s.failNextWrite();
    await expect(s.reserve("self", 4)).rejects.toThrow(/durable write failed/);
    expect(await s.highWater("self")).toBe(0);
    expect((await s.reserve("self", 4)).base).toBe(0);
  });

  it("scopes are independent (self vs ms:<memberId>)", async () => {
    const s = new InMemoryEphemeralCounterStore();
    await s.reserve("self", 5);
    await s.reserve("ms:1", 3);
    expect(await s.highWater("self")).toBe(5);
    expect(await s.highWater("ms:1")).toBe(3);
    expect((await s.reserve("self", 1)).base).toBe(5);
    expect((await s.reserve("ms:1", 1)).base).toBe(3);
  });

  it("rejects a non-positive span and an out-of-span commit", async () => {
    const s = new InMemoryEphemeralCounterStore();
    await expect(s.reserve("self", 0)).rejects.toThrow(/positive/);
    const r = await s.reserve("self", 4);
    await expect(r.commit(99)).rejects.toThrow(/out of reserved span/);
  });
});

describe("KeyRepository self-eph durability (WC-1)", () => {
  const MNEMONIC =
    "test test test test test test test test test test test junk";

  it("a crash after mint but before persist cannot reissue a self-eph index", async () => {
    const account = await DarkAccount.fromMnemonic(MNEMONIC);
    const store = new InMemoryEphemeralCounterStore();
    const m1 = await new KeyRepository(account, store).nextSelfEphemeral();
    // "Crash": the durable store already persisted the reserve; restart from the same durable image.
    const restarted = new InMemoryEphemeralCounterStore(store.snapshot());
    const m2 = await new KeyRepository(account, restarted).nextSelfEphemeral();
    expect(m2.index).toBeGreaterThan(m1.index);
    expect(m2.eph.toString()).not.toBe(m1.eph.toString());
  });

  it("fail-closed: a repo with no configured counter refuses to mint", async () => {
    const account = await DarkAccount.fromMnemonic(MNEMONIC);
    const repo = new KeyRepository(account); // sealed default
    await expect(repo.nextSelfEphemeral()).rejects.toThrow(
      /no durable ephemeral counter configured/,
    );
  });

  it("mints once an explicit in-memory store is provided (test opt-in)", async () => {
    const account = await DarkAccount.fromMnemonic(MNEMONIC);
    const repo = new KeyRepository(
      account,
      new InMemoryEphemeralCounterStore(),
    );
    const a = await repo.nextSelfEphemeral();
    const b = await repo.nextSelfEphemeral();
    expect(b.index).toBeGreaterThan(a.index);
  });
});
