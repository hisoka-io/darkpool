import { describe, expect, it } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import { leaf } from "@hisoka/wallets";
import { WalletRuntimeError } from "../errors.js";
import {
  NoteStore,
  noteKey,
  type NoteView,
  type StoredNote,
  type SyncPoint,
} from "../store/noteStore.js";
import type { RuntimeStore } from "../store/runtimeStore.js";
import { MemoryStore } from "./fixtures/store.js";
import { note } from "./fixtures/tree.js";

const KEY = "hisoka.runtime.v1.test.notes";

function block(n: number, fork = 0): { number: number; hash: string } {
  return {
    number: n,
    hash: `0x${(0xb10c0000 + fork * 0x10000 + n).toString(16).padStart(64, "0")}`,
  };
}

function at(n: number): SyncPoint {
  return { head: block(n), maxReorgBlocks: 16 };
}

async function stored(
  leafIndex: number,
  at: number,
  extra: Partial<StoredNote> = {},
): Promise<StoredNote> {
  const n = note(BigInt(leafIndex));
  return {
    leafIndex,
    commitment: await leaf(n),
    note: n,
    nullifier: new Fr(0x9000n + BigInt(leafIndex)),
    origin: "self",
    derivationIndex: leafIndex,
    complianceVersion: 1,
    block: block(at),
    verification: "verified",
    spent: null,
    mirrored: false,
    ...extra,
  };
}

const VIEW: NoteView = { confirmedHead: 50, sweptThrough: 50, now: 1_000n };

/** Counts writes and can fail the next one, as a crash between two writes would. */
class RecordingStore implements RuntimeStore {
  readonly inner = new MemoryStore();
  writes = 0;
  failNext = false;
  get(key: string): Promise<string | null> {
    return this.inner.get(key);
  }
  async set(key: string, value: string): Promise<void> {
    if (this.failNext) {
      this.failNext = false;
      throw new Error("disk full");
    }
    this.writes += 1;
    await this.inner.set(key, value);
  }
  async setMany(
    entries: readonly (readonly [string, string | null])[],
  ): Promise<void> {
    if (this.failNext) {
      this.failNext = false;
      throw new Error("disk full");
    }
    this.writes += 1;
    await this.inner.setMany(entries);
  }
}

describe("note store", () => {
  it("derives each note's state from the confirmed head, the sweep, spent marks and leases", async () => {
    const notes = await NoteStore.open(new MemoryStore(), KEY);
    const confirmed = await stored(1, 40);
    const unconfirmed = await stored(2, 55);
    const unswept = await stored(3, 45);
    const unverified = await stored(4, 40, { verification: "unverified" });
    const spent = await stored(5, 40, {
      spent: { block: block(48), txHash: "0x01" },
    });
    const spentPending = await stored(6, 40, {
      spent: { block: block(52), txHash: "0x02" },
    });
    await notes.record(
      [confirmed, unconfirmed, unswept, unverified, spent, spentPending],
      at(55),
    );
    const view = { ...VIEW, sweptThrough: 44 };
    expect(notes.notes.map((n) => notes.state(n, view))).toEqual([
      "spendable",
      "pending",
      "pending",
      "unverified",
      "spent",
      "spent-pending",
    ]);
    expect(notes.spendable(view).map((n) => n.leafIndex)).toEqual([1]);
    // Swept past it but above the confirmed head: still pending.
    expect(
      notes.state(unswept, { ...VIEW, confirmedHead: 44, sweptThrough: 50 }),
    ).toBe("pending");
  });

  it("names a note by leaf index and commitment, so a re-mined leaf is a different note", async () => {
    const notes = await NoteStore.open(new MemoryStore(), KEY);
    const a = await stored(7, 10);
    const b = { ...(await stored(7, 11)), commitment: await leaf(note(70n)) };
    await notes.record([a, b], at(11));
    expect(notes.notes).toHaveLength(2);
    expect(noteKey(a)).not.toBe(noteKey(b));
  });

  it("leases notes to one plan, refuses a second plan, and frees them on failure or expiry", async () => {
    const notes = await NoteStore.open(new MemoryStore(), KEY);
    const a = await stored(1, 10);
    await notes.record([a], at(10));
    await notes.acquire("plan-1", [noteKey(a)], 2_000n, 1_000n);
    expect(notes.state(a, VIEW)).toBe("spent-pending");
    const err = await notes
      .acquire("plan-2", [noteKey(a)], 2_000n, 1_000n)
      .catch((e: unknown) => e);
    expect((err as WalletRuntimeError).code).toBe("LEASE_HELD");
    expect((err as WalletRuntimeError).context.planId).toBe("plan-1");

    // Expired at chain time 2001: another plan may take it.
    await notes.acquire("plan-3", [noteKey(a)], 3_000n, 2_001n);
    await notes.updatePlan("plan-3", (p) => ({
      ...p,
      status: "failed",
      leased: [],
    }));
    expect(notes.state(a, { ...VIEW, now: 2_500n })).toBe("spendable");
    const unknown = await notes
      .updatePlan("nope", (p) => p)
      .catch((e: unknown) => e);
    expect((unknown as WalletRuntimeError).code).toBe("PLAN_UNKNOWN");
  });

  it("rolls back in ONE write: notes dropped, spent marks undone, plans orphaned, leases released, cursor moved", async () => {
    const store = new RecordingStore();
    const notes = await NoteStore.open(store, KEY);
    const kept = await stored(1, 10, {
      spent: { block: block(30), txHash: "0x0a" },
    });
    const unspend = await stored(2, 12, {
      spent: { block: block(35), txHash: "0x0b" },
      mirrored: true,
    });
    const droppedMirrored = await stored(3, 33, { mirrored: true });
    const droppedLocal = await stored(4, 34);
    const belowFork = await stored(5, 20, { mirrored: true });
    await notes.record(
      [kept, unspend, droppedMirrored, droppedLocal, belowFork],
      at(36),
    );
    await notes.markSpent([], 36);
    await notes.acquire("orphan", [noteKey(unspend)], 9_000n, 1n);
    await notes.updatePlan("orphan", (p) => ({
      ...p,
      status: "included",
      submission: { txHash: "0x0b", block: block(35) },
    }));
    await notes.acquire("older", [noteKey(kept)], 9_000n, 1n);
    await notes.updatePlan("older", (p) => ({
      ...p,
      status: "included",
      submission: { txHash: "0x0a", block: block(30) },
    }));

    const before = store.writes;
    const result = await notes.rollback({
      ancestor: block(31),
      orphaned: [block(33), block(34), block(35), block(36)],
    });
    expect(store.writes - before).toBe(1);

    expect(result.droppedNotes.map((n) => n.leafIndex).sort()).toEqual([3, 4]);
    expect(result.unspent.map((n) => n.leafIndex)).toEqual([2]);
    expect(result.orphanedPlans).toEqual(["orphan"]);
    expect(notes.notes.map((n) => n.leafIndex)).toEqual([1, 2, 5]);
    expect(notes.find(noteKey(unspend))?.spent).toBeNull();
    expect(notes.find(noteKey(kept))?.spent?.block.number).toBe(30);
    expect(notes.plans.find((p) => p.planId === "orphan")).toMatchObject({
      status: "orphaned",
      leased: [],
    });
    expect(notes.plans.find((p) => p.planId === "older")?.status).toBe(
      "included",
    );
    expect(notes.cursor).toEqual(block(31));
    expect(notes.sweptThrough).toBe(31);
    // Only the dropped note that reached PSS needs a tombstone there.
    expect(notes.pendingTombstones).toEqual([
      {
        leafIndex: 3,
        nullifier: `0x${(0x9003).toString(16).padStart(64, "0")}`,
        block: 33,
        blockHash: block(33).hash,
      },
    ]);

    const reopened = await NoteStore.open(store, KEY);
    expect(reopened.notes.map((n) => n.leafIndex)).toEqual([1, 2, 5]);
    expect(reopened.pendingTombstones).toHaveLength(1);
    expect(reopened.cursor).toEqual(block(31));
  });

  it("leaves the store untouched when the rollback write fails", async () => {
    const store = new RecordingStore();
    const notes = await NoteStore.open(store, KEY);
    await notes.record([await stored(1, 10), await stored(2, 40)], at(40));
    store.failNext = true;
    await expect(
      notes.rollback({ ancestor: block(20), orphaned: [block(40)] }),
    ).rejects.toThrow("disk full");
    expect(notes.notes.map((n) => n.leafIndex)).toEqual([1, 2]);
    expect(notes.cursor).toEqual(block(40));
    const reopened = await NoteStore.open(store, KEY);
    expect(reopened.notes.map((n) => n.leafIndex)).toEqual([1, 2]);
  });

  it("keeps a known note's spent mark and mirror flag when discovery reports it again", async () => {
    const notes = await NoteStore.open(new MemoryStore(), KEY);
    const a = await stored(1, 10, { verification: "unverified" });
    await notes.record([a], at(10));
    await notes.markSpent(
      [{ nullifier: a.nullifier, block: block(12), txHash: "0x0c" }],
      12,
    );
    await notes.markMirrored([noteKey(a)], []);
    await notes.record([{ ...a, verification: "verified" }], at(13));
    expect(notes.find(noteKey(a))).toMatchObject({
      verification: "verified",
      mirrored: true,
      spent: { block: block(12), txHash: "0x0c" },
    });
  });

  it("refuses to load a corrupt document instead of starting empty", async () => {
    const store = new MemoryStore();
    await store.set(KEY, '{"v":2,"notes":[{}]}');
    const err = await NoteStore.open(store, KEY).catch((e: unknown) => e);
    expect((err as WalletRuntimeError).code).toBe("STORE_CORRUPT");
  });
  it("never drops or tombstones a note whose block is still on the chain, even above the ancestor", async () => {
    const notes = await NoteStore.open(new MemoryStore(), KEY);
    const canonical = await stored(1, 30, { mirrored: true });
    const gone = await stored(2, 40, { mirrored: true });
    await notes.record([canonical, gone], at(41));
    const result = await notes.rollback({
      ancestor: block(10),
      orphaned: [block(40), block(41)],
    });
    expect(result.droppedNotes.map((n) => n.leafIndex)).toEqual([2]);
    expect(notes.notes.map((n) => n.leafIndex)).toEqual([1]);
    expect(notes.pendingTombstones.map((t) => t.leafIndex)).toEqual([2]);
    expect(notes.cursor).toEqual(block(10));
  });

  it("keeps a note's first inclusion block when discovery files it again under a later head", async () => {
    const notes = await NoteStore.open(new MemoryStore(), KEY);
    const a = await stored(1, 10);
    await notes.record([a], at(10));
    await notes.record([{ ...a, block: block(25) }], at(25));
    expect(notes.find(noteKey(a))?.block).toEqual(block(10));
    expect(
      notes.state(notes.find(noteKey(a))!, { ...VIEW, confirmedHead: 20 }),
    ).toBe("spendable");
  });

  it("clears a pending tombstone when the same note is recorded again", async () => {
    const notes = await NoteStore.open(new MemoryStore(), KEY);
    const a = await stored(1, 10, { mirrored: true });
    const b = await stored(2, 11, { mirrored: true });
    await notes.record([a, b], at(11));
    await notes.rollback({
      ancestor: block(9),
      orphaned: [block(10), block(11)],
    });
    expect(notes.pendingTombstones.map((t) => t.leafIndex)).toEqual([1, 2]);
    await notes.record([{ ...a, mirrored: false }], at(12));
    expect(notes.pendingTombstones.map((t) => t.leafIndex)).toEqual([2]);
  });

  it("keeps earlier sync heads inside the reorg bound plus the newest one below it", async () => {
    const store = new MemoryStore();
    const notes = await NoteStore.open(store, KEY);
    for (const n of [10, 20, 30, 40]) await notes.record([], at(n));
    expect(notes.cursor).toEqual(block(40));
    expect(notes.heads).toEqual([block(20), block(30)]);
    const reopened = await NoteStore.open(store, KEY);
    expect(reopened.heads).toEqual([block(20), block(30)]);
  });

  it("settles a submitted plan only after its deadline at a swept confirmed head, from what the sweep saw", async () => {
    const notes = await NoteStore.open(new MemoryStore(), KEY);
    const quiet = await stored(1, 10);
    const landed = await stored(2, 10);
    const fee = await stored(3, 10);
    const action = await stored(4, 10);
    await notes.record([quiet, landed, fee, action], at(10));
    const submit = async (
      id: string,
      keys: string[],
      resume: bigint | null,
    ) => {
      await notes.acquire(id, keys, 2_000n, 1_000n);
      await notes.updatePlan(id, (p) => ({
        ...p,
        status: "submitted",
        resume:
          resume === null
            ? null
            : { executionId: `0x${"12".repeat(32)}`, validUntilUnix: resume },
      }));
    };
    const stateAt = (n: StoredNote, now: bigint) =>
      notes.state(notes.find(noteKey(n))!, { ...VIEW, now });
    await submit("quiet", [noteKey(quiet)], null);
    await submit("landed", [noteKey(landed)], 5_000n);
    await submit("half", [noteKey(fee), noteKey(action)], 5_000n);
    await notes.markSpent(
      [
        { nullifier: landed.nullifier, block: block(48), txHash: "0x0d" },
        { nullifier: fee.nullifier, block: block(48), txHash: "0x0e" },
      ],
      50,
    );

    // Before every deadline, and with the sweep behind the confirmed head, nothing moves.
    expect(await notes.settleSubmitted({ ...VIEW, now: 2_000n })).toEqual([]);
    expect(
      await notes.settleSubmitted({
        confirmedHead: 50,
        sweptThrough: 49,
        now: 9_000n,
      }),
    ).toEqual([]);
    expect(stateAt(quiet, 9_000n)).toBe("spent-pending");

    // Past the lease end only the plan without a resume token is due: nothing of it landed, so it is released.
    const first = await notes.settleSubmitted({ ...VIEW, now: 2_001n });
    expect(first.map((p) => [p.planId, p.status])).toEqual([
      ["quiet", "failed"],
    ]);
    expect(stateAt(quiet, 2_001n)).toBe("spendable");
    expect(stateAt(fee, 2_001n)).toBe("spent");

    // Past validUntilUnix: one plan landed whole, the other paid its fee and its action did not.
    const second = await notes.settleSubmitted({ ...VIEW, now: 5_001n });
    expect(second.map((p) => [p.planId, p.status])).toEqual([
      ["landed", "included"],
      ["half", "reverted"],
    ]);
    expect(notes.plans.find((p) => p.planId === "landed")?.submission).toEqual({
      txHash: "0x0d",
      block: block(48),
    });
    expect(stateAt(action, 5_001n)).toBe("spendable");
  });

  it("holds a submitted plan whose spend is still above the confirmed head", async () => {
    const notes = await NoteStore.open(new MemoryStore(), KEY);
    const a = await stored(1, 10);
    await notes.record([a], at(10));
    await notes.acquire("p", [noteKey(a)], 2_000n, 1_000n);
    await notes.updatePlan("p", (p) => ({ ...p, status: "submitted" }));
    await notes.markSpent(
      [{ nullifier: a.nullifier, block: block(52), txHash: "0x0f" }],
      52,
    );
    expect(
      await notes.settleSubmitted({
        confirmedHead: 50,
        sweptThrough: 52,
        now: 9_000n,
      }),
    ).toEqual([]);
    expect(notes.plans[0]?.status).toBe("submitted");
  });
});
