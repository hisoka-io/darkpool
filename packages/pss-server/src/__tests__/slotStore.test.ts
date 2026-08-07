import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import type { Collection } from "@hisoka/pss-client/wire";
import { defaultMigrationsDir } from "../config.js";
import { loadMigrations, runMigrations, today } from "../db/migrate.js";
import { retentionCutoff } from "../db/retention.js";
import type { InviteGate, SlotStore, SlotWrite } from "../db/slotStore.js";
import { openSlotStore } from "../db/sqliteSlotStore.js";

const ACCOUNT = new Uint8Array(32).fill(0xa1);
const OTHER = new Uint8Array(32).fill(0xb2);
const NONCE = new Uint8Array(12).fill(0xc3);
const OPEN: InviteGate = { required: false };
const DAY = "2026-08-07";

let directory: string;

function migrate(db: Database.Database): void {
  runMigrations(db, loadMigrations(defaultMigrationsDir()));
}

function memoryStore(): { db: Database.Database; store: SlotStore } {
  const db = new Database(":memory:");
  migrate(db);
  return { db, store: openSlotStore(db) };
}

function write(
  version: number,
  prevVersion: number,
  overrides: Partial<SlotWrite> = {},
): SlotWrite {
  return {
    accountId: ACCOUNT,
    collection: "state" as Collection,
    version,
    prevVersion,
    nonce: NONCE,
    ciphertext: Uint8Array.of(version),
    updatedOn: DAY,
    ...overrides,
  };
}

function addInvite(db: Database.Database, code: string): void {
  db.prepare("INSERT INTO invites (code_hash, spent) VALUES (?, 0)").run(
    createHash("sha256").update(code, "utf8").digest(),
  );
}

beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), "pss-slotstore-"));
});

afterEach(() => {
  rmSync(directory, { recursive: true, force: true });
});

describe("compare and swap", () => {
  it("creates the first row through the insert arm", () => {
    const { store } = memoryStore();
    expect(store.upsert(write(1, 0), OPEN)).toBe("written");
    expect(store.get(ACCOUNT, "state")).toEqual({
      version: 1,
      prevVersion: 0,
      nonce: NONCE,
      ciphertext: Uint8Array.of(1),
      updatedOn: DAY,
    });
  });

  it("advances a slot whose stored version is the declared prevVersion", () => {
    const { store } = memoryStore();
    store.upsert(write(1, 0), OPEN);
    expect(store.upsert(write(2, 1), OPEN)).toBe("written");
    expect(store.get(ACCOUNT, "state")?.version).toBe(2);
  });

  it("refuses a gap, a repeat and a rollback", () => {
    const { store } = memoryStore();
    store.upsert(write(1, 0), OPEN);
    expect(store.upsert(write(3, 2), OPEN)).toBe("conflict");
    expect(store.upsert(write(1, 0), OPEN)).toBe("conflict");
    expect(store.upsert(write(2, 0), OPEN)).toBe("conflict");
    expect(store.get(ACCOUNT, "state")?.version).toBe(1);
  });

  it("keeps the two collections independent", () => {
    const { store } = memoryStore();
    store.upsert(write(1, 0), OPEN);
    expect(store.upsert(write(1, 0, { collection: "labels" }), OPEN)).toBe(
      "written",
    );
    expect(store.get(ACCOUNT, "labels")?.version).toBe(1);
  });

  it("gives exactly one winner to two writers that read the same version", () => {
    const path = join(directory, "race.db");
    const seed = new Database(path);
    migrate(seed);
    openSlotStore(seed).upsert(write(1, 0), OPEN);
    seed.close();

    const left = new Database(path);
    const right = new Database(path);
    const leftStore = openSlotStore(left);
    const rightStore = openSlotStore(right);

    const leftSeen = leftStore.get(ACCOUNT, "state")?.version ?? 0;
    const rightSeen = rightStore.get(ACCOUNT, "state")?.version ?? 0;
    expect(leftSeen).toBe(rightSeen);

    const outcomes = [
      leftStore.upsert(
        write(leftSeen + 1, leftSeen, { ciphertext: Uint8Array.of(0x11) }),
        OPEN,
      ),
      rightStore.upsert(
        write(rightSeen + 1, rightSeen, { ciphertext: Uint8Array.of(0x22) }),
        OPEN,
      ),
    ];
    expect(outcomes.filter((outcome) => outcome === "written")).toHaveLength(1);
    expect(leftStore.get(ACCOUNT, "state")?.ciphertext).toEqual(
      Uint8Array.of(0x11),
    );
    left.close();
    right.close();
  });

  it("gives exactly one winner to two racing creators", () => {
    const path = join(directory, "create.db");
    const seed = new Database(path);
    migrate(seed);
    seed.close();

    const left = new Database(path);
    const right = new Database(path);
    const outcomes = [
      openSlotStore(left).upsert(write(1, 0), OPEN),
      openSlotStore(right).upsert(write(1, 0), OPEN),
    ];
    expect(outcomes.filter((outcome) => outcome === "written")).toHaveLength(1);
    left.close();
    right.close();
  });
});

describe("invite gate", () => {
  it("spends a code once and refuses the same code for the next account", () => {
    const { db, store } = memoryStore();
    addInvite(db, "alpha");
    expect(store.upsert(write(1, 0), { required: true, code: "alpha" })).toBe(
      "written",
    );
    expect(
      store.upsert(write(1, 0, { accountId: OTHER }), {
        required: true,
        code: "alpha",
      }),
    ).toBe("invite_rejected");
    expect(store.get(OTHER, "state")).toBeNull();
  });

  it("refuses a create with no code and one with an unknown code", () => {
    const { store } = memoryStore();
    expect(store.upsert(write(1, 0), { required: true, code: null })).toBe(
      "invite_rejected",
    );
    expect(store.upsert(write(1, 0), { required: true, code: "nope" })).toBe(
      "invite_rejected",
    );
    expect(store.get(ACCOUNT, "state")).toBeNull();
  });

  it("stores the digest of a code and never the code", () => {
    const { db, store } = memoryStore();
    addInvite(db, "alpha");
    store.upsert(write(1, 0), { required: true, code: "alpha" });
    const rows = db.prepare("SELECT code_hash, spent FROM invites").all() as {
      code_hash: Buffer;
      spent: number;
    }[];
    expect(rows).toHaveLength(1);
    expect(rows[0].spent).toBe(1);
    expect(rows[0].code_hash.toString("utf8")).not.toContain("alpha");
    expect(rows[0].code_hash).toEqual(
      createHash("sha256").update("alpha", "utf8").digest(),
    );
  });

  it("burns no code when another writer created the account first", () => {
    const path = join(directory, "gate.db");
    const seed = new Database(path);
    migrate(seed);
    addInvite(seed, "alpha");
    seed.close();

    const left = new Database(path);
    const right = new Database(path);
    expect(openSlotStore(left).upsert(write(1, 0), { required: false })).toBe(
      "written",
    );
    expect(
      openSlotStore(right).upsert(write(1, 0), {
        required: true,
        code: "alpha",
      }),
    ).toBe("conflict");
    const spent = right.prepare("SELECT spent FROM invites").get() as {
      spent: number;
    };
    expect(spent.spent).toBe(0);
    left.close();
    right.close();
  });

  it("does not consult the gate for an account that already owns a row", () => {
    const { db, store } = memoryStore();
    store.upsert(write(1, 0), { required: false });
    expect(store.upsert(write(2, 1), { required: true, code: null })).toBe(
      "written",
    );
    expect(db.prepare("SELECT COUNT(*) AS n FROM invites").get()).toEqual({
      n: 0,
    });
  });
});

describe("delete and sweep", () => {
  it("erases every collection of one account and leaves the others", () => {
    const { store } = memoryStore();
    store.upsert(write(1, 0), OPEN);
    store.upsert(write(1, 0, { collection: "labels" }), OPEN);
    store.upsert(write(1, 0, { accountId: OTHER }), OPEN);

    expect(store.deleteAccount(ACCOUNT)).toBe(2);
    expect(store.get(ACCOUNT, "state")).toBeNull();
    expect(store.get(ACCOUNT, "labels")).toBeNull();
    expect(store.get(OTHER, "state")?.version).toBe(1);
    expect(store.deleteAccount(ACCOUNT)).toBe(0);
  });

  it("sweeps only the rows written before the retention cutoff", () => {
    const { store } = memoryStore();
    const now = new Date(Date.UTC(2026, 7, 7));
    const retentionDays = 400;
    const cutoff = retentionCutoff(now, retentionDays);

    store.upsert(write(1, 0, { updatedOn: cutoff }), OPEN);
    store.upsert(
      write(1, 0, {
        accountId: OTHER,
        updatedOn: today(new Date(Date.UTC(2024, 0, 1))),
      }),
      OPEN,
    );

    expect(store.sweepExpired(cutoff)).toBe(1);
    expect(store.get(ACCOUNT, "state")?.version).toBe(1);
    expect(store.get(OTHER, "state")).toBeNull();
  });

  it("anchors the cutoff on a date and moves with the injected clock", () => {
    expect(retentionCutoff(new Date(Date.UTC(2026, 7, 7)), 400)).toBe(
      "2025-07-03",
    );
    expect(retentionCutoff(new Date(Date.UTC(2026, 7, 7, 23, 59, 59)), 1)).toBe(
      "2026-08-06",
    );
    expect(retentionCutoff(new Date(Date.UTC(2026, 7, 7)), 0)).toBe(
      "2026-08-07",
    );
  });
});
