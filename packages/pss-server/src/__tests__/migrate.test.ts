import { describe, expect, it } from "vitest";
import Database from "better-sqlite3";
import { defaultMigrationsDir } from "../config.js";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  MigrationError,
  loadMigrations,
  runMigrations,
  today,
} from "../db/migrate.js";
import { openSlotStore } from "../db/sqliteSlotStore.js";

function migratedDb(): Database.Database {
  const db = new Database(":memory:");
  runMigrations(db, loadMigrations(defaultMigrationsDir()));
  return db;
}

function tableNames(db: Database.Database): string[] {
  return db
    .prepare(
      "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name",
    )
    .all()
    .map((row) => (row as { name: string }).name);
}

describe("migrations", () => {
  it("removes retention metadata without changing either stored collection", () => {
    const db = new Database(":memory:");
    const migrations = loadMigrations(defaultMigrationsDir());
    const initial = migrations.find((migration) =>
      migration.name.startsWith("001_"),
    );
    expect(initial).toBeDefined();
    runMigrations(db, [initial!]);

    const insert = db.prepare(
      "INSERT INTO slots " +
        "(account_id, collection, version, prev_version, nonce, ciphertext, updated_on) " +
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
    );
    const stateAccountId = Buffer.alloc(32, 0xa1);
    const labelsAccountId = Buffer.alloc(32, 0xd4);
    const state = {
      collection: "state",
      version: 9,
      prevVersion: 7,
      nonce: Buffer.alloc(12, 0xb2),
      ciphertext: Buffer.from([1, 3, 5, 7]),
    } as const;
    const labels = {
      collection: "labels",
      version: 12,
      prevVersion: 11,
      nonce: Buffer.alloc(12, 0xc3),
      ciphertext: Buffer.from([2, 4, 6, 8, 10]),
    } as const;
    for (const [accountId, row] of [
      [stateAccountId, state],
      [labelsAccountId, labels],
    ] as const) {
      insert.run(
        accountId,
        row.collection,
        row.version,
        row.prevVersion,
        row.nonce,
        row.ciphertext,
        "2020-01-01",
      );
    }

    const applied = runMigrations(db, migrations);
    expect(applied).toEqual(["002_remove_slot_retention.sql"]);
    const rows = db
      .prepare(
        "SELECT account_id, collection, version, prev_version, nonce, ciphertext " +
          "FROM slots ORDER BY collection",
      )
      .all() as Array<{
      collection: string;
      account_id: Buffer;
      version: number;
      prev_version: number;
      nonce: Buffer;
      ciphertext: Buffer;
    }>;
    expect(rows).toEqual([
      {
        account_id: labelsAccountId,
        collection: labels.collection,
        version: labels.version,
        prev_version: labels.prevVersion,
        nonce: labels.nonce,
        ciphertext: labels.ciphertext,
      },
      {
        account_id: stateAccountId,
        collection: state.collection,
        version: state.version,
        prev_version: state.prevVersion,
        nonce: state.nonce,
        ciphertext: state.ciphertext,
      },
    ]);
    const columns = db
      .prepare("PRAGMA table_info(slots)")
      .all()
      .map((row) => (row as { name: string }).name);
    const indexes = db
      .prepare("PRAGMA index_list(slots)")
      .all()
      .map((row) => (row as { name: string }).name);
    expect(columns).not.toContain("updated_on");
    expect(indexes).not.toContain("slots_updated_on");
    const store = openSlotStore(db);
    expect(store.get(stateAccountId, "state")?.ciphertext).toEqual(
      Uint8Array.from(state.ciphertext),
    );
    expect(store.get(labelsAccountId, "labels")?.ciphertext).toEqual(
      Uint8Array.from(labels.ciphertext),
    );
  });

  it("applies every numbered file exactly once", () => {
    const db = new Database(":memory:");
    const migrations = loadMigrations(defaultMigrationsDir());
    expect(migrations.length).toBeGreaterThan(0);

    const first = runMigrations(db, migrations);
    expect(first).toEqual(migrations.map((m) => m.name));

    const second = runMigrations(db, migrations);
    expect(second).toEqual([]);
  });

  it("creates the slots and invites tables", () => {
    expect(tableNames(migratedDb())).toEqual([
      "applied_migrations",
      "invites",
      "slots",
    ]);
  });

  it("preserves the composite primary key after the table rebuild", () => {
    const db = migratedDb();
    const insert = db.prepare(
      "INSERT INTO slots " +
        "(account_id, collection, version, prev_version, nonce, ciphertext) " +
        "VALUES (?, 'state', 1, 0, ?, ?)",
    );
    const accountId = Buffer.alloc(32, 0xd4);
    insert.run(accountId, Buffer.alloc(12), Buffer.of(1));
    expect(() =>
      insert.run(accountId, Buffer.alloc(12), Buffer.of(2)),
    ).toThrow();
  });

  it("gives invites no column that could name an account", () => {
    const columns = migratedDb()
      .prepare("SELECT name FROM pragma_table_info('invites')")
      .all()
      .map((row) => (row as { name: string }).name);
    expect(columns).toEqual(["code_hash", "spent"]);
  });

  it("the historical schema rejects an updated_on timestamp rather than a date", () => {
    const db = new Database(":memory:");
    const initial = loadMigrations(defaultMigrationsDir()).find((migration) =>
      migration.name.startsWith("001_"),
    );
    expect(initial).toBeDefined();
    runMigrations(db, [initial!]);
    const insert = db.prepare(
      "INSERT INTO slots (account_id, collection, version, prev_version, nonce, ciphertext, updated_on) " +
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
    );
    const row = [
      Buffer.alloc(32),
      "state",
      1,
      0,
      Buffer.alloc(12),
      Buffer.of(1),
    ] as const;
    expect(() => insert.run(...row, "2026-08-07T10:11:12Z")).toThrow();
    expect(() => insert.run(...row, "2026-08-07")).not.toThrow();
  });

  it("rejects an unknown collection", () => {
    const db = migratedDb();
    expect(() =>
      db
        .prepare(
          "INSERT INTO slots (account_id, collection, version, prev_version, nonce, ciphertext) " +
            "VALUES (?, ?, ?, ?, ?, ?)",
        )
        .run(Buffer.alloc(32), "secrets", 1, 0, Buffer.alloc(12), Buffer.of(1)),
    ).toThrow();
  });

  it("stamps applied_on as a date", () => {
    const stamped = migratedDb()
      .prepare("SELECT applied_on FROM applied_migrations LIMIT 1")
      .get() as { applied_on: string };
    expect(stamped.applied_on).toMatch(/^\d{4}-\d{2}-\d{2}$/);
  });

  it("formats a date without an instant", () => {
    expect(today(new Date(Date.UTC(2026, 7, 7, 23, 59, 59)))).toBe(
      "2026-08-07",
    );
  });
});

describe("migration naming", () => {
  // Apply order is lexical, so a file that does not carry a zero-padded numeric prefix has undefined
  // order relative to its siblings. The rule exists; nothing exercised it.
  it("refuses a migration whose name does not fix its apply order", () => {
    const dir = mkdtempSync(join(tmpdir(), "pss-migrations-"));
    try {
      writeFileSync(join(dir, "001_init.sql"), "SELECT 1;");
      writeFileSync(join(dir, "1_bad.sql"), "SELECT 1;");
      expect(() => loadMigrations(dir)).toThrow(MigrationError);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
