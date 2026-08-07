import { describe, expect, it } from "vitest";
import Database from "better-sqlite3";
import { defaultMigrationsDir } from "../config.js";
import { loadMigrations, runMigrations, today } from "../db/migrate.js";

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

  it("gives invites no column that could name an account", () => {
    const columns = migratedDb()
      .prepare("SELECT name FROM pragma_table_info('invites')")
      .all()
      .map((row) => (row as { name: string }).name);
    expect(columns).toEqual(["code_hash", "spent"]);
  });

  it("rejects a slot whose updated_on is a timestamp rather than a date", () => {
    const db = migratedDb();
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
          "INSERT INTO slots (account_id, collection, version, prev_version, nonce, ciphertext, updated_on) " +
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .run(
          Buffer.alloc(32),
          "secrets",
          1,
          0,
          Buffer.alloc(12),
          Buffer.of(1),
          "2026-08-07",
        ),
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
