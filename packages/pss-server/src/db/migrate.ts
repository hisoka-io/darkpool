import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { Database } from "better-sqlite3";

const MIGRATION_SHAPE = /^\d{3}_[a-z0-9_]+\.sql$/;

export interface Migration {
  readonly name: string;
  readonly sql: string;
}

export class MigrationError extends Error {
  constructor(detail: string) {
    super(`PSS migration: ${detail}`);
    this.name = "MigrationError";
  }
}

export function loadMigrations(dir: string): Migration[] {
  const names = readdirSync(dir)
    .filter((name) => name.endsWith(".sql"))
    .sort();
  for (const name of names) {
    if (!MIGRATION_SHAPE.test(name)) {
      throw new MigrationError(
        `${name} does not match NNN_lower_snake.sql, so apply order is undefined`,
      );
    }
  }
  return names.map((name) => ({
    name,
    sql: readFileSync(join(dir, name), "utf8"),
  }));
}

export function runMigrations(
  db: Database,
  migrations: readonly Migration[],
): string[] {
  db.exec(
    "CREATE TABLE IF NOT EXISTS applied_migrations (" +
      "name TEXT PRIMARY KEY, applied_on TEXT NOT NULL)",
  );
  const seen = new Set(
    db
      .prepare("SELECT name FROM applied_migrations")
      .all()
      .map((row) => (row as { name: string }).name),
  );
  const applied: string[] = [];
  const apply = db.transaction((migration: Migration) => {
    db.exec(migration.sql);
    db.prepare(
      "INSERT INTO applied_migrations (name, applied_on) VALUES (?, ?)",
    ).run(migration.name, today());
  });
  for (const migration of migrations) {
    if (seen.has(migration.name)) continue;
    apply(migration);
    applied.push(migration.name);
  }
  return applied;
}

// A date, never a timestamp: an exact instant beside an account is the correlation data the design
// exists to avoid producing, and it would survive in every backup.
export function today(now: Date = new Date()): string {
  return now.toISOString().slice(0, 10);
}
