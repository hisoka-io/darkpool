import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import Database from "better-sqlite3";
import { PSS_STATUS } from "@hisoka/pss-client/wire";
import { defaultMigrationsDir, loadConfig } from "../config.js";
import { loadMigrations, runMigrations } from "../db/migrate.js";
import {
  type RunningServer,
  openDatabase,
  shouldAutoStart,
  startServer,
} from "../main.js";
import { sendRequest } from "./harness.js";

const ACCOUNT_PATH = "a".repeat(64);
const SQLITE_SYNCHRONOUS_NORMAL = 1;

let directory: string;
let running: RunningServer | null = null;

beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), "pss-main-"));
});

afterEach(async () => {
  if (running !== null) await running.close();
  running = null;
  rmSync(directory, { recursive: true, force: true });
});

describe("entry point", () => {
  it("creates the database directory, migrates and serves", async () => {
    const databasePath = join(directory, "nested", "pss.db");
    running = await startServer({
      ...loadConfig(),
      port: 0,
      databasePath,
    });
    expect(running.port).toBeGreaterThan(0);

    const reply = await sendRequest(
      running.port,
      "GET",
      `/v1/blob/${ACCOUNT_PATH}/state`,
    );
    expect(reply).toEqual({ status: PSS_STATUS.not_found, body: "" });
    expect(running.counters.snapshot()).toEqual({ "blob_get.4xx": 1 });

    await running.close();
    running = null;

    expect(existsSync(databasePath)).toBe(true);
    const db = new Database(databasePath, { readonly: true });
    const tables = db
      .prepare(
        "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name",
      )
      .all()
      .map((row) => (row as { name: string }).name);
    db.close();
    expect(tables).toContain("slots");
    expect(tables).toContain("invites");
  });

  // Asserted against the decision rather than against the machine's ambient port state: probing the
  // configured port fails whenever a real server happens to be running on it.
  it("auto-starts only when this module is the process entry point", () => {
    const self = join(directory, "main.js");
    expect(shouldAutoStart([], pathToFileURL(self).href)).toBe(false);
    expect(
      shouldAutoStart(
        ["node", join(directory, "other.js")],
        pathToFileURL(self).href,
      ),
    ).toBe(false);
    expect(shouldAutoStart(["node", self], pathToFileURL(self).href)).toBe(
      true,
    );
  });

  it("sweeps expired rows at boot, not only on the interval", async () => {
    const databasePath = join(directory, "stale.db");
    const seed = new Database(databasePath);
    runMigrations(seed, loadMigrations(defaultMigrationsDir()));
    seed
      .prepare(
        "INSERT INTO slots (account_id, collection, version, prev_version, nonce, ciphertext, updated_on) " +
          "VALUES (?, 'state', 1, 0, ?, ?, '2020-01-01')",
      )
      .run(Buffer.alloc(32, 7), Buffer.alloc(12), Buffer.of(1));
    seed.close();

    // The interval is a day, so a restart cadence shorter than that would otherwise never sweep.
    running = await startServer({ ...loadConfig(), port: 0, databasePath });
    await running.close();
    running = null;

    const after = new Database(databasePath, { readonly: true });
    const rows = after.prepare("SELECT COUNT(*) AS n FROM slots").get() as {
      n: number;
    };
    after.close();
    expect(rows.n).toBe(0);
  });

  // synchronous is per connection and never persisted, so this can only be read from the connection the
  // server itself opened. Both are checked because a fresh file and an existing WAL database reach the
  // level by different routes.
  it("opens every connection at the durability level it states", () => {
    const config = { ...loadConfig(), databasePath: join(directory, "p.db") };
    for (const pass of ["creates", "reopens"]) {
      const db = openDatabase(config);
      const level = db.pragma("synchronous", { simple: true });
      db.close();
      expect(level, pass).toBe(SQLITE_SYNCHRONOUS_NORMAL);
    }
  });
});

describe("defaults", () => {
  it("anchors the database to the package, not the working directory", () => {
    const { databasePath } = loadConfig({});
    expect(isAbsolute(databasePath)).toBe(true);
    expect(resolve(defaultMigrationsDir(), "..")).toBe(
      resolve(databasePath, "..", ".."),
    );
  });

  it("still lets the environment place the database", () => {
    expect(
      loadConfig({ PSS_DATABASE_PATH: "/srv/pss/state.db" }).databasePath,
    ).toBe("/srv/pss/state.db");
  });
});
