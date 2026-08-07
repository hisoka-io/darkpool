import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { PSS_STATUS } from "@hisoka/pss-client/wire";
import { loadConfig } from "../config.js";
import { type RunningServer, startServer } from "../main.js";
import { sendRequest } from "./harness.js";

const ACCOUNT_PATH = "a".repeat(64);

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

  it("does not listen merely because the module was imported", async () => {
    const config = loadConfig();
    await expect(
      sendRequest(config.port, "GET", `/v1/blob/${ACCOUNT_PATH}/state`),
    ).rejects.toThrow();
  });
});
