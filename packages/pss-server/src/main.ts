import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import type { Server } from "node:http";
import Database from "better-sqlite3";
import { type ServerConfig, loadConfig } from "./config.js";
import { loadMigrations, runMigrations } from "./db/migrate.js";
import { SWEEP_INTERVAL_MS, retentionCutoff } from "./db/retention.js";
import { openSlotStore } from "./db/sqliteSlotStore.js";
import { createPssServer } from "./http/server.js";
import { type RequestCounters, createCounters } from "./metrics.js";
import { createRateLimiter } from "./rateLimit.js";
import { createReplayGuard } from "./replayGuard.js";

const MEMORY_DATABASE = ":memory:";

export interface RunningServer {
  readonly port: number;
  readonly counters: RequestCounters;
  close(): Promise<void>;
}

function openDatabase(config: ServerConfig): Database.Database {
  if (config.databasePath !== MEMORY_DATABASE) {
    mkdirSync(dirname(resolve(config.databasePath)), { recursive: true });
  }
  const db = new Database(config.databasePath);
  db.pragma("journal_mode = WAL");
  runMigrations(db, loadMigrations(config.migrationsDir));
  return db;
}

function listen(server: Server, config: ServerConfig): Promise<number> {
  return new Promise<number>((accept, reject) => {
    const onError = (error: Error): void => {
      reject(
        new Error(
          `PSS server cannot listen on ${config.host}:${config.port}: ${error.message}`,
        ),
      );
    };
    server.once("error", onError);
    server.listen(config.port, config.host, () => {
      server.off("error", onError);
      const address = server.address();
      accept(
        typeof address === "object" && address !== null
          ? address.port
          : config.port,
      );
    });
  });
}

export async function startServer(
  config: ServerConfig = loadConfig(),
): Promise<RunningServer> {
  const db = openDatabase(config);
  const store = openSlotStore(db);
  const counters = createCounters();
  const limiter = createRateLimiter({
    writesPerHour: config.writesPerHour,
    burst: config.writeBurst,
    maxTrackedAccounts: config.maxTrackedAccounts,
    now: () => Date.now(),
  });
  const replay = createReplayGuard({
    windowSeconds: config.timestampSkewSeconds * 2,
    capacity: config.maxTrackedReplays,
    now: () => Date.now(),
  });
  const server = createPssServer({
    config,
    store,
    limiter,
    replay,
    counters,
    now: () => Date.now(),
  });
  const port = await listen(server, config);

  const sweep = setInterval(() => {
    store.sweepExpired(retentionCutoff(new Date(), config.retentionDays));
    limiter.sweepIdle();
  }, SWEEP_INTERVAL_MS);
  sweep.unref();

  return {
    port,
    counters,
    close: () =>
      new Promise<void>((done) => {
        clearInterval(sweep);
        server.close(() => {
          db.close();
          done();
        });
        server.closeAllConnections();
      }),
  };
}

function isDirectRun(): boolean {
  const entry = process.argv[1];
  if (entry === undefined) return false;
  return import.meta.url === pathToFileURL(resolve(entry)).href;
}

async function run(): Promise<void> {
  const config = loadConfig();
  const running = await startServer(config);
  process.stdout.write(
    `pss-server listening on ${config.host}:${running.port}\n`,
  );
  for (const signal of ["SIGINT", "SIGTERM"] as const) {
    process.once(signal, () => {
      running
        .close()
        .then(() => {
          process.stdout.write(
            `${JSON.stringify(running.counters.snapshot())}\n`,
          );
        })
        .catch((error: unknown) => {
          console.error(
            `PSS server shutdown failed: ${error instanceof Error ? error.message : String(error)}`,
          );
          process.exitCode = 1;
        });
    });
  }
}

if (isDirectRun()) {
  run().catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}
