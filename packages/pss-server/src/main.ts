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

// `synchronous` is per connection and is never persisted, so only the connection that opens the file
// can observe the level this sets. Exported so that is checkable.
export function openDatabase(config: ServerConfig): Database.Database {
  if (config.databasePath !== MEMORY_DATABASE) {
    mkdirSync(dirname(resolve(config.databasePath)), { recursive: true });
  }
  const db = new Database(config.databasePath);
  db.pragma("journal_mode = WAL");
  // Stated rather than inherited from the driver's build flags. NORMAL under WAL can lose the last
  // acknowledged writes to a power loss, which is the right trade for a store the chain can rebuild.
  db.pragma("synchronous = NORMAL");
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

  const sweep = (): void => {
    store.sweepExpired(retentionCutoff(new Date(), config.retentionDays));
    limiter.sweepIdle();
  };
  // Once at boot, because the interval is a day: a deploy or restart cadence shorter than that would
  // otherwise mean the sweep never runs, and nothing catches up the backlog built while it was down.
  sweep();
  const sweepTimer = setInterval(sweep, SWEEP_INTERVAL_MS);
  sweepTimer.unref();

  return {
    port,
    counters,
    close: () =>
      new Promise<void>((done) => {
        clearInterval(sweepTimer);
        server.close(() => {
          db.close();
          done();
        });
        server.closeAllConnections();
      }),
  };
}

export function shouldAutoStart(
  argv: readonly string[],
  moduleUrl: string,
): boolean {
  const entry = argv[1];
  if (entry === undefined) return false;
  return moduleUrl === pathToFileURL(resolve(entry)).href;
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

if (shouldAutoStart(process.argv, import.meta.url)) {
  run().catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}
