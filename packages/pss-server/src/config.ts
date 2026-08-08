import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import {
  BODY_HEADROOM_BYTES,
  MAX_CIPHERTEXT_BYTES,
  RETENTION_DAYS,
  TIMESTAMP_SKEW_SECONDS,
  WRITES_PER_HOUR,
  WRITE_BURST,
} from "@hisoka/pss-client/wire";

const DEFAULT_HOST = "127.0.0.1";
const DEFAULT_PORT = 8787;
const MAX_PORT = 65_535;
// Bounds on the two in-process caches. An accountId costs an attacker one keypair, so neither map may
// grow with the number of accounts that have ever sent a valid request.
const DEFAULT_MAX_TRACKED_ACCOUNTS = 100_000;
const DEFAULT_MAX_TRACKED_REPLAYS = 100_000;

export class ConfigError extends Error {
  constructor(detail: string) {
    super(`PSS config: ${detail}`);
    this.name = "ConfigError";
  }
}

export interface ServerConfig {
  readonly host: string;
  readonly port: number;
  readonly databasePath: string;
  readonly migrationsDir: string;
  readonly timestampSkewSeconds: number;
  readonly maxCiphertextBytes: number;
  readonly bodyHeadroomBytes: number;
  readonly writesPerHour: number;
  readonly writeBurst: number;
  readonly retentionDays: number;
  readonly maxTrackedAccounts: number;
  readonly maxTrackedReplays: number;
  readonly inviteRequired: boolean;
}

function packageDir(): string {
  return resolve(dirname(fileURLToPath(import.meta.url)), "..");
}

export function defaultMigrationsDir(): string {
  return resolve(packageDir(), "migrations");
}

// Anchored to the module, not the working directory, so the two defaults in this file agree about what
// "the package" means. A cwd-relative default silently opens a different, empty database when the
// process is launched from elsewhere while the migrations still resolve, which reads as a healthy
// server that has lost every account. A real deployment sets PSS_DATABASE_PATH.
export function defaultDatabasePath(): string {
  return resolve(packageDir(), "data", "pss.db");
}

function readPort(raw: string | undefined): number {
  if (raw === undefined || raw === "") return DEFAULT_PORT;
  const port = Number(raw);
  if (!Number.isInteger(port) || port < 1 || port > MAX_PORT) {
    throw new ConfigError(`PSS_PORT must be 1..${MAX_PORT}, got ${raw}`);
  }
  return port;
}

// Protocol limits come from the wire contract, never from the environment. A deployment that could
// widen its own padding tier or skew window would be distinguishable from every other deployment.
export function loadConfig(
  env: Readonly<Record<string, string | undefined>> = process.env,
): ServerConfig {
  return {
    host: env.PSS_HOST ?? DEFAULT_HOST,
    port: readPort(env.PSS_PORT),
    databasePath: env.PSS_DATABASE_PATH ?? defaultDatabasePath(),
    migrationsDir: defaultMigrationsDir(),
    timestampSkewSeconds: TIMESTAMP_SKEW_SECONDS,
    maxCiphertextBytes: MAX_CIPHERTEXT_BYTES,
    bodyHeadroomBytes: BODY_HEADROOM_BYTES,
    writesPerHour: WRITES_PER_HOUR,
    writeBurst: WRITE_BURST,
    retentionDays: RETENTION_DAYS,
    maxTrackedAccounts: DEFAULT_MAX_TRACKED_ACCOUNTS,
    maxTrackedReplays: DEFAULT_MAX_TRACKED_REPLAYS,
    inviteRequired: true,
  };
}
