import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import {
  BODY_HEADROOM_BYTES,
  MAX_CIPHERTEXT_BYTES,
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
// Deployment limits, not protocol limits, so unlike the tiers and the skew window these are a local
// operational choice and are deliberately not read from the environment either.
//
// A body is accumulated before the signature is checked, because the signature covers a digest of it,
// so an unauthenticated caller can hold memory for as long as the request stays open. Node's defaults
// are a 300 s request timeout and no connection cap at all, which is 1.37 MB of retained buffers per
// half-open chunked upload for five minutes, times an unbounded number of sockets.
//
// 30 s is far more than a 1 MB upload needs on a slow link and far less than 300 s. 10 s for headers is
// generous for a request whose headers are three lines. 512 concurrent connections is well above what a
// deployment sized for tens to hundreds of accounts will ever see, and bounds the worst case.
const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;
const DEFAULT_HEADERS_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_CONNECTIONS = 512;
export const SERVER_MAINTENANCE_INTERVAL_MS = 86_400_000;

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
  readonly maxTrackedAccounts: number;
  readonly maxTrackedReplays: number;
  readonly requestTimeoutMs: number;
  readonly headersTimeoutMs: number;
  readonly maxConnections: number;
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
    maxTrackedAccounts: DEFAULT_MAX_TRACKED_ACCOUNTS,
    maxTrackedReplays: DEFAULT_MAX_TRACKED_REPLAYS,
    requestTimeoutMs: DEFAULT_REQUEST_TIMEOUT_MS,
    headersTimeoutMs: DEFAULT_HEADERS_TIMEOUT_MS,
    maxConnections: DEFAULT_MAX_CONNECTIONS,
    inviteRequired: true,
  };
}
