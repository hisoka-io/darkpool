import {
  createHash,
  generateKeyPairSync,
  randomBytes,
  sign,
} from "node:crypto";
import { request } from "node:http";
import type { AddressInfo } from "node:net";
import Database from "better-sqlite3";
import {
  type Collection,
  ED25519_PUBLIC_KEY_BYTES,
  GCM_NONCE_BYTES,
  type PutBlobRequest,
  encodeAccountIdPath,
  putPreimage,
  toBase64,
} from "@hisoka/pss-client/wire";
import { defaultMigrationsDir, loadConfig } from "../config.js";
import { loadMigrations, runMigrations } from "../db/migrate.js";
import type { SlotStore } from "../db/slotStore.js";
import { openSlotStore } from "../db/sqliteSlotStore.js";
import { createPssServer } from "../http/server.js";
import { createCounters } from "../metrics.js";
import { createRateLimiter } from "../rateLimit.js";
import { type ReplayGuard, createReplayGuard } from "../replayGuard.js";

export interface TestAccount {
  readonly authPk: Uint8Array;
  readonly accountId: Uint8Array;
  readonly path: string;
  sign(message: Uint8Array): Uint8Array;
}

export function newAccount(): TestAccount {
  const pair = generateKeyPairSync("ed25519");
  const spki = pair.publicKey.export({ format: "der", type: "spki" });
  const authPk = Uint8Array.from(
    spki.subarray(spki.length - ED25519_PUBLIC_KEY_BYTES),
  );
  const accountId = Uint8Array.from(
    createHash("sha256").update(authPk).digest(),
  );
  return {
    authPk,
    accountId,
    path: encodeAccountIdPath(accountId),
    sign: (message) => Uint8Array.from(sign(null, message, pair.privateKey)),
  };
}

export interface HttpReply {
  readonly status: number;
  readonly body: string;
}

export interface Harness {
  readonly port: number;
  readonly db: Database.Database;
  readonly store: SlotStore;
  readonly replay: ReplayGuard;
  readonly counters: ReturnType<typeof createCounters>;
  setNow(ms: number): void;
  advance(ms: number): void;
  seconds(): number;
  send(
    method: string,
    path: string,
    body?: string,
    headers?: Readonly<Record<string, string>>,
  ): Promise<HttpReply>;
  stop(): Promise<void>;
}

const START_MS = Date.UTC(2026, 7, 7, 12, 0, 0);
const MS_PER_SECOND = 1000;

export async function startHarness(
  overrides: Partial<ReturnType<typeof loadConfig>> = {},
): Promise<Harness> {
  const config = { ...loadConfig(), databasePath: ":memory:", ...overrides };
  const db = new Database(":memory:");
  runMigrations(db, loadMigrations(defaultMigrationsDir()));
  const store = openSlotStore(db);
  const counters = createCounters();
  let nowMs = START_MS;
  const now = (): number => nowMs;
  const limiter = createRateLimiter({
    writesPerHour: config.writesPerHour,
    burst: config.writeBurst,
    maxTrackedAccounts: config.maxTrackedAccounts,
    now,
  });
  const replay = createReplayGuard({
    windowSeconds: config.timestampSkewSeconds * 2,
    capacity: config.maxTrackedReplays,
    now,
  });
  const server = createPssServer({
    config,
    store,
    limiter,
    replay,
    counters,
    now,
  });
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  const port = (server.address() as AddressInfo).port;

  return {
    port,
    db,
    store,
    replay,
    counters,
    setNow: (ms) => {
      nowMs = ms;
    },
    advance: (ms) => {
      nowMs += ms;
    },
    seconds: () => Math.floor(nowMs / MS_PER_SECOND),
    send: (method, path, body, headers) =>
      sendRequest(port, method, path, body, headers),
    stop: () =>
      new Promise<void>((done) => {
        server.closeAllConnections();
        server.close(() => {
          db.close();
          done();
        });
      }),
  };
}

export function sendRequest(
  port: number,
  method: string,
  path: string,
  body?: string,
  headers: Readonly<Record<string, string>> = {},
): Promise<HttpReply> {
  return new Promise<HttpReply>((accept, reject) => {
    const payload = body === undefined ? undefined : Buffer.from(body, "utf8");
    const req = request(
      {
        host: "127.0.0.1",
        port,
        method,
        path,
        headers: {
          ...(payload === undefined
            ? {}
            : { "content-length": String(payload.length) }),
          ...headers,
        },
      },
      (res) => {
        let text = "";
        res.setEncoding("utf8");
        res.on("data", (chunk: string) => {
          text += chunk;
        });
        res.on("end", () =>
          accept({ status: res.statusCode ?? 0, body: text }),
        );
      },
    );
    req.on("error", reject);
    req.end(payload);
  });
}

export interface RawOptions {
  readonly headers?: Readonly<Record<string, string>>;
  readonly chunks: readonly Buffer[];
  readonly finish: boolean;
}

// Sends bytes the way an attacker would rather than the way the client library does: a declared length
// the body never delivers, or a chunked body with no declared length at all.
export function rawRequest(
  port: number,
  method: string,
  path: string,
  options: RawOptions,
): Promise<HttpReply> {
  return new Promise<HttpReply>((accept, reject) => {
    let answered = false;
    const req = request(
      { host: "127.0.0.1", port, method, path, headers: options.headers ?? {} },
      (res) => {
        let text = "";
        res.setEncoding("utf8");
        res.on("data", (chunk: string) => {
          text += chunk;
        });
        res.on("end", () => {
          answered = true;
          req.destroy();
          accept({ status: res.statusCode ?? 0, body: text });
        });
      },
    );
    req.on("error", (error) => {
      if (!answered) reject(error);
    });
    for (const chunk of options.chunks) req.write(chunk);
    if (options.finish) req.end();
  });
}

export interface PutOptions {
  readonly version?: number;
  readonly prevVersion?: number;
  readonly ciphertext?: Uint8Array;
  readonly timestamp?: number;
  readonly invite?: string;
  readonly signAs?: TestAccount;
  readonly signCollection?: Collection;
  readonly signAccountId?: Uint8Array;
}

export function signedPut(
  account: TestAccount,
  collection: Collection,
  timestamp: number,
  options: PutOptions = {},
): PutBlobRequest {
  const version = options.version ?? 1;
  const prevVersion = options.prevVersion ?? 0;
  const ciphertext = options.ciphertext ?? Uint8Array.of(1, 2, 3, 4);
  const nonce = Uint8Array.from(randomBytes(GCM_NONCE_BYTES));
  const signer = options.signAs ?? account;
  const preimage = putPreimage({
    accountId: options.signAccountId ?? account.accountId,
    collection: options.signCollection ?? collection,
    version,
    prevVersion,
    ciphertextDigest: Uint8Array.from(
      createHash("sha256").update(ciphertext).digest(),
    ),
    timestamp: options.timestamp ?? timestamp,
  });
  return {
    version,
    prevVersion,
    nonce: toBase64(nonce),
    ciphertext: toBase64(ciphertext),
    authPk: toBase64(signer.authPk),
    sig: toBase64(signer.sign(preimage)),
    timestamp: options.timestamp ?? timestamp,
    ...(options.invite === undefined ? {} : { invite: options.invite }),
  };
}

export function insertInvite(db: Database.Database, code: string): void {
  db.prepare("INSERT INTO invites (code_hash, spent) VALUES (?, 0)").run(
    createHash("sha256").update(code, "utf8").digest(),
  );
}
