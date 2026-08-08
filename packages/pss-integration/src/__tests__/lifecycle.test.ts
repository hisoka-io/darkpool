import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createHash, randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DarkAccount } from "@hisoka/wallets";
import {
  DEFAULT_SYNC_CONFIG,
  type PssKeys,
  type PssStore,
  StateSync,
  VersionFloor,
  buildDeleteRequest,
  createHttpTransport,
  deriveKeys,
  nobleBackend,
  toHexRaw,
} from "@hisoka/pss-client";
import {
  defaultMigrationsDir,
  loadConfig,
  openDatabase,
  startServer,
} from "@hisoka/pss-server";
import type { RunningServer } from "@hisoka/pss-server";

const MNEMONIC = "test test test test test test test test test test test junk";
const GCM_NONCE_BYTES = 12;

class MemoryStore implements PssStore {
  readonly #cells = new Map<string, string>();
  get(key: string): Promise<string | null> {
    return Promise.resolve(this.#cells.get(key) ?? null);
  }
  set(key: string, value: string): Promise<void> {
    this.#cells.set(key, value);
    return Promise.resolve();
  }
  remove(key: string): Promise<void> {
    this.#cells.delete(key);
    return Promise.resolve();
  }
}

let directory: string;
let server: RunningServer;
let baseUrl: string;
let databasePath: string;
let keys: PssKeys;

// Issuance is manual and out of band by design, so there is no API to call. This writes the same row an
// operator would, through the server's own connection helper rather than a second sqlite dependency.
function insertInvite(code: string): void {
  const db = openDatabase({ ...loadConfig(), databasePath });
  db.prepare("INSERT INTO invites (code_hash, spent) VALUES (?, 0)").run(
    createHash("sha256").update(code, "utf8").digest(),
  );
  db.close();
}

async function device(invite?: string): Promise<StateSync> {
  const store = new MemoryStore();
  return StateSync.open({
    store,
    floor: new VersionFloor(store, toHexRaw(keys.accountId)),
    transport: createHttpTransport({
      baseUrl,
      fetch: (url, request) =>
        fetch(url, {
          method: request.method,
          headers: request.headers,
          body: request.body,
          signal: request.signal,
        }),
      timeoutMs: DEFAULT_SYNC_CONFIG.requestTimeoutMs,
    }),
    oracle: { spentBetween: () => Promise.resolve(new Set<string>()) },
    backend: nobleBackend,
    keys,
    config: DEFAULT_SYNC_CONFIG,
    platform: "extension/chrome",
    now: () => Date.now(),
    ...(invite === undefined ? {} : { invite }),
  });
}

function note(leafIndex: number): {
  leafIndex: number;
  assetId: string;
  amount: string;
  nullifier: string;
} {
  return {
    leafIndex,
    assetId: "0x1234567890123456789012345678901234567890",
    amount: "1000",
    nullifier: `0x${leafIndex.toString(16).padStart(64, "0")}`,
  };
}

beforeAll(async () => {
  directory = mkdtempSync(join(tmpdir(), "pss-e2e-"));
  databasePath = join(directory, "pss.db");
  server = await startServer({
    ...loadConfig(),
    port: 0,
    databasePath,
    migrationsDir: defaultMigrationsDir(),
  });
  baseUrl = `http://127.0.0.1:${server.port}`;
  const account = await DarkAccount.fromMnemonic(MNEMONIC);
  keys = await deriveKeys(
    nobleBackend,
    Uint8Array.from((await account.getStateKey()).toBuffer()),
  );
});

afterAll(async () => {
  await server.close();
  rmSync(directory, { recursive: true, force: true });
});

describe("two devices against a real server", () => {
  it("runs the full lifecycle, and the takeover preserves the first device's state", async () => {
    insertInvite("invite-lifecycle-1");
    const a = await device("invite-lifecycle-1");

    // Create with an invite, then write.
    await a.update((p) => ({
      known: {
        ...p.known,
        unspentNotes: [note(5), note(6)],
        issuedAddresses: [{ index: 3 }],
        incomingIssueHighwater: 11,
        selfEphHighwater: 41,
      },
      extra: p.extra,
    }));
    await a.flushNow();
    expect(a.state.degraded).toBeNull();

    // Read it back over HTTP and decrypt.
    const reread = await a.pull();
    expect(reread).toMatchObject({ kind: "present" });
    if (reread.kind !== "present") throw new Error("unreachable");
    expect(reread.payload.known.unspentNotes.map((n) => n.leafIndex)).toEqual([
      5, 6,
    ]);

    // Device B, same account, different install. It must be read-only until the user confirms.
    const b = await device();
    expect(b.identity.installId).not.toBe(a.identity.installId);
    await b.pull();
    expect(b.state.mode).toBe("readonly");
    expect(b.state.heldBy?.installId).toBe(a.identity.installId);

    // A read-only write is refused and reported, and the server still holds A's blob.
    await b.update((p) => ({
      known: { ...p.known, selfEphHighwater: 999 },
      extra: p.extra,
    }));
    await b.flushNow();
    expect(b.state.degraded?.message).toContain("read-only");

    // Takeover, then B writes. This is the case that silently destroyed A's state before the
    // merge-on-read fix, and it is asserted here over real HTTP rather than in a unit test.
    await b.confirmTakeover({ state: 0, labels: 0 });
    expect(b.state.mode).toBe("writer");
    await b.update((p) => ({
      known: {
        ...p.known,
        unspentNotes: [...p.known.unspentNotes, note(9)],
      },
      extra: p.extra,
    }));
    await b.flushNow();
    expect(b.state.degraded).toBeNull();

    const afterTakeover = await b.pull();
    if (afterTakeover.kind !== "present") throw new Error("unreachable");
    expect(
      afterTakeover.payload.known.unspentNotes.map((n) => n.leafIndex),
    ).toEqual([5, 6, 9]);
    expect(afterTakeover.payload.known.issuedAddresses).toEqual([{ index: 3 }]);
    expect(afterTakeover.payload.known.incomingIssueHighwater).toBe(11);
    expect(afterTakeover.payload.known.selfEphHighwater).toBe(999);
    expect(afterTakeover.payload.known.installId).toBe(b.identity.installId);

    // A now reads a blob it does not hold, and is demoted in turn.
    await a.pull();
    expect(a.state.mode).toBe("readonly");
    expect(a.state.heldBy?.installId).toBe(b.identity.installId);
  });

  it("erases every collection on a signed delete, and 404s afterwards", async () => {
    const nonce = Uint8Array.from(randomBytes(GCM_NONCE_BYTES));
    const body = await buildDeleteRequest(nobleBackend, keys, {
      nonce,
      timestamp: Math.floor(Date.now() / 1000),
    });
    const response = await fetch(
      `${baseUrl}/v1/blob/${toHexRaw(keys.accountId)}`,
      {
        method: "DELETE",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
      },
    );
    expect(response.status).toBe(200);

    const after = await fetch(
      `${baseUrl}/v1/blob/${toHexRaw(keys.accountId)}/state`,
    );
    expect(after.status).toBe(404);
  });

  it("needs a fresh invite to recreate the account, and the spent one is refused", async () => {
    // No tombstone, no recovery: the account is gone and the old code is spent.
    const stale = await device("invite-lifecycle-1");
    await stale.update((p) => ({
      known: { ...p.known, selfEphHighwater: 1 },
      extra: p.extra,
    }));
    await stale.flushNow();
    expect(stale.state.degraded).not.toBeNull();

    insertInvite("invite-lifecycle-2");
    const fresh = await device("invite-lifecycle-2");
    await fresh.update((p) => ({
      known: { ...p.known, selfEphHighwater: 2 },
      extra: p.extra,
    }));
    await fresh.flushNow();
    expect(fresh.state.degraded).toBeNull();

    const recreated = await fresh.pull();
    expect(recreated).toMatchObject({ kind: "present" });
  });
});
