import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  DarkAccount,
  leaf,
  NOTE_TYPE_STANDARD,
  NOTE_VERSION,
  toFr,
  type Note,
} from "@hisoka/wallets";
import {
  DEFAULT_SYNC_CONFIG,
  type PssKeys,
  type PssStore,
  StateSync,
  VersionFloor,
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
import {
  mirrorNotes,
  NoteStore,
  nullifierHex,
  PssEphemeralCounterStore,
  requireWriter,
  reverifyPssHints,
  WalletRuntimeError,
  type RuntimeStore,
  type StoredNote,
} from "@hisoka/wallet-runtime";

const MNEMONIC = "test test test test test test test test test test test junk";
const OTHER_MNEMONIC =
  "legal winner thank year wave sausage worth useful legal winner thank yellow";
const NOTES_KEY = "hisoka.runtime.v1.test.notes";
const LEAF = 7;

class MemoryPssStore implements PssStore {
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

class MemoryRuntimeStore implements RuntimeStore {
  readonly #cells = new Map<string, string>();
  get(key: string): Promise<string | null> {
    return Promise.resolve(this.#cells.get(key) ?? null);
  }
  set(key: string, value: string): Promise<void> {
    this.#cells.set(key, value);
    return Promise.resolve();
  }
  setMany(
    entries: readonly (readonly [string, string | null])[],
  ): Promise<void> {
    for (const [k, v] of entries) {
      if (v === null) this.#cells.delete(k);
      else this.#cells.set(k, v);
    }
    return Promise.resolve();
  }
}

let directory: string;
let server: RunningServer;
let baseUrl: string;
let databasePath: string;
let keys: PssKeys;
let otherKeys: PssKeys;

function insertInvite(code: string): void {
  const db = openDatabase({ ...loadConfig(), databasePath });
  db.prepare("INSERT INTO invites (code_hash, spent) VALUES (?, 0)").run(
    createHash("sha256").update(code, "utf8").digest(),
  );
  db.close();
}

async function device(
  platform: string,
  invite?: string,
  account: PssKeys = keys,
): Promise<StateSync> {
  const store = new MemoryPssStore();
  return StateSync.open({
    store,
    floor: new VersionFloor(store, toHexRaw(account.accountId)),
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
    keys: account,
    config: DEFAULT_SYNC_CONFIG,
    platform,
    now: () => Date.now(),
    ...(invite === undefined ? {} : { invite }),
  });
}

/** One block of one fork: the fork id is folded into the hash, so the same height on two forks differs. */
function block(n: number, fork: number): { number: number; hash: string } {
  return {
    number: n,
    hash: `0x${(0xf0000 * (fork + 1) + n).toString(16).padStart(64, "0")}`,
  };
}

/** A note this wallet owns at `LEAF`, distinct per seed, included in `at`. */
async function owned(
  seed: bigint,
  at: { number: number; hash: string },
): Promise<StoredNote> {
  const note: Note = {
    noteVersion: NOTE_VERSION,
    assetId: toFr(0xa55e7n),
    noteType: toFr(NOTE_TYPE_STANDARD),
    conditionsHash: toFr(0n),
    value: 100n + seed,
    owner: toFr(0xb0bn),
    psi: toFr(0x5eedn + seed),
    parents: toFr(0n),
  };
  return {
    leafIndex: LEAF,
    commitment: await leaf(note),
    note,
    nullifier: toFr(0x9000n + seed),
    origin: "self",
    derivationIndex: Number(seed),
    complianceVersion: 1,
    block: at,
    verification: "verified",
    spent: null,
    mirrored: false,
  };
}

function leaves(sync: StateSync): number[] {
  return sync.current().known.unspentNotes.map((n) => n.leafIndex);
}

beforeAll(async () => {
  directory = mkdtempSync(join(tmpdir(), "pss-reorg-"));
  databasePath = join(directory, "pss.db");
  server = await startServer({
    ...loadConfig(),
    port: 0,
    databasePath,
    migrationsDir: defaultMigrationsDir(),
  });
  baseUrl = `http://127.0.0.1:${server.port}`;
  const stateKey = async (mnemonic: string) =>
    Uint8Array.from(
      (
        await (await DarkAccount.fromMnemonic(mnemonic)).getStateKey()
      ).toBuffer(),
    );
  keys = await deriveKeys(nobleBackend, await stateKey(MNEMONIC));
  otherKeys = await deriveKeys(nobleBackend, await stateKey(OTHER_MNEMONIC));
});

afterAll(async () => {
  await server.close();
  rmSync(directory, { recursive: true, force: true });
});

describe("a reorg across two devices against a real server", () => {
  it("does not resurrect a reorged note, keeps it out after a takeover, and survives a disagreement at one leaf", async () => {
    insertInvite("invite-reorg-1");
    const a = await device("extension/chrome", "invite-reorg-1");
    await a.pull();
    const notesA = await NoteStore.open(new MemoryRuntimeStore(), NOTES_KEY);

    // A, the writer, mirrors confirmed note X at leaf 7 (PSS write depth 0, as on hardhat).
    const x = await owned(1n, block(20, 0));
    await notesA.record([x], { head: block(20, 0), maxReorgBlocks: 16 });
    await a.update((p) => p);
    await a.flushNow();
    expect(a.state.mode).toBe("writer");
    await mirrorNotes(a, notesA, block(20, 0));
    await a.flushNow();
    expect(a.state.degraded).toBeNull();

    // B, a second install of the same account, pulls X while read-only.
    const b = await device("mobile/ios", "unrelated-invite");
    await b.pull();
    expect(b.state.mode).toBe("readonly");
    expect(leaves(b)).toEqual([LEAF]);

    // A reorg drops X. A rolls back in one write and its next mirror tombstones X.
    const rolled = await notesA.rollback({
      ancestor: block(19, 0),
      orphaned: [block(20, 0)],
    });
    expect(rolled.droppedNotes.map((n) => n.leafIndex)).toEqual([LEAF]);
    await mirrorNotes(a, notesA, block(21, 1));
    await a.flushNow();
    expect(a.state.degraded).toBeNull();
    expect(leaves(a)).toEqual([]);

    // B is stale and still holds X: its pull merges A's tombstone and drops X instead of re-uploading it.
    expect(leaves(b)).toEqual([LEAF]);
    await b.pull();
    expect(leaves(b)).toEqual([]);
    expect(b.current().known.droppedNotes).toEqual([
      {
        leafIndex: LEAF,
        nullifier: nullifierHex(x.nullifier),
        block: 20,
        blockHash: block(20, 0).hash,
      },
    ]);

    // B takes over. Its store is rebuilt from PSS hints, which no longer carry X.
    await b.confirmTakeover({ state: 0, labels: 0 });
    expect(b.state.mode).toBe("writer");
    const notesB = await NoteStore.open(new MemoryRuntimeStore(), NOTES_KEY);
    await reverifyPssHints(b, notesB, () =>
      Promise.resolve({ kind: "rejected", reason: "not on chain" }),
    );
    expect(notesB.notes).toEqual([]);

    // On B's fork leaf 7 now holds Y, and B mirrors it.
    const y = await owned(2n, block(20, 1));
    await notesB.record([y], { head: block(21, 1), maxReorgBlocks: 16 });
    await mirrorNotes(b, notesB, block(21, 1));
    await b.flushNow();
    expect(b.state.degraded).toBeNull();

    // A, stale on a third fork, holds Z at leaf 7 locally. The two surviving entries disagree: the merge keeps
    // neither instead of throwing, so the account is not wedged and a counter reservation still works.
    const z = await owned(3n, block(20, 2));
    await a.update((p) => ({
      known: {
        ...p.known,
        unspentNotes: [
          {
            leafIndex: LEAF,
            assetId: `0x${z.note.assetId.toBigInt().toString(16).padStart(40, "0")}`,
            amount: z.note.value.toString(),
            nullifier: nullifierHex(z.nullifier),
            block: 20,
            blockHash: block(20, 2).hash,
          },
        ],
      },
      extra: p.extra,
    }));
    const pulled = await a.pull();
    expect(pulled.kind).toBe("present");
    expect(leaves(a)).toEqual([]);
    await a.confirmTakeover({ state: 0, labels: 0 });
    const reservation = await new PssEphemeralCounterStore(a).reserve(
      "self",
      1,
    );
    await reservation.commit(reservation.base);
    await a.flushNow();
    expect(a.state.degraded).toBeNull();
  });

  it("refuses to mint from a read-only install and reserves no index there", async () => {
    insertInvite("invite-reorg-2");
    const writer = await device(
      "extension/chrome",
      "invite-reorg-2",
      otherKeys,
    );
    await writer.pull();
    await writer.update((p) => p);
    await writer.flushNow();
    const reader = await device(
      "mobile/android",
      "unrelated-invite",
      otherKeys,
    );
    await reader.pull();
    expect(reader.state.mode).toBe("readonly");

    const err = (() => {
      try {
        requireWriter(reader);
        return null;
      } catch (e) {
        return e;
      }
    })();
    expect(err).toBeInstanceOf(WalletRuntimeError);
    expect((err as WalletRuntimeError).code).toBe("NOT_WRITER");
    expect((err as WalletRuntimeError).context.heldByPlatform).toBe(
      "extension/chrome",
    );
    const before = { ...reader.current().known.ephemeralCounters };
    await expect(
      new PssEphemeralCounterStore(reader).reserve("self", 1),
    ).rejects.toThrow(/read-only/);
    expect(reader.current().known.ephemeralCounters).toEqual(before);
    expect(reader.state.mode).toBe("readonly");
  });
});
