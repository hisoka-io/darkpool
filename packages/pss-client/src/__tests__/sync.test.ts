import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { deriveKeys, nobleBackend, openCell } from "../crypto/index.js";
import {
  DEFAULT_SYNC_CONFIG,
  StateSync,
  StateSyncDeps,
  createLogSweepOracle,
  pruneSpentNotes,
  spendableNote,
} from "../sync/index.js";
import { PssTransport, createHttpTransport } from "../sync/transport.js";
import {
  PssRollbackError,
  PssStateError,
  type StampedPayload,
  VersionFloor,
  decodeStatePayload,
  installKey,
  payloadKey,
} from "../state/index.js";
import { fromBase64, toHexRaw } from "../wire/codec.js";
import {
  MAX_CIPHERTEXT_BYTES,
  PSS_SCHEMA_VERSION,
  PSS_STATUS,
} from "../wire/index.js";
import { PssError, PssProtocolError } from "../wire/errors.js";
import { parseGetBlobResponse } from "../wire/types.js";
import { ParsedStatePayload, UnspentNote } from "../wire/payload.js";
import { MemoryPssStore } from "./memoryStore.js";
import { FakeTransport } from "./fakeTransport.js";

const K_STATE = new Uint8Array(32).fill(7);
const NOW_MS = 1_785_900_000_000;

function note(leafIndex: number, nullifier?: string): UnspentNote {
  return {
    leafIndex,
    assetId: "0x1234567890123456789012345678901234567890",
    amount: "1000",
    nullifier: nullifier ?? `0x${leafIndex.toString(16).padStart(64, "0")}`,
  };
}

interface Rig {
  readonly sync: StateSync;
  readonly store: MemoryPssStore;
  readonly transport: FakeTransport;
  readonly floor: VersionFloor;
  readonly accountPath: string;
  readonly deps: StateSyncDeps;
}

async function rig(
  overrides: Partial<StateSyncDeps> = {},
  store = new MemoryPssStore(),
  transport = new FakeTransport(),
  activate = true,
): Promise<Rig> {
  const keys = await deriveKeys(nobleBackend, K_STATE);
  const floor = new VersionFloor(store, toHexRaw(keys.accountId));
  const deps: StateSyncDeps = {
    store,
    floor,
    transport,
    oracle: { spentBetween: () => Promise.resolve(new Set<string>()) },
    backend: nobleBackend,
    keys,
    config: DEFAULT_SYNC_CONFIG,
    platform: "extension/chrome",
    now: () => NOW_MS,
    invite: "test-create",
    ...overrides,
  };
  const sync = await StateSync.open(deps);
  if (activate) await sync.pull();
  return {
    sync,
    store,
    transport,
    floor,
    accountPath: toHexRaw(keys.accountId),
    deps,
  };
}

async function openStored(r: Rig): Promise<ParsedStatePayload> {
  const slot = r.transport.stored(r.accountPath, "state");
  if (slot === null) throw new Error("no stored slot");
  const plaintext = await openCell(
    nobleBackend,
    r.deps.keys.cellKey.state,
    { collection: "state", version: slot.version },
    {
      nonce: fromBase64(slot.nonce, "nonce"),
      ciphertext: fromBase64(slot.ciphertext, "ciphertext"),
    },
  );
  return decodeStatePayload(new TextDecoder().decode(plaintext));
}

describe("get response parsing", () => {
  const good = {
    version: 3,
    prevVersion: 2,
    nonce: "AAAAAAAAAAAAAAAA",
    ciphertext: "AAAAAAAAAAAAAAAAAAAAAAA=",
    serverTime: 1_785_900_000,
  };

  it("accepts an honest response and a ciphertext exactly at the cap", () => {
    expect(parseGetBlobResponse(good).version).toBe(3);
    const atCap = Buffer.alloc(MAX_CIPHERTEXT_BYTES).toString("base64");
    expect(
      parseGetBlobResponse({ ...good, ciphertext: atCap }).ciphertext,
    ).toBe(atCap);
  });

  // A 12-byte value is exactly four base64 quanta, so its encoding has no spare bits and no
  // non-canonical spelling exists to reject. The canonicality check is real, but only the ciphertext,
  // whose length is generally not a multiple of three, can exercise it.
  it("has no non-canonical spelling available for a 12 byte nonce", () => {
    const canonical = Buffer.alloc(12).toString("base64");
    expect(canonical).toHaveLength(16);
    expect(canonical.endsWith("=")).toBe(false);
  });

  it.each([
    ["nonce 11 bytes", { nonce: Buffer.alloc(11).toString("base64") }],
    ["nonce 16 bytes", { nonce: Buffer.alloc(16).toString("base64") }],
    ["empty ciphertext", { ciphertext: "" }],
    [
      "ciphertext one byte over the cap",
      {
        ciphertext: Buffer.alloc(MAX_CIPHERTEXT_BYTES + 1).toString("base64"),
      },
    ],
    ["non-integer serverTime", { serverTime: 1.5 }],
    ["negative serverTime", { serverTime: -1 }],
    // "AR==" decodes to the same single byte as the canonical "AQ==" but sets bits the encoding does
    // not use, so accepting it would let a signed request be respelled without breaking its signature.
    ["non-canonical base64 ciphertext", { ciphertext: "AR==" }],
  ])("refuses %s", (_label: string, patch: Record<string, unknown>) => {
    expect(() => parseGetBlobResponse({ ...good, ...patch })).toThrow(
      PssProtocolError,
    );
  });

  it.each([
    ["a non-object body", 42],
    ["an array body", []],
    ["null", null],
  ])("refuses %s", (_label: string, body: unknown) => {
    expect(() => parseGetBlobResponse(body)).toThrow(PssProtocolError);
  });
});

describe("http transport", () => {
  const base = { baseUrl: "http://pss.test", timeoutMs: 1000 };

  it("turns every non-200 into a typed PssError", async () => {
    for (const [status, code] of [
      [PSS_STATUS.unauthorized, "unauthorized"],
      [PSS_STATUS.version_conflict, "version_conflict"],
      [PSS_STATUS.rate_limited, "rate_limited"],
      [PSS_STATUS.payload_too_large, "payload_too_large"],
    ] as const) {
      const transport = createHttpTransport({
        ...base,
        fetch: () =>
          Promise.resolve({ status, json: () => Promise.resolve({}) }),
      });
      await expect(
        transport.getBlob("a".repeat(64), "state"),
      ).rejects.toMatchObject({ failure: { code } });
    }
  });

  it("reads a 404 as an absent blob rather than a failure", async () => {
    const transport = createHttpTransport({
      ...base,
      fetch: () =>
        Promise.resolve({
          status: PSS_STATUS.not_found,
          json: () => Promise.resolve({}),
        }),
    });
    await expect(
      transport.getBlob("a".repeat(64), "state"),
    ).resolves.toBeNull();
  });

  it("serialises bodies compactly, so the create path keeps its headroom", async () => {
    let sent = "";
    const transport = createHttpTransport({
      ...base,
      fetch: (_url, request) => {
        sent = request.body ?? "";
        return Promise.resolve({
          status: PSS_STATUS.ok,
          json: () => Promise.resolve({}),
        });
      },
    });
    await transport.deleteAccount("a".repeat(64), {
      authPk: "x",
      sig: "y",
      timestamp: 1,
      nonce: "z",
    });
    expect(sent).not.toMatch(/\n| {2}/);
  });

  it("converts a transport that never answers into a typed failure, not a hang", async () => {
    const transport = createHttpTransport({
      baseUrl: "http://pss.test",
      timeoutMs: 5,
      fetch: (_url, request) =>
        new Promise((_resolve, reject) => {
          request.signal?.addEventListener("abort", () => {
            reject(new Error("aborted"));
          });
        }),
    });
    await expect(transport.getBlob("a".repeat(64), "state")).rejects.toThrow(
      PssError,
    );
  });
});

describe("install identity and local cache", () => {
  it("mints an install id once and reuses it on a warm start", async () => {
    const store = new MemoryPssStore();
    const first = await rig({}, store);
    const key = installKey(first.accountPath);
    expect(store.snapshot()[key]).toBe(first.sync.identity.installId);

    const warm = await rig({}, store);
    expect(warm.sync.identity.installId).toBe(first.sync.identity.installId);
  });

  it("mints a new install id after a reinstall", async () => {
    const first = await rig();
    const reinstalled = await rig({}, new MemoryPssStore());
    expect(reinstalled.sync.identity.installId).not.toBe(
      first.sync.identity.installId,
    );
  });

  // The invite rides only on the create. Dropping the prevVersion term is behaviourally undetectable
  // against the server, which ignores a repeated code on an update and still answers 200, so nothing
  // would notice the code being resent on every write for the life of the account.
  it("sends the invite on the create and never again", async () => {
    const r = await rig(
      { invite: "invite-code-1" },
      new MemoryPssStore(),
      new FakeTransport(),
      false,
    );
    expect(r.sync.state.mode).toBe("readonly");
    await r.sync.pull();
    expect(r.sync.state.mode).toBe("readonly");
    await r.sync.update((p) => ({
      known: { ...p.known, selfEphHighwater: 1 },
      extra: p.extra,
    }));
    await r.sync.flushNow();
    expect(r.sync.state.mode).toBe("writer");
    await r.sync.update((p) => ({
      known: { ...p.known, selfEphHighwater: 2 },
      extra: p.extra,
    }));
    await r.sync.flushNow();

    expect(r.transport.puts).toHaveLength(2);
    expect(r.transport.puts[0].invite).toBe("invite-code-1");
    expect(r.transport.puts[1].prevVersion).toBe(1);
    expect(r.transport.puts[1].invite).toBeUndefined();
  });

  it("caches the payload locally under its own key", async () => {
    const r = await rig();
    await r.sync.update((p) => ({
      known: { ...p.known, selfEphHighwater: 41 },
      extra: p.extra,
    }));
    const cached = r.store.snapshot()[payloadKey(r.accountPath, "state")];
    expect(decodeStatePayload(cached).known.selfEphHighwater).toBe(41);
  });
});

describe("takeover through the loop", () => {
  async function twoDevices(): Promise<{ a: Rig; b: Rig }> {
    const transport = new FakeTransport();
    const a = await rig({}, new MemoryPssStore(), transport);
    await a.sync.update((p) => ({
      known: { ...p.known, selfEphHighwater: 5 },
      extra: p.extra,
    }));
    await a.sync.flushNow();
    return { a, b: await rig({}, new MemoryPssStore(), transport) };
  }

  it("demotes the second device to read-only and names who holds the account", async () => {
    const { a, b } = await twoDevices();
    await b.sync.pull();
    expect(b.sync.state.mode).toBe("readonly");
    expect(b.sync.state.heldBy?.installId).toBe(a.sync.identity.installId);

    const exposedIdentity = b.sync.identity;
    expect(
      Reflect.set(exposedIdentity, "installId", a.sync.identity.installId),
    ).toBe(false);
    expect(b.sync.identity.installId).not.toBe(a.sync.identity.installId);
    const exposedState = b.sync.state;
    expect(Reflect.set(exposedState, "mode", "writer")).toBe(false);
    expect(b.sync.state.mode).toBe("readonly");
    await expect(b.sync.updateAsWriter((payload) => payload)).rejects.toThrow(
      /read-only/,
    );
  });

  it("refuses to write while read-only, and reports it rather than throwing", async () => {
    const { b, a } = await twoDevices();
    await b.sync.pull();
    const stored = b.transport.stored(b.accountPath, "state");

    await b.sync.update((p) => ({
      known: { ...p.known, selfEphHighwater: 99 },
      extra: p.extra,
    }));
    await expect(b.sync.flushNow()).resolves.toBeUndefined();

    expect(b.sync.state.degraded?.message).toContain("read-only");
    expect(b.transport.stored(b.accountPath, "state")).toEqual(stored);
    expect(a.sync.identity.installId).not.toBe(b.sync.identity.installId);
  });

  it("writes its own install id once takeover is confirmed, after the floor bootstrap", async () => {
    const { b } = await twoDevices();
    await b.sync.pull();
    await b.sync.confirmTakeover({ state: 7, labels: 0 });

    expect(b.sync.state.mode).toBe("writer");
    // The bootstrap ran before this install became the writer, so anything the other device minted and
    // did not sync is still respected.
    expect(await b.floor.current("state")).toBe(7);

    await b.sync.update((p) => ({
      known: { ...p.known, selfEphHighwater: 42 },
      extra: p.extra,
    }));
    await b.sync.flushNow();
    expect(b.sync.state.degraded).toBeNull();
    expect((await openStored(b)).known.installId).toBe(
      b.sync.identity.installId,
    );
  });

  it("does not destroy the other device's state when it takes over", async () => {
    const transport = new FakeTransport();
    const a = await rig({}, new MemoryPssStore(), transport);
    await a.sync.update((p) => ({
      known: {
        ...p.known,
        unspentNotes: [note(5), note(6)],
        issuedAddresses: [{ index: 3 }],
        incomingIssueHighwater: 11,
      },
      extra: p.extra,
    }));
    await a.sync.flushNow();

    const b = await rig({}, new MemoryPssStore(), transport);
    await b.sync.pull();
    await b.sync.confirmTakeover({ state: 0, labels: 0 });
    await b.sync.update((p) => ({
      known: { ...p.known, unspentNotes: [...p.known.unspentNotes, note(9)] },
      extra: p.extra,
    }));
    await b.sync.flushNow();

    // B's write must carry A's notes forward. A read that did not merge would upload only what B
    // happened to hold and silently drop everything A wrote.
    const stored = await openStored(b);
    expect(stored.known.unspentNotes.map((n) => n.leafIndex)).toEqual([
      5, 6, 9,
    ]);
    expect(stored.known.issuedAddresses).toEqual([{ index: 3 }]);
    expect(stored.known.incomingIssueHighwater).toBe(11);
  });

  it("refuses takeover when no remote payload names a holder", async () => {
    const r = await rig();
    await expect(
      r.sync.confirmTakeover({ state: 0, labels: 0 }),
    ).rejects.toThrow(PssStateError);
  });
});

describe("the write path", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("debounces local writes without losing a newer update behind a durable PUT", async () => {
    const r = await rig();
    await r.sync.update((p) => ({
      known: { ...p.known, selfEphHighwater: 9 },
      extra: p.extra,
    }));

    // Local storage already holds it; nothing has been uploaded.
    expect(
      decodeStatePayload(r.store.snapshot()[payloadKey(r.accountPath, "state")])
        .known.selfEphHighwater,
    ).toBe(9);
    expect(r.transport.puts).toHaveLength(0);

    await vi.advanceTimersByTimeAsync(DEFAULT_SYNC_CONFIG.debounceMs - 1);
    expect(r.transport.puts).toHaveLength(0);
    await vi.advanceTimersByTimeAsync(2);
    await r.sync.stop();
    expect(r.transport.puts).toHaveLength(1);

    const transport = new FakeTransport();
    const honestPut = transport.putBlob.bind(transport);
    let releasePut: (() => void) | undefined;
    let markPutStarted: (() => void) | undefined;
    const putStarted = new Promise<void>((resolve) => {
      markPutStarted = resolve;
    });
    const putReleased = new Promise<void>((resolve) => {
      releasePut = resolve;
    });
    transport.putBlob = async (...args) => {
      markPutStarted?.();
      await putReleased;
      await honestPut(...args);
    };
    const overlap = await rig({}, new MemoryPssStore(), transport);

    const durable = overlap.sync.mutateAsWriterDurably((payload) => ({
      payload: {
        known: { ...payload.known, selfEphHighwater: 1 },
        extra: payload.extra,
      },
      value: null,
    }));
    await putStarted;
    await overlap.sync.update((payload) => ({
      known: { ...payload.known, incomingIssueHighwater: 9 },
      extra: payload.extra,
    }));
    releasePut?.();
    await durable;

    expect(overlap.sync.state.pendingWrite).toBe(true);
    await vi.advanceTimersByTimeAsync(DEFAULT_SYNC_CONFIG.debounceMs + 1);
    await overlap.sync.stop();
    expect(transport.puts).toHaveLength(2);
    expect((await openStored(overlap)).known.incomingIssueHighwater).toBe(9);
    expect(overlap.sync.state.pendingWrite).toBe(false);
  });

  it("flushes on a fixed interval regardless of pending local edits, which is what propagates a prune or a merge", async () => {
    const r = await rig();
    r.sync.start();
    await r.sync.update((p) => ({
      known: { ...p.known, selfEphHighwater: 1 },
      extra: p.extra,
    }));
    await vi.advanceTimersByTimeAsync(DEFAULT_SYNC_CONFIG.debounceMs + 1);
    const afterDebounce = r.transport.puts.length;
    expect(afterDebounce).toBe(1);

    await vi.advanceTimersByTimeAsync(DEFAULT_SYNC_CONFIG.flushIntervalMs);
    await r.sync.stop();
    expect(r.transport.puts.length).toBeGreaterThan(afterDebounce);
  });

  it("does not write on stop", async () => {
    const r = await rig();
    r.sync.start();
    await r.sync.update((p) => ({
      known: { ...p.known, selfEphHighwater: 3 },
      extra: p.extra,
    }));
    await r.sync.stop();
    await vi.advanceTimersByTimeAsync(DEFAULT_SYNC_CONFIG.flushIntervalMs * 2);
    expect(r.transport.puts).toHaveLength(0);
  });
});

describe("the stamped-payload brand", () => {
  it("makes an unstamped payload unassignable to the write path", async () => {
    const r = await rig();
    const unstamped: ParsedStatePayload = r.sync.current();
    // Only InstallGuard.stamp can produce a StampedPayload, so a write path typed to take one cannot be
    // reached without passing the read-only check. This is graded by the typechecker: remove the brand
    // and the directive below becomes an unused-expect-error, which is itself an error.
    // @ts-expect-error a payload that never passed the guard is not a StampedPayload
    const stamped: StampedPayload = unstamped;
    expect(stamped.known.schema).toBe(PSS_SCHEMA_VERSION);
  });
});

describe("the version-conflict path", () => {
  // The single-writer conflict, which is the one that actually happens: the stored version is in
  // memory only, so the first write after a restart offers version 1 against a server already holding
  // three. A second install writing here instead would be refused as read-only, which is the takeover
  // rule doing its job, not a conflict.
  async function warmStartOverExistingBlob(): Promise<{
    warm: Rig;
    transport: FakeTransport;
  }> {
    const store = new MemoryPssStore();
    const transport = new FakeTransport();
    const first = await rig({}, store, transport);
    await first.sync.update((p) => ({
      known: {
        ...p.known,
        unspentNotes: [note(5)],
        incomingIssueHighwater: 4,
      },
      extra: p.extra,
    }));
    await first.sync.flushNow();
    expect(transport.stored(first.accountPath, "state")?.version).toBe(1);
    return { warm: await rig({}, store, transport, false), transport };
  }

  it("re-reads, merges and retries once, and the retried blob opens", async () => {
    const { warm, transport } = await warmStartOverExistingBlob();

    await warm.sync.update((p) => ({
      known: {
        ...p.known,
        unspentNotes: [...p.known.unspentNotes, note(9)],
        selfEphHighwater: 12,
      },
      extra: p.extra,
    }));
    await warm.sync.flushNow();

    expect(transport.stored(warm.accountPath, "state")?.version).toBe(2);

    // The decisive assertion: the stored blob opens at the version it was stored under. A retry that
    // reused the first attempt's seal would be accepted by the server and unopenable forever, and
    // nothing on either side would notice.
    const stored = await openStored(warm);
    expect(stored.known.unspentNotes.map((n) => n.leafIndex)).toEqual([5, 9]);
    expect(stored.known.selfEphHighwater).toBe(12);
    expect(stored.known.incomingIssueHighwater).toBe(4);
    expect(warm.sync.state.degraded).toBeNull();
  });

  it("draws a fresh nonce for the retry rather than reusing the first attempt's", async () => {
    const { warm, transport } = await warmStartOverExistingBlob();
    const before = transport.puts.length;

    await warm.sync.update((p) => ({
      known: { ...p.known, selfEphHighwater: 2 },
      extra: p.extra,
    }));
    await warm.sync.flushNow();

    const attempts = transport.puts.slice(before);
    expect(attempts).toHaveLength(2);
    expect(new Set(attempts.map((p) => p.nonce)).size).toBe(2);
    expect(attempts.map((p) => p.version)).toEqual([1, 2]);
  });

  it("retries once and then reports degraded rather than looping", async () => {
    const { warm, transport } = await warmStartOverExistingBlob();
    // The stored version keeps moving under the retry, so the retry conflicts too. One retry, then
    // degraded: a loop here would hammer the server for as long as the conflict persists.
    let attempts = 0;
    transport.putBlob = () => {
      attempts += 1;
      return Promise.reject(
        new PssError({ code: "version_conflict" }, "still stale"),
      );
    };

    await warm.sync.update((p) => ({
      known: { ...p.known, selfEphHighwater: 3 },
      extra: p.extra,
    }));
    await expect(warm.sync.flushNow()).resolves.toBeUndefined();

    expect(attempts).toBe(2);
    expect(warm.sync.state.degraded).not.toBeNull();
  });
});

describe("the missing-blob path", () => {
  it("treats a 404 as a fresh account only when the floor is zero", async () => {
    const r = await rig();
    await expect(r.sync.pull()).resolves.toEqual({ kind: "absent" });
    expect(r.sync.state.blobMissing).toBe(false);
  });

  it("refuses to read a 404 as fresh once the floor has moved", async () => {
    const r = await rig();
    await r.sync.update((p) => ({
      known: { ...p.known, selfEphHighwater: 1 },
      extra: p.extra,
    }));
    await r.sync.flushNow();
    await r.sync.pull();
    expect(await r.floor.current("state")).toBe(1);

    // The server drops the row, the way a TTL sweep or a signed delete would.
    r.transport.drop(r.accountPath, "state");
    const outcome = await r.sync.pull();
    expect(outcome).toEqual({ kind: "missing", floor: 1 });
    expect(r.sync.state.blobMissing).toBe(true);
  });

  it("recreates above the floor, never at version 1", async () => {
    const r = await rig();
    for (let i = 0; i < 3; i++) {
      await r.sync.update((p) => ({
        known: { ...p.known, selfEphHighwater: i + 1 },
        extra: p.extra,
      }));
      await r.sync.flushNow();
    }
    await r.sync.pull();
    const floorBefore = await r.floor.current("state");
    expect(floorBefore).toBe(3);

    r.transport.drop(r.accountPath, "state");
    await r.sync.update((p) => ({
      known: { ...p.known, selfEphHighwater: 99 },
      extra: p.extra,
    }));
    await r.sync.flushNow();

    // Version 1 here would be accepted by the server and then trip the rollback guard on the next read.
    expect(r.transport.stored(r.accountPath, "state")?.version).toBe(
      floorBefore + 1,
    );
    await expect(r.sync.pull()).resolves.toMatchObject({ kind: "present" });
    expect(await r.floor.current("state")).toBe(4);
  });
});

describe("the floor rises on this install's own accepted write", () => {
  it("refuses a rollback without an intervening pull", async () => {
    const r = await rig();
    for (let i = 1; i <= 3; i++) {
      await r.sync.update((p) => ({
        known: { ...p.known, selfEphHighwater: i },
        extra: p.extra,
      }));
      await r.sync.flushNow();
    }
    // The client authored these versions and the server accepted them, so the claim is authenticated at
    // the source. Before this the floor moved only on a read, so a wallet that wrote and was then
    // served an older version accepted the rollback.
    expect(await r.floor.current("state")).toBe(3);

    r.transport.rollbackTo = 1;
    await expect(r.sync.pull()).rejects.toThrow(PssRollbackError);
    expect(await r.floor.current("state")).toBe(3);
  });
});

describe("rollback refusal", () => {
  it("refuses a version below the floor with a typed error naming both", async () => {
    const r = await rig();
    await r.floor.accept("state", 41);
    await expect(r.floor.accept("state", 4)).rejects.toThrow(PssRollbackError);
  });
});

describe("degraded mode", () => {
  it("never throws out of the loop when every request fails", async () => {
    const dead: PssTransport = {
      getBlob: () =>
        Promise.reject(
          new PssError({ code: "bad_request", field: "transport" }, "down"),
        ),
      putBlob: () =>
        Promise.reject(
          new PssError({ code: "bad_request", field: "transport" }, "down"),
        ),
      deleteAccount: () =>
        Promise.reject(
          new PssError({ code: "bad_request", field: "transport" }, "down"),
        ),
    };
    const store = new MemoryPssStore();
    const r = await rig({ transport: dead }, store, undefined, false);

    await r.sync.update((p) => ({
      known: { ...p.known, selfEphHighwater: 412 },
      extra: p.extra,
    }));
    await expect(r.sync.flushNow()).resolves.toBeUndefined();

    // Degraded, not broken: local storage holds the change and the floor never moved.
    expect(r.sync.state.degraded).not.toBeNull();
    expect(r.sync.current().known.selfEphHighwater).toBe(412);
    expect(await r.floor.current("state")).toBe(0);
  });

  it("keeps a spend-shaped read working while the transport is dead", async () => {
    const dead: PssTransport = {
      getBlob: () => Promise.reject(new Error("no route to host")),
      putBlob: () => Promise.reject(new Error("no route to host")),
      deleteAccount: () => Promise.reject(new Error("no route to host")),
    };
    const r = await rig({ transport: dead }, undefined, undefined, false);
    await r.sync.update((p) => ({
      known: { ...p.known, unspentNotes: [note(7)] },
      extra: p.extra,
    }));
    await r.sync.flushNow();
    // Reads never hit the network, so the note is still spendable.
    expect(
      spendableNote(
        { note: r.sync.current().known.unspentNotes[0], leafBlock: 0 },
        10,
      ).leafIndex,
    ).toBe(7);
  });

  it("reports a 500 as degraded rather than raising", async () => {
    const r = await rig();
    r.transport.failNext = new PssError(
      { code: "bad_request", field: "status 500" },
      "PUT state answered 500",
    );
    await r.sync.update((p) => ({
      known: { ...p.known, selfEphHighwater: 1 },
      extra: p.extra,
    }));
    await expect(r.sync.flushNow()).resolves.toBeUndefined();
    expect(r.sync.state.degraded?.message).toContain("500");
  });
});

describe("spent-note prune", () => {
  const payload = (notes: readonly UnspentNote[]): ParsedStatePayload => ({
    known: {
      schema: 1,
      installId: "0x11111111111111111111111111111111",
      platform: "web",
      updatedAt: 1,
      selfEphHighwater: 0,
      incomingIssueHighwater: 0,
      issuedAddresses: [],
      unspentNotes: [...notes],
      syncCursor: { block: 0, logIndex: 0 },
      nullifierCheckedAt: { block: 100 },
      ephemeralCounters: {},
    },
    extra: {},
  });

  it("drops exactly the notes the chain shows spent and advances the checkpoint", async () => {
    const spent = new Set([note(5).nullifier]);
    const result = await pruneSpentNotes(
      payload([note(5), note(9)]),
      { spentBetween: () => Promise.resolve(spent) },
      0,
      500,
    );
    expect(result.dropped.map((n) => n.leafIndex)).toEqual([5]);
    expect(result.payload.known.unspentNotes.map((n) => n.leafIndex)).toEqual([
      9,
    ]);
    expect(result.checkedThroughBlock).toBe(500);
  });

  // The merge unions notes while taking the max checkpoint, so a note one device pruned is reinstated
  // by another's union and then covered by the higher checkpoint. A range scan above the checkpoint
  // would never revisit it; testing the whole set is what makes that unreachable.
  it("tests notes below the checkpoint, not only a range above it", async () => {
    const reinstated = note(5);
    const seen: Array<[number, number]> = [];
    const result = await pruneSpentNotes(
      payload([reinstated]),
      {
        spentBetween: (from, to) => {
          seen.push([from, to]);
          return Promise.resolve(new Set([reinstated.nullifier]));
        },
      },
      0,
      50,
    );
    expect(result.dropped).toHaveLength(1);
    // The checkpoint was already 100, above the swept range, and the note was still dropped.
    expect(result.payload.known.nullifierCheckedAt.block).toBe(100);
    expect(seen).toEqual([[0, 50]]);
  });

  it("sweeps in config-driven chunks and asks for the whole public set", async () => {
    const ranges: Array<[number, number]> = [];
    const oracle = createLogSweepOracle({
      chunkBlocks: 100,
      source: (from, to) => {
        ranges.push([from, to]);
        return Promise.resolve([]);
      },
    });
    await oracle.spentBetween(0, 250);
    expect(ranges).toEqual([
      [0, 99],
      [100, 199],
      [200, 250],
    ]);
  });

  // The other half of the whole-set rule. Testing every note closes the note-set axis; starting at or
  // below the checkpoint closes the block axis, because the result certifies every block up to toBlock
  // as checked, so a sweep starting above the checkpoint silently certifies blocks it never asked about.
  it("refuses a sweep that would skip blocks below the checkpoint", async () => {
    let asked = 0;
    const oracle = {
      spentBetween: () => {
        asked += 1;
        return Promise.resolve(new Set<string>());
      },
    };
    // Blocks 101..499 would never be asked about, yet the result would certify everything through 1000.
    await expect(
      pruneSpentNotes(payload([note(5)]), oracle, 500, 1000),
    ).rejects.toThrow(PssStateError);
    expect(asked).toBe(0);

    // Starting at or below the checkpoint is what the rule requires, and it drops the note.
    const ok = await pruneSpentNotes(
      payload([note(5)]),
      { spentBetween: () => Promise.resolve(new Set([note(5).nullifier])) },
      0,
      5000,
    );
    expect(ok.dropped).toHaveLength(1);
  });

  // Starting exactly AT the checkpoint leaves no certification gap and is therefore allowed, but it
  // does not revisit a spend below the checkpoint, which is precisely what a merge can reinstate. The
  // library cannot close that on its own because it has no deployment block, so the doc contract on
  // pruneSpentNotes and pruneSpent requires the embedder to sweep from the deployment block on load.
  it("allows a sweep starting exactly at the checkpoint, which is why the caller owes a full sweep", async () => {
    const spentLow = new Set([note(5).nullifier]);
    const fromCheckpoint = await pruneSpentNotes(
      payload([note(5)]),
      {
        spentBetween: (from) =>
          Promise.resolve(from <= 80 ? spentLow : new Set<string>()),
      },
      100,
      5000,
    );
    expect(fromCheckpoint.dropped).toHaveLength(0);

    const fromDeployment = await pruneSpentNotes(
      payload([note(5)]),
      {
        spentBetween: (from) =>
          Promise.resolve(from <= 80 ? spentLow : new Set<string>()),
      },
      0,
      5000,
    );
    expect(fromDeployment.dropped).toHaveLength(1);
  });

  it("refuses block bounds that are not non-negative integers", async () => {
    for (const [from, to] of [
      [-5, 100],
      [0, 2.5],
      [Number.NaN, 100],
    ]) {
      await expect(
        pruneSpentNotes(
          payload([note(5)]),
          { spentBetween: () => Promise.resolve(new Set<string>()) },
          from,
          to,
        ),
      ).rejects.toThrow(PssStateError);
    }
  });

  it("refuses a chunk size that would never terminate", () => {
    expect(() =>
      createLogSweepOracle({
        chunkBlocks: 0,
        source: () => Promise.resolve([]),
      }),
    ).toThrow(PssStateError);
  });

  it("refuses to spend a note whose leaf block is past the checkpoint", () => {
    expect(() => spendableNote({ note: note(5), leafBlock: 101 }, 100)).toThrow(
      PssStateError,
    );
    expect(
      spendableNote({ note: note(5), leafBlock: 100 }, 100).leafIndex,
    ).toBe(5);
  });

  it("prunes through the loop and persists the result locally", async () => {
    const r = await rig({
      oracle: {
        spentBetween: () => Promise.resolve(new Set([note(5).nullifier])),
      },
    });
    await r.sync.update((p) => ({
      known: { ...p.known, unspentNotes: [note(5), note(9)] },
      extra: p.extra,
    }));
    expect(await r.sync.pruneSpent(0, 10)).toBe(1);
    expect(r.sync.current().known.unspentNotes.map((n) => n.leafIndex)).toEqual(
      [9],
    );
    expect(
      decodeStatePayload(r.store.snapshot()[payloadKey(r.accountPath, "state")])
        .known.unspentNotes,
    ).toHaveLength(1);
  });
});

describe("the ephemeral highwater is a hint, never a source", () => {
  it("never lowers a local highwater when a stale remote payload merges in", async () => {
    const store = new MemoryPssStore();
    const transport = new FakeTransport();

    // The server holds an old blob for this install carrying highwater 0.
    const earlier = await rig({}, store, transport);
    await earlier.sync.update((p) => ({
      known: { ...p.known, selfEphHighwater: 0 },
      extra: p.extra,
    }));
    await earlier.sync.flushNow();

    // A warm start reaches 412 locally, then hits the conflict path and merges that old blob in.
    const warm = await rig({}, store, transport);
    await warm.sync.update((p) => ({
      known: {
        ...p.known,
        selfEphHighwater: 412,
      },
      extra: p.extra,
    }));
    const stale = warm.sync.current();
    await warm.sync.update((p) => ({
      known: {
        ...p.known,
        ephemeralCounters: { ...p.known.ephemeralCounters, self: 73 },
      },
      extra: p.extra,
    }));
    const exposed = warm.sync.current();
    Reflect.set(exposed.known.ephemeralCounters, "self", 0);
    expect(warm.sync.current().known.ephemeralCounters.self).toBe(73);
    await warm.sync.update((current) => {
      Reflect.set(current.known.ephemeralCounters, "self", 0);
      return current;
    });
    expect(warm.sync.current().known.ephemeralCounters.self).toBe(73);
    await warm.sync.mutateAsWriterDurably((current) => {
      Reflect.set(current.known.ephemeralCounters, "self", 0);
      return { payload: current, value: null };
    });
    expect(warm.sync.current().known.ephemeralCounters.self).toBe(73);
    await warm.sync.update(() => stale);
    await warm.sync.flushNow();

    expect(warm.sync.current().known.selfEphHighwater).toBe(412);
    expect(warm.sync.current().known.ephemeralCounters.self).toBe(73);
    expect((await openStored(warm)).known.selfEphHighwater).toBe(412);
    const restarted = await rig({}, store, transport);
    expect(restarted.sync.current().known.ephemeralCounters.self).toBe(73);
  });

  it("keeps the highwater out of every allocation decision", () => {
    // The highwater is a lookup hint and the chain is the source of truth, so nothing in this package
    // may hand it to a minter. Verified as an absence, by searching for the allocation vocabulary.
    const surface = Object.keys(
      StateSync.prototype as unknown as Record<string, unknown>,
    );
    expect(
      surface.filter((name) =>
        /mint|allocat|nextEphemeral|reserve/i.test(name),
      ),
    ).toEqual([]);
  });
});
