import { describe, expect, it } from "vitest";
import { deriveKeys, nobleBackend, sealCell } from "../crypto/index.js";
import {
  DEFAULT_SYNC_CONFIG,
  StateSync,
  StateSyncDeps,
} from "../sync/index.js";
import {
  PssRollbackError,
  PssSchemaError,
  PssStateError,
  VersionFloor,
  serializeStatePayload,
} from "../state/index.js";
import { PssCryptoError } from "../crypto/backend.js";
import { PssProtocolError } from "../wire/errors.js";
import { toBase64, toHexRaw, utf8 } from "../wire/codec.js";
import { MAX_CIPHERTEXT_BYTES, PSS_SCHEMA_VERSION } from "../wire/constants.js";
import { GetBlobResponse } from "../wire/types.js";
import { ParsedStatePayload } from "../wire/payload.js";
import { MemoryPssStore } from "./memoryStore.js";
import { HostileTransport } from "./hostileTransport.js";

const K_STATE = new Uint8Array(32).fill(7);
const NOW_MS = 1_785_900_000_000;

interface Victim {
  readonly sync: StateSync;
  readonly store: MemoryPssStore;
  readonly transport: HostileTransport;
  readonly floor: VersionFloor;
  readonly keys: Awaited<ReturnType<typeof deriveKeys>>;
  readonly accountPath: string;
}

async function victim(
  store = new MemoryPssStore(),
  transport = new HostileTransport(),
): Promise<Victim> {
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
  };
  return {
    sync: await StateSync.open(deps),
    store,
    transport,
    floor,
    keys,
    accountPath: toHexRaw(keys.accountId),
  };
}

/** Drives the victim to a stored version, honestly, so an attack has something to lie about. */
async function seeded(highwater = 1): Promise<Victim> {
  const v = await victim();
  for (let i = 1; i <= highwater; i++) {
    await v.sync.update((p) => ({
      known: { ...p.known, selfEphHighwater: i },
      extra: p.extra,
    }));
    await v.sync.flushNow();
  }
  await v.sync.pull();
  return v;
}

async function serveSealed(
  v: Victim,
  payload: ParsedStatePayload,
  sealVersion: number,
  envelopeVersion: number,
  collection: "state" | "labels" = "state",
): Promise<GetBlobResponse> {
  const sealed = await sealCell(
    nobleBackend,
    v.keys.cellKey[collection],
    { collection, version: sealVersion },
    utf8(serializeStatePayload(payload)),
  );
  return {
    version: envelopeVersion,
    prevVersion: Math.max(0, envelopeVersion - 1),
    nonce: toBase64(sealed.nonce),
    ciphertext: toBase64(sealed.ciphertext),
    serverTime: 1_785_900_000,
  };
}

describe("attack 1: rollback", () => {
  it("refuses a version below the floor, naming both", async () => {
    const v = await seeded(3);
    expect(await v.floor.current("state")).toBe(3);
    v.transport.lie = { kind: "rollback", version: 1 };

    await expect(v.sync.pull()).rejects.toThrow(PssRollbackError);
    await expect(v.sync.pull()).rejects.toThrow(/state.*1.*3/s);
    expect(await v.floor.current("state")).toBe(3);

    v.transport.stopLying();
    await expect(v.sync.pull()).resolves.toMatchObject({ kind: "present" });
  });
});

describe("attack 2: dropped write", () => {
  it("does not treat its own write as landed when the server keeps nothing", async () => {
    const v = await seeded(1);
    v.transport.lie = { kind: "drop_writes" };

    await v.sync.update((p) => ({
      known: { ...p.known, selfEphHighwater: 99 },
      extra: p.extra,
    }));
    await v.sync.flushNow();

    // The server answered 200 and stored nothing, so a re-read serves the superseded version. The
    // client raised its floor on its own accepted write, so it refuses that rather than accepting it
    // as current: acknowledging a write and then serving something older IS a rollback.
    await expect(v.sync.pull()).rejects.toThrow(PssRollbackError);
    expect(v.transport.honest.stored(v.accountPath, "state")?.version).toBe(1);
    // Local storage still holds the change, so nothing was lost.
    expect(v.sync.current().known.selfEphHighwater).toBe(99);

    // Recovery is NOT automatic here, and that is the deliberate trade. Raising the floor on an
    // accepted write is what lets the client detect the drop at all; the cost is that a server which
    // destroyed an acknowledged write is now behind the floor, so honest service alone cannot restore
    // it. The client fails closed and reports, local state keeps every change, and the documented
    // recovery is a client-side resync from the chain rather than a server repair.
    v.transport.stopLying();
    await expect(v.sync.flushNow()).resolves.toBeUndefined();
    expect(v.sync.state.degraded).not.toBeNull();
    expect(v.sync.current().known.selfEphHighwater).toBe(99);
    expect(await v.floor.current("state")).toBe(2);
  });
});

describe("attack 3: collection substitution", () => {
  it("fails at the AEAD when the labels blob is served at the state path", async () => {
    const v = await seeded(1);
    // A labels cell exists at the same version, sealed under the labels key and AAD.
    const labels = await serveSealed(v, v.sync.current(), 1, 1, "labels");
    v.transport.lie = { kind: "serve", body: labels };

    await expect(v.sync.pull()).rejects.toThrow(PssCryptoError);

    v.transport.stopLying();
    await expect(v.sync.pull()).resolves.toMatchObject({ kind: "present" });
  });
});

describe("attack 4: oversized body", () => {
  it("refuses an oversized ciphertext before attempting to decrypt", async () => {
    const v = await seeded(1);
    for (const size of [MAX_CIPHERTEXT_BYTES + 1, MAX_CIPHERTEXT_BYTES * 2]) {
      v.transport.lie = {
        kind: "serve",
        body: {
          version: 2,
          prevVersion: 1,
          nonce: Buffer.alloc(12).toString("base64"),
          ciphertext: Buffer.alloc(size).toString("base64"),
          serverTime: 1,
        },
      };
      await expect(v.sync.pull()).rejects.toThrow(PssProtocolError);
    }
    // The refusal happened at the parser, so the floor never moved.
    expect(await v.floor.current("state")).toBe(1);

    v.transport.stopLying();
    await expect(v.sync.pull()).resolves.toMatchObject({ kind: "present" });
  });
});

describe("attack 5: wrong-collection ciphertext at a matching version", () => {
  it("refuses a ciphertext sealed under the other collection's AAD", async () => {
    const v = await seeded(1);
    const body = await serveSealed(v, v.sync.current(), 2, 2, "labels");
    v.transport.lie = { kind: "serve", body };

    await expect(v.sync.pull()).rejects.toThrow(PssCryptoError);
    // The floor did not take the version the unopenable cell claimed.
    expect(await v.floor.current("state")).toBe(1);

    v.transport.stopLying();
    await expect(v.sync.pull()).resolves.toMatchObject({ kind: "present" });
  });
});

describe("attack 6: post-reinstall rollback", () => {
  it("refuses version 1 against a floor bootstrapped from the chain", async () => {
    const transport = new HostileTransport();
    const first = await victim(new MemoryPssStore(), transport);
    for (let i = 1; i <= 3; i++) {
      await first.sync.update((p) => ({
        known: { ...p.known, selfEphHighwater: i },
        extra: p.extra,
      }));
      await first.sync.flushNow();
    }

    // A reinstall: empty local store, floor bootstrapped before any PSS value is trusted.
    const fresh = await victim(new MemoryPssStore(), transport);
    await fresh.floor.bootstrap("state", 3);
    transport.lie = { kind: "rollback", version: 1 };

    await expect(fresh.sync.pull()).rejects.toThrow(PssRollbackError);
    expect(await fresh.floor.current("state")).toBe(3);
  });
});

describe("attack 7: a payload from a newer schema", () => {
  it("refuses it, and does not merge, narrow or re-upload it", async () => {
    const v = await seeded(1);
    const future = JSON.parse(
      serializeStatePayload(v.sync.current()),
    ) as Record<string, unknown>;
    // Relative to the current version, not a literal: a schema bump must not silently turn this
    // attack into a legal payload.
    future.schema = PSS_SCHEMA_VERSION + 1;
    const sealed = await sealCell(
      nobleBackend,
      v.keys.cellKey.state,
      { collection: "state", version: 2 },
      utf8(JSON.stringify(future)),
    );
    v.transport.lie = {
      kind: "serve",
      body: {
        version: 2,
        prevVersion: 1,
        nonce: toBase64(sealed.nonce),
        ciphertext: toBase64(sealed.ciphertext),
        serverTime: 1,
      },
    };

    await expect(v.sync.pull()).rejects.toThrow(PssSchemaError);
    // Nothing from the future payload reached local state, and nothing was written back.
    expect(v.sync.current().known.selfEphHighwater).toBe(1);
    expect(v.transport.honest.stored(v.accountPath, "state")?.version).toBe(1);
  });
});

describe("attack 8: mixed and alternating staleness", () => {
  it("keeps the floor monotone across an alternating server", async () => {
    const v = await seeded(3);
    for (const version of [3, 2, 3, 1]) {
      v.transport.lie = { kind: "rollback", version };
      if (version < 3) {
        await expect(v.sync.pull()).rejects.toThrow(PssRollbackError);
      } else {
        await expect(v.sync.pull()).resolves.toMatchObject({ kind: "present" });
      }
      expect(await v.floor.current("state")).toBe(3);
    }
  });

  it("keeps one collection's staleness out of the other's floor", async () => {
    const v = await seeded(2);
    expect(await v.floor.current("state")).toBe(2);
    // labels was never written, so its floor is independent and still zero.
    expect(await v.floor.current("labels")).toBe(0);
  });
});

describe("attack 9: swapped nonce", () => {
  it("fails closed on a rewritten nonce and recovers on the next honest write", async () => {
    const v = await seeded(1);
    // The PUT preimage does not cover the nonce, so an on-path rewrite of just that field is accepted
    // by the server, stored verbatim, and leaves the owner unable to open the cell.
    v.transport.lie = {
      kind: "swap_nonce",
      nonce: Buffer.alloc(12, 0xab).toString("base64"),
    };
    await expect(v.sync.pull()).rejects.toThrow(PssCryptoError);

    v.transport.stopLying();
    await v.sync.update((p) => ({
      known: { ...p.known, selfEphHighwater: 7 },
      extra: p.extra,
    }));
    await v.sync.flushNow();
    await expect(v.sync.pull()).resolves.toMatchObject({ kind: "present" });
    expect(v.sync.state.degraded).toBeNull();
  });
});

describe("attack 10: flipped ciphertext byte", () => {
  it("fails at the authentication tag rather than decrypting garbage", async () => {
    const v = await seeded(1);
    v.transport.lie = { kind: "flip_ciphertext_byte" };
    await expect(v.sync.pull()).rejects.toThrow(PssCryptoError);
    expect(v.sync.current().known.selfEphHighwater).toBe(1);

    v.transport.stopLying();
    await expect(v.sync.pull()).resolves.toMatchObject({ kind: "present" });
  });
});

describe("attack 11: wrong version in the envelope", () => {
  it("refuses to open a correct ciphertext at a version it was not sealed under", async () => {
    const v = await seeded(2);
    // The AAD binds collection and version, so claiming a different version breaks authentication even
    // though the ciphertext is genuine.
    v.transport.lie = { kind: "wrong_version", version: 5 };
    await expect(v.sync.pull()).rejects.toThrow(PssCryptoError);

    // The invented version must NOT have moved the floor. The floor only goes up, so a server that
    // could raise it with an unauthenticated claim would wedge the account with a single response:
    // every honest version below the invented one would afterwards read as a rollback.
    expect(await v.floor.current("state")).toBe(2);

    v.transport.stopLying();
    await expect(v.sync.pull()).resolves.toMatchObject({ kind: "present" });
  });

  it("cannot raise the floor with an absurd invented version", async () => {
    const v = await seeded(2);
    v.transport.lie = { kind: "wrong_version", version: 9_000_000 };
    await expect(v.sync.pull()).rejects.toThrow(PssCryptoError);
    expect(await v.floor.current("state")).toBe(2);

    v.transport.stopLying();
    await expect(v.sync.pull()).resolves.toMatchObject({ kind: "present" });
  });
});

describe("attack 12: 404 against a non-zero floor", () => {
  it("does not promote to writer, and recreates above the floor", async () => {
    const v = await seeded(2);
    v.transport.lie = { kind: "always_absent" };

    const outcome = await v.sync.pull();
    expect(outcome).toEqual({ kind: "missing", floor: 2 });
    expect(v.sync.state.blobMissing).toBe(true);

    // 404 forever: the loop must keep reporting it rather than deciding it is a fresh account.
    for (let i = 0; i < 3; i++) {
      expect(await v.sync.pull()).toEqual({ kind: "missing", floor: 2 });
    }
    expect(await v.floor.current("state")).toBe(2);
  });
});

// Not on the list. The frozen payload rule says a client MUST preserve unknown fields verbatim through
// a merge, and the merge does exactly that, so a writer can put arbitrary junk in an unknown field and
// every other device carries it faithfully and re-uploads it forever. Pushed far enough it crosses a
// padding tier and then the 1 MB ceiling, at which point the client can no longer write its own state.
//
// The actor is NOT the server: the junk has to arrive in a cell that opens under the account's own cell
// key, which the server never holds. It is a writer that legitimately holds that key, meaning a
// future-schema client of the same account or a compromised device. The seal below uses the victim's
// own cellKey.state for exactly that reason.
describe("attack 13 (mine): unknown-field amplification", () => {
  async function inject(v: Victim, junkBytes: number): Promise<void> {
    const carrier = JSON.parse(
      serializeStatePayload(v.sync.current()),
    ) as Record<string, unknown>;
    carrier.junk = "x".repeat(junkBytes);
    const sealed = await sealCell(
      nobleBackend,
      v.keys.cellKey.state,
      { collection: "state", version: 2 },
      utf8(JSON.stringify(carrier)),
    );
    v.transport.lie = {
      kind: "serve",
      body: {
        version: 2,
        prevVersion: 1,
        nonce: toBase64(sealed.nonce),
        ciphertext: toBase64(sealed.ciphertext),
        serverTime: 1,
      },
    };
  }

  it("carries the server's junk verbatim, which is the lever", async () => {
    const v = await seeded(1);
    await inject(v, 4_096);
    const outcome = await v.sync.pull();
    expect(outcome).toMatchObject({ kind: "present" });
    if (outcome.kind !== "present") throw new Error("unreachable");
    // Preserved verbatim, exactly as the schema rule requires. The client will now re-upload it.
    expect(outcome.payload.extra.junk).toHaveLength(4_096);
  });

  it("fails closed, not by truncating, once the server has eaten the storage budget", async () => {
    const v = await seeded(1);
    // Just inside the ceiling, so the response is deliverable and the client must accept it. The merge
    // on read is what pulls the junk into local state, exactly as the schema rule requires.
    await inject(v, 1_040_000);
    await expect(v.sync.pull()).resolves.toMatchObject({ kind: "present" });
    expect(v.sync.current().extra.junk).toHaveLength(1_040_000);

    // The client's own state no longer fits beside the junk. It must refuse with a typed error and
    // report degraded, never silently drop fields to make room.
    await v.sync.update((p) => ({
      known: {
        ...p.known,
        unspentNotes: Array.from({ length: 200 }, (_unused, i) => ({
          leafIndex: i,
          assetId: "0x1234567890123456789012345678901234567890",
          amount: "1000",
          nullifier: `0x${i.toString(16).padStart(64, "0")}`,
        })),
      },
      extra: p.extra,
    }));
    await expect(v.sync.flushNow()).resolves.toBeUndefined();

    expect(v.sync.state.degraded?.message).toMatch(/exceeds the largest tier/i);
    // Nothing was truncated: the junk and the notes are both still in local state.
    expect(v.sync.current().known.unspentNotes).toHaveLength(200);
    expect(v.sync.current().extra.junk).toHaveLength(1_040_000);
  });
});

describe("no attack blocks a spend, and none lowers a floor", () => {
  it("leaves local state readable through every lie", async () => {
    const v = await seeded(2);
    const before = v.sync.current().known.selfEphHighwater;
    const lies: HostileTransport["lie"][] = [
      { kind: "rollback", version: 1 },
      { kind: "flip_ciphertext_byte" },
      { kind: "swap_nonce", nonce: Buffer.alloc(12, 1).toString("base64") },
      { kind: "always_absent" },
      { kind: "drop_writes" },
    ];
    for (const lie of lies) {
      v.transport.lie = lie;
      await v.sync.pull().catch(() => undefined);
      expect(v.sync.current().known.selfEphHighwater).toBe(before);
      expect(await v.floor.current("state")).toBeGreaterThanOrEqual(2);
    }
  });

  it("never lets a hostile response promote a read-only install to writer", async () => {
    const transport = new HostileTransport();
    const a = await victim(new MemoryPssStore(), transport);
    await a.sync.update((p) => ({
      known: { ...p.known, selfEphHighwater: 1 },
      extra: p.extra,
    }));
    await a.sync.flushNow();

    const b = await victim(new MemoryPssStore(), transport);
    await b.sync.pull();
    expect(b.sync.state.mode).toBe("readonly");

    // A 404 must not hand B the writer role either.
    transport.lie = { kind: "always_absent" };
    await b.sync.pull();
    expect(b.sync.state.mode).toBe("readonly");
    await b.sync.update((p) => ({
      known: { ...p.known, selfEphHighwater: 50 },
      extra: p.extra,
    }));
    await expect(b.sync.flushNow()).resolves.toBeUndefined();
    expect(b.sync.state.degraded?.message).toContain("read-only");
  });
});

describe("every refusal is typed and actionable", () => {
  it("throws only from the existing error family, and names what it refused", async () => {
    const v = await seeded(3);
    const cases: ReadonlyArray<[HostileTransport["lie"], RegExp]> = [
      [{ kind: "rollback", version: 1 }, /rollback|below/i],
      [{ kind: "flip_ciphertext_byte" }, /authentication/i],
      [
        { kind: "swap_nonce", nonce: Buffer.alloc(12, 2).toString("base64") },
        /authentication/i,
      ],
      [
        {
          kind: "serve",
          body: {
            version: 9,
            prevVersion: 8,
            nonce: Buffer.alloc(12).toString("base64"),
            ciphertext: Buffer.alloc(MAX_CIPHERTEXT_BYTES + 1).toString(
              "base64",
            ),
            serverTime: 1,
          },
        },
        /ciphertext must be/i,
      ],
    ];

    for (const [lie, message] of cases) {
      v.transport.lie = lie;
      const error: unknown = await v.sync.pull().then(
        () => null,
        (thrown: unknown) => thrown,
      );
      expect(error).toBeInstanceOf(Error);
      // No bare throws, no string errors, no parallel family.
      expect(
        error instanceof PssRollbackError ||
          error instanceof PssSchemaError ||
          error instanceof PssStateError ||
          error instanceof PssCryptoError ||
          error instanceof PssProtocolError,
      ).toBe(true);
      expect((error as Error).message).toMatch(message);
    }
  });
});
