import { describe, expect, it } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import type { UnspentNote } from "@hisoka/pss-client";
import { leaf } from "@hisoka/wallets";
import { WalletRuntimeError } from "../errors.js";
import {
  mirrorNotes,
  requireWriter,
  reverifyPssHints,
} from "../pss/noteMirror.js";
import {
  NoteStore,
  noteKey,
  type StoredNote,
  type SyncPoint,
} from "../store/noteStore.js";
import { FakePss, INSTALL } from "./fixtures/pss.js";
import { MemoryStore } from "./fixtures/store.js";
import { note } from "./fixtures/tree.js";

const KEY = "hisoka.runtime.v1.test.notes";

function at(n: number): SyncPoint {
  return { head: block(n), maxReorgBlocks: 16 };
}

function block(n: number): { number: number; hash: string } {
  return {
    number: n,
    hash: `0x${(0xb10c00 + n).toString(16).padStart(64, "0")}`,
  };
}

async function stored(
  leafIndex: number,
  at: number,
  extra: Partial<StoredNote> = {},
): Promise<StoredNote> {
  const n = note(BigInt(leafIndex));
  return {
    leafIndex,
    commitment: await leaf(n),
    note: n,
    nullifier: new Fr(0x9000n + BigInt(leafIndex)),
    origin: "self",
    derivationIndex: leafIndex,
    complianceVersion: 1,
    block: block(at),
    verification: "verified",
    spent: null,
    mirrored: false,
    ...extra,
  };
}

describe("PSS note mirror", () => {
  it("writes only verified notes at or below the PSS head, and moves the cursor and checkpoint no further", async () => {
    const notes = await NoteStore.open(new MemoryStore(), KEY);
    await notes.record(
      [
        await stored(1, 10),
        await stored(2, 30),
        await stored(3, 10, { verification: "unverified" }),
        await stored(4, 10, { spent: { block: block(15), txHash: "0x01" } }),
        await stored(5, 10, { spent: { block: block(25), txHash: "0x02" } }),
      ],
      at(30),
    );
    await notes.markSpent([], block(30), -1);
    const pss = new FakePss();
    const result = await mirrorNotes(pss, notes, block(20));

    expect(result).toEqual({ written: true, notes: 2, tombstones: 0 });
    const known = pss.payload.known;
    // 2 is above the head, 3 is unverified, 4 is spent at or below the checkpoint; 5's spend is above it.
    expect(known.unspentNotes.map((n) => n.leafIndex)).toEqual([1, 5]);
    expect(known.unspentNotes[0]).toEqual({
      leafIndex: 1,
      assetId: `0x${0xa11ce0001n.toString(16).padStart(40, "0")}`,
      amount: "1001",
      nullifier: `0x${(0x9001).toString(16).padStart(64, "0")}`,
      block: 10,
      blockHash: block(10).hash,
    });
    expect(known.syncCursor).toEqual({ block: 20, logIndex: 0 });
    expect(known.nullifierCheckedAt).toEqual({ block: 20 });
    expect(
      notes.notes.filter((n) => n.mirrored).map((n) => n.leafIndex),
    ).toEqual([1, 5]);
  });

  it("writes a tombstone for a mirrored note a rollback dropped, in the same write that removes it", async () => {
    const notes = await NoteStore.open(new MemoryStore(), KEY);
    const pss = new FakePss();
    const x = await stored(1, 10);
    await notes.record([x, await stored(2, 9)], at(10));
    await notes.markSpent([], block(10), -1);
    await mirrorNotes(pss, notes, block(10));
    expect(pss.payload.known.unspentNotes.map((n) => n.leafIndex)).toEqual([
      1, 2,
    ]);

    await notes.rollback({ ancestor: block(9), orphaned: [block(10)] });
    expect(notes.pendingTombstones).toHaveLength(1);
    await mirrorNotes(pss, notes, block(9));
    expect(pss.payload.known.unspentNotes.map((n) => n.leafIndex)).toEqual([2]);
    expect(pss.payload.known.droppedNotes).toEqual([
      {
        leafIndex: 1,
        nullifier: `0x${(0x9001).toString(16).padStart(64, "0")}`,
        block: 10,
        blockHash: block(10).hash,
      },
    ]);
    expect(notes.pendingTombstones).toEqual([]);
  });

  it("writes nothing from a read-only install, and refuses to mint there", async () => {
    const notes = await NoteStore.open(new MemoryStore(), KEY);
    await notes.record([await stored(1, 10)], at(10));
    const pss = new FakePss();
    pss.state = {
      mode: "readonly",
      heldBy: { installId: INSTALL, platform: "mobile/ios" },
    };
    expect(await mirrorNotes(pss, notes, block(10))).toEqual({
      written: false,
      notes: 0,
      tombstones: 0,
    });
    expect(pss.payload.known.unspentNotes).toEqual([]);
    const err = (() => {
      try {
        requireWriter(pss);
      } catch (e) {
        return e;
      }
      return null;
    })();
    expect((err as WalletRuntimeError).code).toBe("NOT_WRITER");
    expect((err as WalletRuntimeError).context.heldByPlatform).toBe(
      "mobile/ios",
    );
  });

  it("re-verifies PSS hints: a confirmed hint enters the store, a refuted one is tombstoned", async () => {
    const notes = await NoteStore.open(new MemoryStore(), KEY);
    const real = await stored(1, 10);
    const pss = new FakePss();
    const hint = (n: StoredNote, blockHash = n.block.hash): UnspentNote => ({
      leafIndex: n.leafIndex,
      assetId: `0x${n.note.assetId.toBigInt().toString(16).padStart(40, "0")}`,
      amount: n.note.value.toString(),
      nullifier: `0x${n.nullifier.toBigInt().toString(16).padStart(64, "0")}`,
      block: n.block.number,
      blockHash,
    });
    const fake = await stored(2, 11);
    const otherFork = await stored(3, 12);
    await pss.update((p) => ({
      known: {
        ...p.known,
        unspentNotes: [
          hint(real),
          hint(fake),
          hint(otherFork, `0x${"ee".repeat(32)}`),
        ],
      },
      extra: p.extra,
    }));
    const chainHas = new Map([
      [1, real],
      [3, otherFork],
    ]);
    const result = await reverifyPssHints(pss, notes, async (h) => {
      const found = chainHas.get(h.leafIndex);
      return found === undefined
        ? { kind: "rejected", reason: "no such note on chain" }
        : { kind: "confirmed", note: found };
    });
    expect(result).toEqual({ confirmed: 1, rejected: 2 });
    expect(notes.notes.map((n) => n.leafIndex)).toEqual([1]);
    expect(notes.find(noteKey(real))?.mirrored).toBe(true);
    expect(notes.pendingTombstones.map((t) => t.leafIndex)).toEqual([2, 3]);
    expect(notes.cursor).toBeNull();
  });
});
