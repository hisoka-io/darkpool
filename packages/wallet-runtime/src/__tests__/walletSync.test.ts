import { describe, expect, it } from "vitest";
import { RpcLogSource } from "../chain/logs.js";
import type { DiscoveryPort } from "../discovery/ports.js";
import { readComplianceHistory } from "../history/compliance.js";
import { mergeStatePayloads } from "@hisoka/pss-client";
import { WalletRuntimeError } from "../errors.js";
import {
  NoteStore,
  noteKey,
  nullifierHex,
  type NoteView,
} from "../store/noteStore.js";
import { syncWallet, type WalletSyncDeps } from "../walletSync.js";
import { funded, runtimeEnv, type RuntimeEnv } from "./fixtures/env.js";
import { ASSET, evenSelfIndex, selfNote } from "./fixtures/mint.js";
import { COMPLIANCE_PK } from "./fixtures/pool.js";
import { FakePss } from "./fixtures/pss.js";

function syncDeps(
  env: RuntimeEnv,
  pss: FakePss | undefined,
  discovery: DiscoveryPort = env.index,
): WalletSyncDeps {
  const config = env.pool.config;
  const logs = RpcLogSource.over(env.pool.chain.rpc, config);
  const historyDeps = { config, chain: env.chain, logs, store: env.store };
  return {
    config,
    chain: env.chain,
    logs,
    discovery,
    notes: env.notes,
    account: env.alice,
    history: async () => (await readComplianceHistory(historyDeps)).history,
    highWater: async () => ({ self: 40, incoming: 0 }),
    ...(pss === undefined ? {} : { pss }),
  };
}

function view(env: RuntimeEnv): NoteView {
  const head = env.pool.chain.head;
  return { confirmedHead: head, sweptThrough: head, now: 0n };
}

describe("wallet sync", () => {
  it("rolls the store back on a reorg, tombstones the mirrored note in PSS, and keeps only the re-mined note", async () => {
    const env = await runtimeEnv(20);
    const pss = new FakePss();
    const [first, second] = await funded(env, [100n, 20n]);
    await syncWallet(syncDeps(env, pss));
    expect(pss.payload.known.unspentNotes.map((n) => n.leafIndex)).toEqual([
      1, 2,
    ]);

    // The reorged chain mines someone else's note first, then the second note one index later.
    env.pool.reorgFrom(11);
    const pk = COMPLIANCE_PK[0]!;
    const other = await evenSelfIndex(env.bob, 0);
    await env.pool.insertSelf(11, await selfNote(env.bob, other, 7n, pk));
    const again = await evenSelfIndex(env.alice, second!.derivationIndex);
    await env.pool.insertSelf(
      12,
      await selfNote(env.alice, again, 20n, pk, ASSET),
    );
    const report = await syncWallet(syncDeps(env, pss));

    expect(report.head.rewoundTo).toBe(2);
    expect(report.rolledBack?.droppedNotes.map((n) => n.leafIndex)).toEqual([
      2,
    ]);
    expect(env.notes.notes.map((n) => [n.leafIndex, n.block.number])).toEqual([
      [1, 10],
      [3, 12],
    ]);
    const remined = env.notes.notes.find((n) => n.leafIndex === 3)!;
    expect(remined.nullifier.equals(second!.nullifier)).toBe(false);
    expect(pss.payload.known.droppedNotes).toEqual([
      {
        leafIndex: 2,
        nullifier: nullifierHex(second!.nullifier),
        block: 11,
        blockHash: second!.block.hash,
      },
    ]);
    expect(pss.payload.known.unspentNotes.map((n) => n.leafIndex)).toEqual([
      1, 3,
    ]);
    expect(env.notes.pendingTombstones).toEqual([]);
    expect(env.notes.find(`1:${first!.commitment.toString()}`)).toBeDefined();
  });

  it("undoes a spend whose block was reorged away, so the note is spendable again", async () => {
    const env = await runtimeEnv(20);
    const [note] = await funded(env, [100n]);
    env.pool.chain.mine(2);
    env.pool.spend(21, note!.nullifier);
    await syncWallet(syncDeps(env, undefined));
    expect(env.notes.notes[0]!.spent?.block.number).toBe(21);

    env.pool.reorgFrom(18);
    const report = await syncWallet(syncDeps(env, undefined));
    expect(report.rolledBack?.unspent.map((n) => n.leafIndex)).toEqual([1]);
    expect(env.notes.notes[0]!.spent).toBeNull();
    expect(env.notes.state(env.notes.notes[0]!, view(env))).toBe("spendable");
  });

  it("rolls back on a cursor that left the canonical chain even when the adapter reports no rewind", async () => {
    const env = await runtimeEnv(20);
    const [note] = await funded(env, [100n]);
    env.pool.chain.mine(2);
    env.pool.spend(21, note!.nullifier);
    const silent: DiscoveryPort = {
      sync: async () => {
        const head = await env.index.sync();
        return {
          leafCount: head.leafCount,
          root: head.root,
          block: head.block,
        };
      },
      match: (tags) => env.index.match(tags),
      leafAt: (i) => env.index.leafAt(i),
    };
    await syncWallet(syncDeps(env, undefined, silent));
    expect(env.notes.notes[0]!.spent).not.toBeNull();

    env.pool.reorgFrom(15);
    const report = await syncWallet(syncDeps(env, undefined, silent));
    expect(report.head.rewoundTo).toBeUndefined();
    expect(report.rolledBack?.unspent.map((n) => n.leafIndex)).toEqual([1]);
    expect(report.rolledBack?.droppedNotes).toEqual([]);
    expect(env.notes.notes[0]!.spent).toBeNull();
    expect(env.notes.cursor?.hash).toBe(env.pool.chain.blocks[22]!.hash);
  });

  it("drops nothing on an adapter rewind when every block the store recorded is still canonical", async () => {
    const env = await runtimeEnv(20);
    await funded(env, [100n, 20n]);
    let rewind = true;
    const rewinding: DiscoveryPort = {
      sync: async () => {
        const head = await env.index.sync();
        if (!rewind) return head;
        rewind = false;
        return {
          ...head,
          rewoundTo: 2,
          ancestor: {
            number: 10,
            hash: env.pool.chain.blocks[10]!.hash,
          },
        };
      },
      match: (tags) => env.index.match(tags),
      leafAt: (i) => env.index.leafAt(i),
    };
    const report = await syncWallet(syncDeps(env, undefined, rewinding));
    expect(report.head.rewoundTo).toBe(2);
    expect(report.rolledBack).toBeNull();
    expect(env.notes.notes.map((n) => n.leafIndex)).toEqual([1, 2]);
  });

  for (const shape of ["self-index", "silent adapter"] as const) {
    it(`keeps a canonical mirrored note through a tip reorg with nothing recorded near the tip (${shape})`, async () => {
      const env = await runtimeEnv(20);
      const pss = new FakePss();
      const silent: DiscoveryPort = {
        sync: async () => {
          const head = await env.index.sync();
          return {
            leafCount: head.leafCount,
            root: head.root,
            block: head.block,
          };
        },
        match: (tags) => env.index.match(tags),
        leafAt: (i) => env.index.leafAt(i),
      };
      const port = shape === "self-index" ? env.index : silent;
      const [note] = await funded(env, [100n]);
      env.pool.chain.mine(31);
      await syncWallet(syncDeps(env, pss, port));
      expect(pss.payload.known.unspentNotes.map((n) => n.leafIndex)).toEqual([
        1,
      ]);

      env.pool.reorgFrom(env.pool.chain.head);
      const report = await syncWallet(syncDeps(env, pss, port));
      expect(report.rolledBack?.droppedNotes).toEqual([]);
      expect(env.notes.notes.map((n) => n.block)).toEqual([note!.block]);
      expect(pss.payload.known.droppedNotes).toEqual([]);
      const merged = mergeStatePayloads([
        { payload: pss.current(), noteListComplete: true },
      ]);
      expect(merged.known.unspentNotes.map((n) => n.leafIndex)).toEqual([1]);
    });
  }

  for (const shape of ["self-index", "adapter that saw no reorg"] as const) {
    it(`fails REORG_TOO_DEEP and changes nothing when a block below the reorg bound left the chain (${shape})`, async () => {
      const env = await runtimeEnv(20);
      await funded(env, [100n]);
      env.pool.chain.mine(31);
      const last = await env.index.sync();
      const frozen: DiscoveryPort = {
        sync: async () => last,
        match: (tags) => env.index.match(tags),
        leafAt: (i) => env.index.leafAt(i),
      };
      const port = shape === "self-index" ? env.index : frozen;
      await syncWallet(syncDeps(env, undefined, port));
      const before = env.notes.notes;
      const cursor = env.notes.cursor;

      env.pool.reorgFrom(10);
      const err = await syncWallet(syncDeps(env, undefined, port)).catch(
        (e: unknown) => e,
      );
      expect((err as WalletRuntimeError).code).toBe("REORG_TOO_DEEP");
      expect((err as WalletRuntimeError).context.block).toBe("20");
      expect(env.notes.notes).toBe(before);
      expect(env.notes.cursor).toEqual(cursor);
    });
  }

  it("keeps the block a blockless adapter first found a note at, so the note confirms", async () => {
    const env = await runtimeEnv(20);
    const blockless: DiscoveryPort = {
      sync: () => env.index.sync(),
      match: async (tags) =>
        (await env.index.match(tags)).map((m) => ({
          ...m,
          blocks: m.positions.map(() => null),
        })),
      leafAt: (i) => env.index.leafAt(i),
    };
    await funded(env, [100n]);
    const first = env.pool.chain.blocks[20]!;
    // funded() synced through the self-index; start this store over under the blockless adapter.
    for (const n of env.notes.notes) await env.notes.discard(noteKey(n), null);
    await syncWallet(syncDeps(env, undefined, blockless));
    expect(env.notes.notes[0]!.block).toEqual({
      number: 20,
      hash: first.hash,
    });

    env.pool.chain.mine(5);
    await syncWallet(syncDeps(env, undefined, blockless));
    expect(env.notes.notes[0]!.block.number).toBe(20);
    expect(
      env.notes.state(env.notes.notes[0]!, {
        confirmedHead: 23,
        sweptThrough: 25,
        now: 0n,
      }),
    ).toBe("spendable");
  });

  it("tombstones a PSS hint discovery does not back, and leaves one above the chain head alone", async () => {
    const env = await runtimeEnv(20);
    const pss = new FakePss();
    await funded(env, [100n]);
    const hint = (leafIndex: number, block: number) => ({
      leafIndex,
      assetId: `0x${ASSET.toBigInt().toString(16).padStart(40, "0")}`,
      amount: "5",
      nullifier: `0x${(0x7700 + leafIndex).toString(16).padStart(64, "0")}`,
      block,
      blockHash: `0x${"cd".repeat(32)}`,
    });
    await pss.update((p) => ({
      known: { ...p.known, unspentNotes: [hint(1, 10), hint(9, 99)] },
      extra: p.extra,
    }));
    const report = await syncWallet(syncDeps(env, pss));
    expect(report.hints).toEqual({ confirmed: 0, rejected: 1 });
    expect(pss.payload.known.droppedNotes.map((t) => t.leafIndex)).toEqual([1]);
    expect(env.notes.notes.map((n) => n.leafIndex)).toEqual([1]);
  });

  it("leaves pending, never tombstones, a PSS hint past a lagging device's derivation window", async () => {
    const env = await runtimeEnv(20);
    const idx = await evenSelfIndex(env.alice, 30);
    await env.pool.insertSelf(
      12,
      await selfNote(env.alice, idx, 50n, COMPLIANCE_PK[0]!, ASSET),
    );
    const pss = new FakePss();
    await syncWallet({
      ...syncDeps(env, pss),
      highWater: async () => ({ self: idx, incoming: 0 }),
    });
    const real = pss.payload.known.unspentNotes[0]!;
    expect(real.block).toBe(12);

    // A second device of the account, whose counters lag, takes over as the writer.
    const lagging = await NoteStore.open(env.store, "hisoka.runtime.v1.test.b");
    const report = await syncWallet({
      ...syncDeps(env, pss),
      notes: lagging,
      highWater: async () => ({ self: 0, incoming: 0 }),
    });
    expect(report.hints).toEqual({ confirmed: 0, rejected: 0 });
    expect(pss.payload.known.droppedNotes).toEqual([]);
    expect(lagging.notes).toEqual([]);

    // The first device writes again and the hint is back for every device.
    await syncWallet({
      ...syncDeps(env, pss),
      highWater: async () => ({ self: idx, incoming: 0 }),
    });
    expect(pss.payload.known.unspentNotes).toEqual([real]);
  });

  it("tombstones a PSS hint whose block left the chain, though no note of the device sits at its leaf", async () => {
    const env = await runtimeEnv(20);
    const pss = new FakePss();
    const other = await evenSelfIndex(env.bob, 0);
    await env.pool.insertSelf(
      12,
      await selfNote(env.bob, other, 7n, COMPLIANCE_PK[0]!),
    );
    const gone = {
      leafIndex: 1,
      assetId: `0x${ASSET.toBigInt().toString(16).padStart(40, "0")}`,
      amount: "5",
      nullifier: `0x${"77".repeat(32)}`,
      block: 12,
      blockHash: `0x${"cd".repeat(32)}`,
    };
    await pss.update((p) => ({
      known: { ...p.known, unspentNotes: [gone] },
      extra: p.extra,
    }));
    const report = await syncWallet(syncDeps(env, pss));
    expect(report.hints).toEqual({ confirmed: 0, rejected: 1 });
    expect(pss.payload.known.droppedNotes).toEqual([
      {
        leafIndex: 1,
        nullifier: gone.nullifier,
        block: 12,
        blockHash: gone.blockHash,
      },
    ]);
  });

  it("tombstones a canonical PSS hint at a leaf the device holds with another note, or past the tree", async () => {
    const env = await runtimeEnv(20);
    const pss = new FakePss();
    const [held] = await funded(env, [100n]);
    const canonical = (leafIndex: number, block: number, n: number) => ({
      leafIndex,
      assetId: `0x${ASSET.toBigInt().toString(16).padStart(40, "0")}`,
      amount: "5",
      nullifier: `0x${n.toString(16).padStart(64, "0")}`,
      block,
      blockHash: env.pool.chain.blocks[block]!.hash,
    });
    const atHeld = canonical(held!.leafIndex, held!.block.number, 0x71);
    const pastTree = canonical(9, 15, 0x72);
    await pss.update((p) => ({
      known: { ...p.known, unspentNotes: [atHeld, pastTree] },
      extra: p.extra,
    }));
    const report = await syncWallet(syncDeps(env, pss));
    expect(report.hints).toEqual({ confirmed: 0, rejected: 2 });
    expect(
      pss.payload.known.droppedNotes.map((t) => [t.leafIndex, t.nullifier]),
    ).toEqual([
      [held!.leafIndex, atHeld.nullifier],
      [9, pastTree.nullifier],
    ]);
  });
});
