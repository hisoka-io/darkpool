import { describe, expect, it } from "vitest";
import { RpcLogSource } from "../chain/logs.js";
import type { DiscoveryPort } from "../discovery/ports.js";
import { readComplianceHistory } from "../history/compliance.js";
import { nullifierHex, type NoteView } from "../store/noteStore.js";
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

  it("rolls back what the adapter reports rewound even while the store's cursor is still canonical", async () => {
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
    expect(report.rolledBack?.droppedNotes.map((n) => n.leafIndex)).toEqual([
      2,
    ]);
    // Discovery finds the note again at the same position, since the chain still holds it.
    expect(env.notes.notes.map((n) => n.leafIndex)).toEqual([1, 2]);
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
});
