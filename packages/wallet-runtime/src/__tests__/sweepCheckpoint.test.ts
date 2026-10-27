import { describe, expect, it } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import { computeNullifier } from "@hisoka/wallets";
import { WalletRuntimeError } from "../errors.js";
import { RpcLogSource, type LogSource } from "../chain/logs.js";
import type { DiscoveryPort } from "../discovery/ports.js";
import { readComplianceHistory } from "../history/compliance.js";
import { sweepNullifiers } from "../history/nullifiers.js";
import { noteKey, type NoteView } from "../store/noteStore.js";
import { syncWallet, type WalletSyncDeps } from "../walletSync.js";
import { funded, runtimeEnv, type RuntimeEnv } from "./fixtures/env.js";
import { ASSET, evenSelfIndex, selfNote } from "./fixtures/mint.js";
import { COMPLIANCE_PK } from "./fixtures/pool.js";

const RECIPIENT = "0x00000000000000000000000000000000000000c0";

function deps(
  env: RuntimeEnv,
  discovery: DiscoveryPort,
  self: number,
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
    highWater: async () => ({ self, incoming: 0 }),
  };
}

function view(env: RuntimeEnv): NoteView {
  return {
    confirmedHead: env.pool.chain.head,
    sweptThrough: env.notes.sweptThrough,
    now: 0n,
  };
}

describe("nullifier sweep checkpoint", () => {
  it("marks spent a note minted and spent between the discovery head and the sweep head of one sync", async () => {
    const env = await runtimeEnv(20);
    const idx = await evenSelfIndex(env.alice, 0);
    const minted = await selfNote(
      env.alice,
      idx,
      50n,
      COMPLIANCE_PK[0]!,
      ASSET,
    );
    let raced = false;
    const racing: DiscoveryPort = {
      sync: async () => {
        const head = await env.index.sync();
        if (!raced) {
          raced = true;
          // Another device of the account mints and spends after discovery read its head.
          env.pool.chain.mine(2);
          const leaf = await env.pool.insertSelf(
            env.pool.chain.head - 1,
            minted,
          );
          env.pool.spend(
            env.pool.chain.head,
            await computeNullifier(minted.note.psi, new Fr(BigInt(leaf))),
          );
        }
        return head;
      },
      match: (t) => env.index.match(t),
      leafAt: (i) => env.index.leafAt(i),
    };
    await syncWallet(deps(env, racing, 40));
    expect(env.notes.notes).toHaveLength(0);
    env.pool.chain.mine(3);
    await syncWallet(deps(env, racing, 40));
    const found = env.notes.notes[0]!;
    expect(found.spent?.block.number).toBe(22);
    expect(env.notes.state(found, view(env))).toBe("spent");
  });

  it("marks spent a note found only after the derivation window widens, spent before that", async () => {
    const env = await runtimeEnv(20);
    const idx = await evenSelfIndex(env.alice, 30);
    const minted = await selfNote(
      env.alice,
      idx,
      50n,
      COMPLIANCE_PK[0]!,
      ASSET,
    );
    const leaf = await env.pool.insertSelf(12, minted);
    env.pool.spend(
      13,
      await computeNullifier(minted.note.psi, new Fr(BigInt(leaf))),
    );
    await syncWallet(deps(env, env.index, 0));
    expect(env.notes.notes).toHaveLength(0);
    expect(env.notes.sweptThrough).toBe(20);
    await syncWallet(deps(env, env.index, idx));
    const found = env.notes.notes[0]!;
    expect(found.spent?.block.number).toBe(13);
    expect(env.notes.state(found, view(env))).toBe("spent");
  });

  it("re-reads every spend for a late note an adapter files under the sync head", async () => {
    const env = await runtimeEnv(20);
    const idx = await evenSelfIndex(env.alice, 30);
    const minted = await selfNote(
      env.alice,
      idx,
      50n,
      COMPLIANCE_PK[0]!,
      ASSET,
    );
    const leaf = await env.pool.insertSelf(12, minted);
    env.pool.spend(
      13,
      await computeNullifier(minted.note.psi, new Fr(BigInt(leaf))),
    );
    const blockless: DiscoveryPort = {
      sync: () => env.index.sync(),
      match: async (tags) =>
        (await env.index.match(tags)).map((m) => ({
          ...m,
          blocks: m.blocks.map(() => null),
        })),
      leafAt: (i) => env.index.leafAt(i),
    };
    await syncWallet(deps(env, blockless, 0));
    env.pool.chain.mine(5);
    await syncWallet(deps(env, blockless, idx));
    const found = env.notes.notes[0]!;
    expect(found.block.number).toBe(25);
    expect(found.spent?.block.number).toBe(13);
  });

  it("rolls the checkpoint back when a block it swept leaves the chain above the discovery cursor", async () => {
    const env = await runtimeEnv(20);
    const [note] = await funded(env, [100n]);
    expect(env.notes.cursor?.number).toBe(20);
    // An action's pre-step sweep takes the checkpoint past the discovery cursor.
    env.pool.chain.mine(5);
    const config = env.pool.config;
    await sweepNullifiers(
      {
        config,
        chain: env.chain,
        logs: RpcLogSource.over(env.pool.chain.rpc, config),
      },
      env.notes,
    );
    expect(env.notes.sweptThrough).toBe(25);
    env.pool.reorgFrom(22);
    env.pool.spend(23, note!.nullifier);
    env.pool.chain.mine(2);
    await env.refresh();
    expect(env.notes.notes[0]!.spent?.block.number).toBe(23);
  });

  it("discards a sweep whose checkpoint was lowered while it read, and reads again from the lower point", async () => {
    const env = await runtimeEnv(20);
    const [note] = await funded(env, [100n]);
    expect(env.notes.sweptThrough).toBe(20);
    env.pool.spend(15, note!.nullifier);
    env.pool.chain.mine(2);
    const config = env.pool.config;
    const inner = RpcLogSource.over(env.pool.chain.rpc, config);
    let lowered = false;
    const lowering: LogSource = {
      logs: async (query) => {
        if (!lowered) {
          lowered = true;
          await env.notes.resweepFrom(note!.block.number);
        }
        return inner.logs(query);
      },
    };
    await sweepNullifiers(
      { config, chain: env.chain, logs: lowering },
      env.notes,
    );
    expect(lowered).toBe(true);
    expect(env.notes.find(noteKey(note!))?.spent?.block.number).toBe(15);
    expect(env.notes.sweptThrough).toBe(22);
  });

  it("re-sweeps an input the pool reports spent before failing the action, and marks it spent", async () => {
    const env = await runtimeEnv(40);
    const [note] = await funded(env, [100n]);
    expect(env.notes.sweptThrough).toBe(40);
    // A spend the checkpoint already passed: only a re-sweep from the note's block sees it.
    env.pool.spend(30, note!.nullifier);
    env.submitter.next = {
      status: "not-sent",
      stage: "simulation",
      detail: "eth_call reverted: NullifierAlreadySpent",
      errorName: "NullifierAlreadySpent",
    };
    const err = await env.pipeline.withdraw(note!, 30n, RECIPIENT).then(
      () => null,
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(WalletRuntimeError);
    expect((err as WalletRuntimeError).code).toBe("INPUT_SPENT");
    expect((err as WalletRuntimeError).context.leafIndex).toBe(
      String(note!.leafIndex),
    );
    expect(env.notes.find(noteKey(note!))?.spent?.block.number).toBe(30);
    expect(env.notes.plans[env.notes.plans.length - 1]).toMatchObject({
      status: "failed",
      leased: [],
    });
  });
});
