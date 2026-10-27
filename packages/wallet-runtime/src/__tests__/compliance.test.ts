import { describe, expect, it } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import type { Point } from "@zk-kit/baby-jubjub";
import { publicKey } from "@hisoka/wallets";
import { RpcChainReader } from "../chain/chainReader.js";
import { RpcLogSource } from "../chain/logs.js";
import { WalletRuntimeError } from "../errors.js";
import { readComplianceHistory } from "../history/compliance.js";
import {
  configFor,
  FakeChain,
  type ComplianceState,
} from "./fixtures/chain.js";
import { MemoryStore } from "./fixtures/store.js";

const DEPLOY = 5;
const K: Point<bigint>[] = [11n, 22n, 33n, 44n].map((s) =>
  publicKey(new Fr(s)),
);

/** v1 at DEPLOY, v2 at 20, v3 at 30. */
function rotatingChain(opts: { initEvent: boolean }): FakeChain {
  const chain = new FakeChain(40);
  if (opts.initEvent)
    chain.emit(DEPLOY, "ComplianceKeyRotated", [0n, 1n, K[0]![0], K[0]![1]]);
  chain.emit(20, "ComplianceKeyRotated", [1n, 2n, K[1]![0], K[1]![1]]);
  chain.emit(30, "ComplianceKeyRotated", [2n, 3n, K[2]![0], K[2]![1]]);
  chain.compliance = (n): ComplianceState => {
    if (n < DEPLOY) return { x: 0n, y: 0n, version: 0 };
    const v = n >= 30 ? 3 : n >= 20 ? 2 : 1;
    return { x: K[v - 1]![0], y: K[v - 1]![1], version: v };
  };
  return chain;
}

function deps(chain: FakeChain, store = new MemoryStore()) {
  const config = configFor(DEPLOY);
  return {
    config,
    chain: RpcChainReader.over(chain.rpc, config),
    logs: RpcLogSource.over(chain.rpc, config),
    store,
  };
}

async function failure(p: Promise<unknown>): Promise<WalletRuntimeError> {
  const err = await p.then(
    () => undefined,
    (e: unknown) => e,
  );
  expect(err).toBeInstanceOf(WalletRuntimeError);
  return err as WalletRuntimeError;
}

function logStarts(chain: FakeChain): number[] {
  return chain.calls
    .filter((c) => c.method === "eth_getLogs")
    .map((c) => Number((c.params[0] as { fromBlock: string }).fromBlock));
}

describe("compliance key history", () => {
  it("takes version 1 from the initialization event and keys every rotation by its block", async () => {
    const chain = rotatingChain({ initEvent: true });
    const { history, head } = await readComplianceHistory(deps(chain));

    expect(head.number).toBe(40);
    expect(history.currentVersion).toBe(3);
    expect(history.currentPk).toEqual(K[2]);
    expect(
      history.ring.epochs.map((e) => [e.version, e.pk, e.fromBlock]),
    ).toEqual([
      [1, K[0], DEPLOY],
      [2, K[1], 20],
      [3, K[2], 30],
    ]);
    expect(history.ring.candidatesFor(25)[0]!.version).toBe(2);
    expect(
      chain.calls.some(
        (c) =>
          c.method === "eth_call" &&
          c.params[1] !== "latest" &&
          (c.params[1] as { blockHash: string }).blockHash ===
            chain.blocks[DEPLOY]!.hash,
      ),
    ).toBe(false);
  });

  it("falls back to state at the deployment block for a pool initialized before the event", async () => {
    const chain = rotatingChain({ initEvent: false });
    const { history } = await readComplianceHistory(deps(chain));
    expect(history.ring.epochs.map((e) => e.pk)).toEqual([K[0], K[1], K[2]]);
    const deployRead = chain.calls.find(
      (c) =>
        c.method === "eth_call" &&
        (c.params[1] as { blockHash?: string }).blockHash ===
          chain.blocks[DEPLOY]!.hash,
    );
    expect(deployRead).toBeDefined();
  });

  it("refuses the fallback when a rotation landed in the deployment block", async () => {
    const chain = rotatingChain({ initEvent: false });
    chain.emit(DEPLOY, "ComplianceKeyRotated", [1n, 2n, K[3]![0], K[3]![1]]);
    expect((await failure(readComplianceHistory(deps(chain)))).code).toBe(
      "COMPLIANCE_V1_UNKNOWN",
    );
  });

  it("refuses the fallback when state at the deployment block is not version 1", async () => {
    const chain = rotatingChain({ initEvent: false });
    chain.compliance = () => ({ x: K[1]![0], y: K[1]![1], version: 2 });
    expect((await failure(readComplianceHistory(deps(chain)))).code).toBe(
      "COMPLIANCE_V1_UNKNOWN",
    );
  });

  it("names the archive requirement when the fallback state read fails", async () => {
    const chain = rotatingChain({ initEvent: false });
    chain.archive = false;
    const err = await failure(readComplianceHistory(deps(chain)));
    expect(err.code).toBe("COMPLIANCE_V1_UNKNOWN");
    expect(err.message).toMatch(/archive/);
    expect(err.cause).toBeInstanceOf(WalletRuntimeError);
  });

  it("rejects an initialization event outside the configured deployment block", async () => {
    const chain = new FakeChain(40);
    chain.emit(DEPLOY + 2, "ComplianceKeyRotated", [
      0n,
      1n,
      K[0]![0],
      K[0]![1],
    ]);
    chain.compliance = () => ({ x: K[0]![0], y: K[0]![1], version: 1 });
    expect((await failure(readComplianceHistory(deps(chain)))).code).toBe(
      "COMPLIANCE_V1_UNKNOWN",
    );
  });

  it("fails when the logs miss the last rotation the chain reports", async () => {
    const chain = rotatingChain({ initEvent: true });
    chain.logs.splice(chain.logs.length - 1, 1);
    const err = await failure(readComplianceHistory(deps(chain)));
    expect(err.code).toBe("COMPLIANCE_HISTORY_INVALID");
    expect(err.context.reason).toBe("INCOMPLETE_HISTORY");
  });

  it("fails when a logged rotation does not end at the current key", async () => {
    const chain = rotatingChain({ initEvent: true });
    const honest = chain.compliance;
    chain.compliance = (n) =>
      n >= 30 ? { x: K[3]![0], y: K[3]![1], version: 3 } : honest(n);
    const err = await failure(readComplianceHistory(deps(chain)));
    expect(err.code).toBe("COMPLIANCE_HISTORY_INVALID");
    expect(err.context.reason).toBe("CURRENT_KEY_MISMATCH");
  });

  it("resumes from the cached head, and starts over when that head was reorged away", async () => {
    const chain = rotatingChain({ initEvent: true });
    const store = new MemoryStore();
    await readComplianceHistory(deps(chain, store));
    expect(Math.min(...logStarts(chain))).toBe(DEPLOY);

    chain.mine(10);
    chain.emit(45, "ComplianceKeyRotated", [3n, 4n, K[3]![0], K[3]![1]]);
    const honest = chain.compliance;
    chain.compliance = (n) =>
      n >= 45 ? { x: K[3]![0], y: K[3]![1], version: 4 } : honest(n);
    chain.calls.length = 0;
    const resumed = await readComplianceHistory(deps(chain, store));
    expect(resumed.history.currentVersion).toBe(4);
    expect(Math.min(...logStarts(chain))).toBe(41);
    expect(resumed.history.ring.epochs.map((e) => e.fromBlock)).toEqual([
      DEPLOY,
      20,
      30,
      45,
    ]);

    chain.reorgFrom(48);
    chain.calls.length = 0;
    const restarted = await readComplianceHistory(deps(chain, store));
    expect(restarted.history.currentVersion).toBe(4);
    expect(Math.min(...logStarts(chain))).toBe(DEPLOY);
  });

  it("names both numbers when the configured deployment block is above the chain head", async () => {
    const chain = new FakeChain(3);
    const err = await failure(readComplianceHistory(deps(chain)));
    expect(err.code).toBe("COMPLIANCE_V1_UNKNOWN");
    expect(err.message).toContain(
      "deployment block 5 is above the chain head 3",
    );
    expect(err.message).not.toMatch(/archive/);
  });

  it("refuses a rotation log whose old version is outside the safe integer range", async () => {
    const chain = rotatingChain({ initEvent: true });
    chain.emit(35, "ComplianceKeyRotated", [
      2n ** 53n + 1n,
      4n,
      K[3]![0],
      K[3]![1],
    ]);
    expect((await failure(readComplianceHistory(deps(chain)))).code).toBe(
      "RPC_RESPONSE_INVALID",
    );
  });

  it("ignores a cache that does not parse", async () => {
    const chain = rotatingChain({ initEvent: true });
    const store = new MemoryStore();
    const d = deps(chain, store);
    await readComplianceHistory(d);
    for (const key of store.data.keys()) store.data.set(key, "{not json");
    chain.calls.length = 0;
    expect((await readComplianceHistory(d)).history.currentVersion).toBe(3);
    expect(Math.min(...logStarts(chain))).toBe(DEPLOY);
  });
  it("starts over from a cache written without the initialization event", async () => {
    const chain = rotatingChain({ initEvent: true });
    const store = new MemoryStore();
    const d = deps(chain, store);
    await readComplianceHistory(d);
    for (const [key, raw] of store.data) {
      const snap = JSON.parse(raw) as { v: number; rotations: unknown[] };
      store.data.set(
        key,
        JSON.stringify({ ...snap, v: 1, rotations: snap.rotations.slice(1) }),
      );
    }
    chain.calls.length = 0;
    const { history } = await readComplianceHistory(d);
    expect(Math.min(...logStarts(chain))).toBe(DEPLOY);
    expect(history.ring.epochs[0]!.fromBlock).toBe(DEPLOY);
  });

  it("reads the current key at the head its logs reach, so a rotation landing mid-read cannot split them", async () => {
    const chain = rotatingChain({ initEvent: true });
    const d = deps(chain);
    const real = d.logs;
    let rotated = false;
    const logs = {
      logs: async (q: Parameters<typeof real.logs>[0]) => {
        const out = await real.logs(q);
        if (!rotated) {
          rotated = true;
          chain.mine();
          chain.emit(41, "ComplianceKeyRotated", [3n, 4n, K[3]![0], K[3]![1]]);
          const before = chain.compliance;
          chain.compliance = (n) =>
            n >= 41 ? { x: K[3]![0], y: K[3]![1], version: 4 } : before(n);
        }
        return out;
      },
    };
    const { history, head } = await readComplianceHistory({ ...d, logs });
    expect(head.number).toBe(40);
    expect(history.currentVersion).toBe(3);
    expect(history.currentPk).toEqual(K[2]);
  });
});
