import { describe, expect, it } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import { parseDeploymentRef } from "@hisoka/howl-protocol";
import type { ChainView } from "@hisoka/wallets/tx";
import { RpcChainReader } from "../chain/chainReader.js";
import { HARDHAT_CHAIN_CONFIG } from "../config.js";
import { WalletRuntimeError } from "../errors.js";
import {
  blockJson,
  hash32,
  poolCallHandler,
  scriptedRpc,
} from "./fixtures/rpc.js";

const POOL = "0x6dab000000000000000000000000000000000001";
const CONFIG = HARDHAT_CHAIN_CONFIG(
  parseDeploymentRef({
    domain_version: 1,
    chain_id: "31337",
    dark_pool: POOL,
    deployment_block: "1",
  }),
);
const ROOT = new Fr(0x1234n);

function expectCode(e: unknown, code: string): WalletRuntimeError {
  expect(e).toBeInstanceOf(WalletRuntimeError);
  expect((e as WalletRuntimeError).code).toBe(code);
  return e as WalletRuntimeError;
}

function poolAt(leafCount: bigint, root: Fr) {
  return poolCallHandler((name) => {
    if (name === "getNextLeafIndex") return [leafCount];
    if (name === "getCurrentRoot") return [root.toString()];
    if (name === "isKnownRoot") return [true];
    return [7n, 8n, 2n];
  });
}

describe("chain reader", () => {
  it("reads (leafCount, root) with one EIP-1898 block hash on both calls", async () => {
    const { rpc, calls } = scriptedRpc({
      eth_getBlockByNumber: ([tag]) =>
        blockJson(tag === "latest" ? 40 : Number(tag)),
      eth_call: poolAt(9n, ROOT),
    });
    const reader = RpcChainReader.over(rpc, CONFIG);
    const head = await reader.latest();
    const state = await reader.treeState(head);

    expect(state.leafCount).toBe(9);
    expect(state.root.equals(ROOT)).toBe(true);
    expect(state.block).toBe(head);
    const reads = calls.filter((c) => c.method === "eth_call");
    expect(reads).toHaveLength(2);
    for (const read of reads) {
      expect((read.params[0] as { to: string }).to).toBe(POOL);
      expect(read.params[1]).toEqual({
        blockHash: head.hash,
        requireCanonical: true,
      });
    }
  });

  it("fails RPC_CAPABILITY when the node refuses the block-hash form, with no number-tag fallback", async () => {
    const { rpc, calls } = scriptedRpc({
      eth_call: (params) => {
        if (typeof params[1] === "object") {
          throw Object.assign(new Error("invalid argument 1"), {
            code: -32602,
          });
        }
        return poolAt(9n, ROOT)(params);
      },
    });
    const reader = RpcChainReader.over(rpc, CONFIG);
    const head = { number: 40, hash: hash32(40), timestamp: 1n };
    const err = await reader.treeState(head).catch((e: unknown) => e);
    expectCode(err, "RPC_CAPABILITY");
    expect(calls.every((c) => typeof c.params[1] === "object")).toBe(true);
  });

  it("reports other node errors as RPC_TRANSPORT with the method and code", async () => {
    const { rpc } = scriptedRpc({
      eth_call: () => {
        throw Object.assign(new Error("header not found"), { code: -32000 });
      },
    });
    const err = await RpcChainReader.over(rpc, CONFIG)
      .isKnownRoot(ROOT)
      .catch((e: unknown) => e);
    const e = expectCode(err, "RPC_TRANSPORT");
    expect(e.context).toMatchObject({ method: "eth_call", rpcCode: "-32000" });
  });

  it("times out a hung transport", async () => {
    const config = { ...CONFIG, rpcTimeoutMs: 20 };
    const reader = RpcChainReader.over(
      () => new Promise(() => undefined),
      config,
    );
    expectCode(await reader.latest().catch((e: unknown) => e), "RPC_TRANSPORT");
  });

  it("rejects a root that is not a field element", async () => {
    const { rpc } = scriptedRpc({
      eth_call: poolCallHandler((name) =>
        name === "getNextLeafIndex" ? [3n] : [`0x${"ff".repeat(32)}`],
      ),
    });
    const head = { number: 4, hash: hash32(4), timestamp: 1n };
    const err = await RpcChainReader.over(rpc, CONFIG)
      .treeState(head)
      .catch((e: unknown) => e);
    expectCode(err, "RPC_RESPONSE_INVALID");
  });

  it("resolves the confirmed head by depth or by tag", async () => {
    const { rpc, calls } = scriptedRpc({
      eth_getBlockByNumber: ([tag]) =>
        blockJson(
          tag === "latest" ? 100 : tag === "finalized" ? 64 : Number(tag),
        ),
    });
    const reader = RpcChainReader.over(rpc, CONFIG);
    expect(
      (await reader.confirmedHead({ kind: "depth", blocks: 0 })).number,
    ).toBe(100);
    expect(
      (await reader.confirmedHead({ kind: "depth", blocks: 12 })).number,
    ).toBe(88);
    expect(
      (await reader.confirmedHead({ kind: "depth", blocks: 500 })).number,
    ).toBe(0);
    expect(
      (await reader.confirmedHead({ kind: "tag", tag: "finalized" })).number,
    ).toBe(64);
    expect(calls.map((c) => c.params[0])).toEqual([
      "latest",
      "latest",
      "0x58",
      "latest",
      "0x0",
      "finalized",
    ]);
  });

  it("reads isKnownRoot and the compliance key at latest or at a pinned block", async () => {
    const { rpc, calls } = scriptedRpc({ eth_call: poolAt(9n, ROOT) });
    const reader = RpcChainReader.over(rpc, CONFIG);
    const pinned = { number: 5, hash: hash32(5), timestamp: 1n };
    expect(await reader.isKnownRoot(ROOT)).toBe(true);
    const key = await reader.complianceKey(pinned);
    expect(key).toEqual({ point: [7n, 8n], version: 2 });
    expect(calls[0]!.params[1]).toBe("latest");
    expect(calls[1]!.params[1]).toEqual({
      blockHash: pinned.hash,
      requireCanonical: true,
    });
  });

  it("serves the wallets ChainView port without an adapter", async () => {
    const { rpc } = scriptedRpc({ eth_call: poolAt(9n, ROOT) });
    const view: ChainView = RpcChainReader.over(rpc, CONFIG);
    expect(await view.nextLeafIndex()).toBe(9);
  });
});
