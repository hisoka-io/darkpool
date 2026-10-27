import { parseDeploymentRef } from "@hisoka/howl-protocol";
import { DARK_POOL_INTERFACE } from "../../abi.js";
import type { JsonRpc } from "../../chain/rpc.js";
import {
  validateChainConfig,
  type ChainConfig,
  type ConfirmationPolicy,
} from "../../config.js";
import { hash32 } from "./rpc.js";

export const POOL = "0x6dab00000000000000000000000000000000beef";

export function configFor(
  deploymentBlock: number,
  spendableNotes: ConfirmationPolicy = { kind: "depth", blocks: 0 },
  logRangeBlocks = 7,
): ChainConfig {
  return validateChainConfig({
    deployment: parseDeploymentRef({
      domain_version: 1,
      chain_id: "31337",
      dark_pool: POOL,
      deployment_block: String(deploymentBlock),
    }),
    confirmations: {
      spendableNotes,
      counterAdvance: { kind: "depth", blocks: 0 },
      pssWrite: { kind: "depth", blocks: 0 },
    },
    logRangeBlocks,
    maxReorgBlocks: 16,
    maxOccurrencesPerTag: 100,
    rpcTimeoutMs: 5_000,
  });
}

interface FakeBlock {
  number: number;
  hash: string;
  timestamp: number;
}

interface FakeLog {
  readonly blockNumber: number;
  readonly logIndex: number;
  readonly topics: readonly string[];
  readonly data: string;
  readonly removed: boolean;
}

export interface ComplianceState {
  readonly x: bigint;
  readonly y: bigint;
  readonly version: number;
}

/**
 * An in-memory chain behind a real JSON-RPC shape: blocks with hashes, pool logs and a compliance-key state
 * per block. `reorgFrom` gives every block from a height a new hash and drops their logs, as a real reorg does.
 */
export class FakeChain {
  readonly blocks: FakeBlock[] = [];
  readonly logs: FakeLog[] = [];
  readonly calls: { method: string; params: readonly unknown[] }[] = [];
  private fork = 0;
  compliance: (block: number) => ComplianceState = () => ({
    x: 1n,
    y: 2n,
    version: 1,
  });
  /** Runs before each `latest` answer; tests use it to reorg in the middle of a read. */
  onLatest: (() => void) | null = null;
  /** Answers pool calls other than `complianceKey`, at the block the call was pinned to. */
  poolCall:
    | ((
        name: string,
        args: readonly unknown[],
        block: number,
      ) => readonly unknown[])
    | null = null;
  archive = true;

  constructor(
    height: number,
    readonly genesisTime = 1_000_000,
  ) {
    for (let n = 0; n <= height; n++) this.blocks.push(this.block(n));
  }

  private block(n: number): FakeBlock {
    return {
      number: n,
      hash: hash32(0x100000 * (this.fork + 1) + n),
      timestamp: this.genesisTime + 12 * n,
    };
  }

  get head(): number {
    return this.blocks.length - 1;
  }

  mine(count = 1): void {
    for (let i = 0; i < count; i++)
      this.blocks.push(this.block(this.blocks.length));
  }

  reorgFrom(height: number): void {
    this.fork += 1;
    for (let n = height; n < this.blocks.length; n++)
      this.blocks[n] = this.block(n);
    for (let i = this.logs.length - 1; i >= 0; i--) {
      if (this.logs[i]!.blockNumber >= height) this.logs.splice(i, 1);
    }
  }

  emit(
    blockNumber: number,
    event: string,
    values: readonly unknown[],
    removed = false,
  ): void {
    const fragment = DARK_POOL_INTERFACE.getEvent(event);
    if (fragment === null) throw new Error(`no event ${event}`);
    const encoded = DARK_POOL_INTERFACE.encodeEventLog(fragment, [...values]);
    const logIndex = this.logs.filter(
      (l) => l.blockNumber === blockNumber,
    ).length;
    this.logs.push({
      blockNumber,
      logIndex,
      topics: encoded.topics,
      data: encoded.data,
      removed,
    });
  }

  private blockJson(b: FakeBlock): Record<string, string> {
    return {
      number: `0x${b.number.toString(16)}`,
      hash: b.hash,
      timestamp: `0x${b.timestamp.toString(16)}`,
    };
  }

  readonly rpc: JsonRpc = async (method, params) => {
    this.calls.push({ method, params });
    if (method === "eth_getBlockByNumber") {
      const tag = params[0];
      if (tag === "latest") {
        this.onLatest?.();
        return this.blockJson(this.blocks[this.head]!);
      }
      const n = Number(tag);
      const b = this.blocks[n];
      return b === undefined ? null : this.blockJson(b);
    }
    if (method === "eth_getLogs") {
      const filter = params[0] as {
        address: string;
        topics: string[][];
        fromBlock: string;
        toBlock: string;
      };
      const from = Number(filter.fromBlock);
      const to = Number(filter.toBlock);
      const wanted = new Set(filter.topics[0]);
      return this.logs
        .filter(
          (l) =>
            l.blockNumber >= from &&
            l.blockNumber <= to &&
            wanted.has(l.topics[0]!),
        )
        .reverse()
        .map((l) => ({
          address: POOL,
          topics: l.topics,
          data: l.data,
          blockNumber: `0x${l.blockNumber.toString(16)}`,
          blockHash: this.blocks[l.blockNumber]!.hash,
          logIndex: `0x${l.logIndex.toString(16)}`,
          transactionHash: hash32(0xbeef00 + l.blockNumber * 16 + l.logIndex),
          removed: l.removed,
        }));
    }
    if (method === "eth_call") {
      const tx = params[0] as { data: string };
      const at = params[1];
      let number = this.head;
      if (typeof at === "object" && at !== null && "blockHash" in at) {
        const found = this.blocks.find(
          (b) => b.hash === (at as { blockHash: string }).blockHash,
        );
        if (found === undefined) {
          throw Object.assign(new Error("block not canonical"), {
            code: -32000,
          });
        }
        number = found.number;
        if (!this.archive && number < this.head - 2) {
          throw Object.assign(new Error("missing trie node"), { code: -32000 });
        }
      }
      const call = DARK_POOL_INTERFACE.parseTransaction({ data: tx.data });
      if (call !== null && call.name !== "complianceKey" && this.poolCall) {
        return DARK_POOL_INTERFACE.encodeFunctionResult(call.name, [
          ...this.poolCall(call.name, [...call.args], number),
        ]);
      }
      if (call?.name !== "complianceKey")
        throw new Error(`unscripted call ${call?.name}`);
      const s = this.compliance(number);
      return DARK_POOL_INTERFACE.encodeFunctionResult("complianceKey", [
        s.x,
        s.y,
        BigInt(s.version),
      ]);
    }
    throw Object.assign(new Error(`unscripted ${method}`), { code: -32601 });
  };
}
