import { Fr } from "@aztec/foundation/fields";
import type { Point } from "@zk-kit/baby-jubjub";
import { DARK_POOL_INTERFACE } from "../abi.js";
import type { ChainConfig, ConfirmationPolicy } from "../config.js";
import { describeCause } from "../errors.js";
import {
  atBlock,
  invalidResponse,
  RpcClient,
  type BlockRef,
  type BlockHashParam,
  type JsonRpc,
} from "./rpc.js";

export interface TreeState {
  /** `getNextLeafIndex()`. */
  readonly leafCount: number;
  /** `getCurrentRoot()`. */
  readonly root: Fr;
  /** Both reads were made at exactly this block. */
  readonly block: BlockRef;
}

export interface ComplianceKeyAt {
  readonly point: Point<bigint>;
  readonly version: number;
}

/** Pool reads. Structurally also the wallets `ChainView` port (reads at `latest` when no block is given). */
export interface ChainReader {
  latest(): Promise<BlockRef>;
  confirmedHead(policy: ConfirmationPolicy): Promise<BlockRef>;
  blockByNumber(n: number): Promise<BlockRef>;
  treeState(at: BlockRef): Promise<TreeState>;
  isKnownRoot(root: Fr, at?: BlockRef | "latest"): Promise<boolean>;
  complianceKey(at?: BlockRef | "latest"): Promise<ComplianceKeyAt>;
  nextLeafIndex(): Promise<number>;
}

type CallName =
  | "getNextLeafIndex"
  | "getCurrentRoot"
  | "isKnownRoot"
  | "complianceKey";

export class RpcChainReader implements ChainReader {
  private readonly pool: string;

  constructor(
    private readonly client: RpcClient,
    config: ChainConfig,
  ) {
    this.pool = config.deployment.dark_pool;
  }

  static over(rpc: JsonRpc, config: ChainConfig): RpcChainReader {
    return new RpcChainReader(new RpcClient(rpc, config.rpcTimeoutMs), config);
  }

  latest(): Promise<BlockRef> {
    return this.client.block("latest");
  }

  async confirmedHead(policy: ConfirmationPolicy): Promise<BlockRef> {
    if (policy.kind === "tag") return this.client.block(policy.tag);
    const latest = await this.latest();
    if (policy.blocks === 0) return latest;
    return this.client.block(Math.max(0, latest.number - policy.blocks));
  }

  blockByNumber(n: number): Promise<BlockRef> {
    return this.client.block(n);
  }

  /**
   * `(leafCount, root)` of one block. Both calls carry the same EIP-1898 block hash, so they read one state of
   * one fork whatever the node does between them; a node that refuses the hash form fails `RPC_CAPABILITY`.
   */
  async treeState(at: BlockRef): Promise<TreeState> {
    const block = atBlock(at);
    const [count, root] = await Promise.all([
      this.read("getNextLeafIndex", [], block),
      this.read("getCurrentRoot", [], block),
    ]);
    return Object.freeze({
      leafCount: safeNumber(count[0], "getNextLeafIndex"),
      root: field(root[0], "getCurrentRoot"),
      block: at,
    });
  }

  async isKnownRoot(
    root: Fr,
    at: BlockRef | "latest" = "latest",
  ): Promise<boolean> {
    const [known] = await this.read(
      "isKnownRoot",
      [root.toString()],
      at === "latest" ? "latest" : atBlock(at),
    );
    if (typeof known !== "boolean") {
      invalidResponse("isKnownRoot", known, "is not a bool");
    }
    return known;
  }

  async complianceKey(
    at: BlockRef | "latest" = "latest",
  ): Promise<ComplianceKeyAt> {
    const [x, y, version] = await this.read(
      "complianceKey",
      [],
      at === "latest" ? "latest" : atBlock(at),
    );
    return Object.freeze({
      point: Object.freeze([
        bigintOf(x, "complianceKey.x"),
        bigintOf(y, "complianceKey.y"),
      ]) as Point<bigint>,
      version: safeNumber(version, "complianceKey.version"),
    });
  }

  async nextLeafIndex(): Promise<number> {
    const [count] = await this.read("getNextLeafIndex", [], "latest");
    return safeNumber(count, "getNextLeafIndex");
  }

  private async read(
    name: CallName,
    args: readonly unknown[],
    block: BlockHashParam | "latest",
  ): Promise<readonly unknown[]> {
    const data = DARK_POOL_INTERFACE.encodeFunctionData(name, args);
    const raw = await this.client.call(this.pool, data, block);
    try {
      return [...DARK_POOL_INTERFACE.decodeFunctionResult(name, raw)];
    } catch (cause) {
      return invalidResponse(
        `eth_call ${name}`,
        raw,
        `does not decode: ${describeCause(cause)}`,
      );
    }
  }
}

function bigintOf(value: unknown, what: string): bigint {
  if (typeof value !== "bigint") invalidResponse(what, value, "is not a uint");
  return value;
}

function safeNumber(value: unknown, what: string): number {
  const n = bigintOf(value, what);
  if (n > BigInt(Number.MAX_SAFE_INTEGER)) {
    invalidResponse(what, n.toString(), "exceeds the safe integer range");
  }
  return Number(n);
}

function field(value: unknown, what: string): Fr {
  if (typeof value !== "string") invalidResponse(what, value, "is not bytes32");
  try {
    return new Fr(BigInt(value));
  } catch (cause) {
    return invalidResponse(
      what,
      value,
      `is not a BN254 field element: ${describeCause(cause)}`,
    );
  }
}
