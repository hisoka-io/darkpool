import { WalletRuntimeError, describeCause } from "../errors.js";

/**
 * One JSON-RPC request. The same shape as a Nox-routed send, so one transport can serve a direct node or a
 * mixnet route. Implementations reject with the node's error object (carrying its numeric `code`) on an
 * RPC error.
 */
export type JsonRpc = (
  method: string,
  params: readonly unknown[],
) => Promise<unknown>;

/** JSON-RPC 2.0 "invalid params": the node does not accept a parameter shape, here the EIP-1898 block object. */
const JSON_RPC_INVALID_PARAMS = -32602;

export interface BlockRef {
  readonly number: number;
  readonly hash: string;
  readonly timestamp: bigint;
}

/** EIP-1898 block parameter: pins a read to one block of one fork, so two reads at it see one state. */
export interface BlockHashParam {
  readonly blockHash: string;
  readonly requireCanonical: true;
}

export type BlockTag = "latest" | "safe" | "finalized";

export function atBlock(block: BlockRef): BlockHashParam {
  return { blockHash: block.hash, requireCanonical: true };
}

function errorCode(cause: unknown): number | undefined {
  if (typeof cause !== "object" || cause === null || !("code" in cause)) {
    return undefined;
  }
  const code = (cause as { readonly code: unknown }).code;
  return typeof code === "number" ? code : undefined;
}

export class RpcClient {
  constructor(
    private readonly rpc: JsonRpc,
    private readonly timeoutMs: number,
  ) {}

  async request(method: string, params: readonly unknown[]): Promise<unknown> {
    const started = Date.now();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(
        () =>
          reject(
            new WalletRuntimeError(
              "RPC_TRANSPORT",
              `${method} timed out after ${this.timeoutMs}ms`,
              { method, elapsedMs: String(Date.now() - started) },
            ),
          ),
        this.timeoutMs,
      );
    });
    try {
      return await Promise.race([this.rpc(method, params), timeout]);
    } catch (cause) {
      if (cause instanceof WalletRuntimeError) throw cause;
      const code = errorCode(cause);
      const usesBlockHash = params.some(
        (p) => typeof p === "object" && p !== null && "blockHash" in p,
      );
      if (usesBlockHash && code === JSON_RPC_INVALID_PARAMS) {
        throw new WalletRuntimeError(
          "RPC_CAPABILITY",
          `${method} refused the EIP-1898 block-hash parameter; a block-number read could straddle a reorg, so there is no fallback`,
          { method },
          cause,
        );
      }
      throw new WalletRuntimeError(
        "RPC_TRANSPORT",
        `${method} failed after ${Date.now() - started}ms: ${describeCause(cause)}`,
        {
          method,
          elapsedMs: String(Date.now() - started),
          ...(code === undefined ? {} : { rpcCode: String(code) }),
        },
        cause,
      );
    } finally {
      clearTimeout(timer);
    }
  }

  async block(tag: BlockTag | number): Promise<BlockRef> {
    const param = typeof tag === "number" ? quantity(tag) : tag;
    const raw = await this.request("eth_getBlockByNumber", [param, false]);
    return parseBlock(raw, `eth_getBlockByNumber(${String(tag)})`);
  }

  async chainId(): Promise<bigint> {
    return parseQuantity(await this.request("eth_chainId", []), "eth_chainId");
  }

  async call(
    to: string,
    data: string,
    block: BlockHashParam | BlockTag,
  ): Promise<string> {
    const raw = await this.request("eth_call", [{ to, data }, block]);
    if (typeof raw !== "string" || !/^0x([0-9a-fA-F]{2})*$/.test(raw)) {
      invalidResponse("eth_call", raw, "is not hex data");
    }
    return raw;
  }

  async code(
    address: string,
    block: BlockHashParam | BlockTag,
  ): Promise<string> {
    const raw = await this.request("eth_getCode", [address, block]);
    if (typeof raw !== "string" || !/^0x([0-9a-fA-F]{2})*$/.test(raw)) {
      invalidResponse("eth_getCode", raw, "is not hex data");
    }
    return raw;
  }
}

export function quantity(value: number | bigint): string {
  return `0x${value.toString(16)}`;
}

export function invalidResponse(
  method: string,
  value: unknown,
  why: string,
): never {
  let shown: string;
  try {
    shown = JSON.stringify(value) ?? String(value);
  } catch {
    shown = String(value);
  }
  throw new WalletRuntimeError(
    "RPC_RESPONSE_INVALID",
    `${method} response ${why}: ${shown.slice(0, 200)}`,
    { method },
  );
}

export function parseQuantity(value: unknown, method: string): bigint {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]+$/.test(value)) {
    invalidResponse(method, value, "is not a hex quantity");
  }
  return BigInt(value);
}

export function parseSafeNumber(value: unknown, method: string): number {
  const n = parseQuantity(value, method);
  if (n > BigInt(Number.MAX_SAFE_INTEGER)) {
    invalidResponse(method, value, "exceeds the safe integer range");
  }
  return Number(n);
}

export function parseHash(value: unknown, method: string): string {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(value)) {
    invalidResponse(method, value, "is not a 32-byte hash");
  }
  return value.toLowerCase();
}

function parseBlock(raw: unknown, method: string): BlockRef {
  if (typeof raw !== "object" || raw === null) {
    invalidResponse(method, raw, "is not a block (the node has no such block)");
  }
  const block = raw as Record<string, unknown>;
  return Object.freeze({
    number: parseSafeNumber(block.number, `${method}.number`),
    hash: parseHash(block.hash, `${method}.hash`),
    timestamp: parseQuantity(block.timestamp, `${method}.timestamp`),
  });
}
