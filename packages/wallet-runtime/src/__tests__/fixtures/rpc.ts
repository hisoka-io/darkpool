import { DARK_POOL_INTERFACE } from "../../abi.js";
import type { JsonRpc } from "../../chain/rpc.js";

export interface RecordedCall {
  readonly method: string;
  readonly params: readonly unknown[];
}

export type Handler = (params: readonly unknown[]) => unknown;

/** A JSON-RPC transport answering from per-method handlers and recording every request in order. */
export function scriptedRpc(handlers: Readonly<Record<string, Handler>>): {
  readonly rpc: JsonRpc;
  readonly calls: RecordedCall[];
} {
  const calls: RecordedCall[] = [];
  const rpc: JsonRpc = async (method, params) => {
    calls.push({ method, params });
    const handler = handlers[method];
    if (handler === undefined) {
      throw Object.assign(new Error(`method ${method} not scripted`), {
        code: -32601,
      });
    }
    return handler(params);
  };
  return { rpc, calls };
}

export function hash32(n: number): string {
  return `0x${n.toString(16).padStart(64, "0")}`;
}

export function blockJson(
  number: number,
  hash = hash32(number + 0x1000),
  timestamp = 1_700_000_000 + number,
): Record<string, string> {
  return {
    number: `0x${number.toString(16)}`,
    hash,
    timestamp: `0x${timestamp.toString(16)}`,
  };
}

type CallName =
  | "getNextLeafIndex"
  | "getCurrentRoot"
  | "isKnownRoot"
  | "complianceKey";

/** Decodes an eth_call to the pool and answers it from `answer`, which sees the function name, args and block. */
export function poolCallHandler(
  answer: (
    name: CallName,
    args: readonly unknown[],
    block: unknown,
  ) => readonly unknown[],
): Handler {
  return (params) => {
    const tx = params[0] as { readonly data: string };
    const parsed = DARK_POOL_INTERFACE.parseTransaction({ data: tx.data });
    if (parsed === null) throw new Error("unknown pool call");
    const name = parsed.name as CallName;
    return DARK_POOL_INTERFACE.encodeFunctionResult(name, [
      ...answer(name, [...parsed.args], params[1]),
    ]);
  };
}
