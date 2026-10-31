import { Fr } from "@aztec/foundation/fields";
import type { Point } from "@zk-kit/baby-jubjub";
import {
  addressToFr,
  derivePublicIncomingKey,
  publicKey,
  publicMemoId,
} from "@hisoka/wallets";
import { DARK_POOL_INTERFACE, EVENT_TOPICS } from "../abi.js";
import type { ChainReader } from "../chain/chainReader.js";
import {
  readAtStableHead,
  type LogSource,
  type RawLog,
} from "../chain/logs.js";
import { invalidResponse, type BlockRef } from "../chain/rpc.js";
import {
  deploymentBlock,
  MAX_PUBLIC_MEMO_INDEX,
  PUBLIC_MEMO_INDEX_WINDOW,
  type ChainConfig,
} from "../config.js";
import { describeCause } from "../errors.js";

/** `publicTransfer` bounds: value is the in-circuit u128, timelock is compared as u64. */
const TWO_POW_128 = 1n << 128n;
const TWO_POW_64 = 1n << 64n;

export interface PublicMemosDeps {
  readonly config: ChainConfig;
  readonly chain: Pick<
    ChainReader,
    "latest" | "blockByNumber" | "confirmedHead"
  >;
  readonly logs: LogSource;
}

/** A `publicTransfer` escrow payable to one of this wallet's public receiving indices. */
export interface RuntimePublicMemo {
  readonly memoId: Fr;
  readonly ownerIndex: bigint;
  readonly ownerPub: Point<bigint>;
  readonly asset: string;
  readonly assetId: Fr;
  readonly value: bigint;
  readonly timelock: bigint;
  readonly salt: Fr;
  readonly spent: boolean;
  /** `timelock == 0` or chain time has reached it, as `public_claim` asserts. */
  readonly matured: boolean;
  /** Unspent, matured, and posted at or below the confirmed head for spendable notes. */
  readonly claimable: boolean;
  readonly block: { readonly number: number; readonly hash: string };
  readonly logIndex: number;
  readonly transactionHash: string;
}

export interface PublicMemosRead {
  readonly memos: readonly RuntimePublicMemo[];
  /** Every log up to this block was read; its timestamp is the chain time used for maturity. */
  readonly head: BlockRef;
  readonly confirmedHead: number;
}

interface PostedMemo {
  readonly log: RawLog;
  readonly memoId: Fr;
  readonly asset: string;
  readonly value: bigint;
  readonly timelock: bigint;
  readonly salt: Fr;
}

interface OwnerKey {
  readonly index: bigint;
  readonly pub: Point<bigint>;
}

/**
 * Public memos owned by `viewKey`, recomputed from the pool's logs on every call (a reorged-away memo simply
 * disappears). `NewPublicMemo` omits the owner point, so a memo is recognised by recomputing its id under each
 * public receiving key in a gap-limited window. Chain time is the head block's timestamp, never the device clock,
 * and the same value must be passed to `buildPublicClaim`.
 */
export async function readPublicMemos(
  deps: PublicMemosDeps,
  viewKey: Fr,
): Promise<PublicMemosRead> {
  const firstBlock = deploymentBlock(deps.config);
  const { head, value } = await readAtStableHead(
    deps.chain,
    async (_head, logsTo) => {
      const logs = await logsTo(
        [EVENT_TOPICS.NewPublicMemo, EVENT_TOPICS.PublicMemoSpent],
        firstBlock,
      );
      const posted: PostedMemo[] = [];
      const spent = new Set<string>();
      for (const log of logs) {
        if (log.topics[0] === EVENT_TOPICS.NewPublicMemo)
          posted.push(decodeMemo(log));
        else spent.add(decodeSpent(log).toString());
      }
      return { posted, spent };
    },
    deps.logs,
  );
  const confirmed = Math.min(
    head.number,
    (await deps.chain.confirmedHead(deps.config.confirmations.spendableNotes))
      .number,
  );

  const memos: RuntimePublicMemo[] = [];
  let pending = value.posted;
  let derived = 0n;
  let target = BigInt(PUBLIC_MEMO_INDEX_WINDOW);
  while (derived < target && pending.length > 0) {
    const keys = await ownerKeys(viewKey, derived, target);
    derived = target;
    let highest = -1n;
    const unmatched: PostedMemo[] = [];
    for (const memo of pending) {
      const key = await recognise(memo, keys);
      if (key === null) {
        unmatched.push(memo);
        continue;
      }
      if (key.index > highest) highest = key.index;
      const isSpent = value.spent.has(memo.memoId.toString());
      const matured = memo.timelock === 0n || head.timestamp >= memo.timelock;
      memos.push(
        Object.freeze({
          memoId: memo.memoId,
          ownerIndex: key.index,
          ownerPub: key.pub,
          asset: memo.asset,
          assetId: addressToFr(memo.asset),
          value: memo.value,
          timelock: memo.timelock,
          salt: memo.salt,
          spent: isSpent,
          matured,
          claimable: !isSpent && matured && memo.log.blockNumber <= confirmed,
          block: { number: memo.log.blockNumber, hash: memo.log.blockHash },
          logIndex: memo.log.logIndex,
          transactionHash: memo.log.transactionHash,
        }),
      );
    }
    pending = unmatched;
    if (highest >= 0n) {
      const extended = highest + 1n + BigInt(PUBLIC_MEMO_INDEX_WINDOW);
      const cap = BigInt(MAX_PUBLIC_MEMO_INDEX);
      if (extended > target) target = extended > cap ? cap : extended;
    }
  }

  memos.sort(
    (a, b) => a.block.number - b.block.number || a.logIndex - b.logIndex,
  );
  return { memos, head, confirmedHead: confirmed };
}

async function ownerKeys(
  viewKey: Fr,
  from: bigint,
  to: bigint,
): Promise<OwnerKey[]> {
  const keys: OwnerKey[] = [];
  for (let index = from; index < to; index++) {
    keys.push({
      index,
      pub: publicKey(await derivePublicIncomingKey(viewKey, index)),
    });
  }
  return keys;
}

async function recognise(
  memo: PostedMemo,
  keys: readonly OwnerKey[],
): Promise<OwnerKey | null> {
  const terms = {
    assetId: addressToFr(memo.asset),
    value: memo.value,
    timelock: memo.timelock,
    salt: memo.salt,
  };
  for (const key of keys) {
    if ((await publicMemoId(terms, key.pub)).equals(memo.memoId)) return key;
  }
  return null;
}

function parsed(
  log: RawLog,
  name: "NewPublicMemo" | "PublicMemoSpent",
): readonly unknown[] {
  try {
    const event = DARK_POOL_INTERFACE.parseLog({
      topics: [...log.topics],
      data: log.data,
    });
    if (event === null || event.name !== name) throw new Error(`not ${name}`);
    return [...event.args];
  } catch (cause) {
    return invalidResponse(
      `eth_getLogs ${name}`,
      log,
      `does not decode: ${describeCause(cause)}`,
    );
  }
}

function field(value: unknown, log: RawLog, what: string): Fr {
  try {
    if (typeof value !== "string" && typeof value !== "bigint")
      throw new Error("not a word");
    return new Fr(BigInt(value));
  } catch (cause) {
    return invalidResponse(
      "eth_getLogs",
      log,
      `${what} is not a field element: ${describeCause(cause)}`,
    );
  }
}

/** The pool reverts on any value the checks below reject, so a log failing them did not come from it. */
function decodeMemo(log: RawLog): PostedMemo {
  const [memoId, asset, value, timelock, salt] = parsed(log, "NewPublicMemo");
  if (
    typeof asset !== "string" ||
    typeof value !== "bigint" ||
    typeof timelock !== "bigint" ||
    value === 0n ||
    value >= TWO_POW_128 ||
    timelock >= TWO_POW_64
  ) {
    return invalidResponse(
      "eth_getLogs NewPublicMemo",
      log,
      "is outside the publicTransfer bounds",
    );
  }
  return {
    log,
    memoId: field(memoId, log, "memoId"),
    asset,
    value,
    timelock,
    salt: field(salt, log, "salt"),
  };
}

function decodeSpent(log: RawLog): Fr {
  const [memoId] = parsed(log, "PublicMemoSpent");
  return field(memoId, log, "memoId");
}
