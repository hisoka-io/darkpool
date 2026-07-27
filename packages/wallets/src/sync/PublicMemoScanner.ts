import { Contract, ContractEventName, EventLog, Log } from "ethers";
import { Fr } from "@aztec/foundation/fields";
import { Point } from "@zk-kit/baby-jubjub";
import { addressToFr, toFr } from "../crypto/fields.js";
import { calculatePublicMemoId } from "../crypto/index.js";
import { derivePublicIncomingKey, publicKey } from "../note/keys.js";
import { DiscoveredPublicMemo } from "./types.js";

const DEFAULT_PUBLIC_INDEX_WINDOW = 20;
// Recognition re-derives one key per index, so an unbounded window lets a frontier match spin derivation.
const MAX_PUBLIC_INDEX = 1_000_000n;
const TWO_POW_64 = 1n << 64n;
const TWO_POW_128 = 1n << 128n;

export class PublicMemoScanError extends Error {
  constructor(message: string) {
    super(`PublicMemoScanner: ${message}`);
  }
}

interface PublicOwnerKey {
  index: bigint;
  scalar: Fr;
  pub: Point<bigint>;
}

interface EmittedPublicMemo {
  memoId: Fr;
  asset: string;
  assetId: Fr;
  value: bigint;
  timelock: bigint;
  salt: Fr;
  blockNumber: number;
  logIndex: number;
  txHash: string;
}

/**
 * Discovers `DarkPool.publicTransfer` escrows payable to this wallet.
 *
 * `NewPublicMemo` omits the owner point, so a memo is recognised by recomputing its id from a candidate
 * owner point plus the emitted fields. Nothing is decrypted and no state accumulates across scans, so a
 * reorged-away memo simply stops being reported (unlike ScanEngine, whose Merkle inserts are permanent).
 */
export class PublicMemoScanner {
  constructor(
    private readonly contract: Contract,
    private readonly viewKey: Fr,
    private readonly indexWindow: number = DEFAULT_PUBLIC_INDEX_WINDOW,
  ) {
    if (
      !Number.isInteger(indexWindow) ||
      indexWindow <= 0 ||
      BigInt(indexWindow) > MAX_PUBLIC_INDEX
    ) {
      throw new PublicMemoScanError(
        `indexWindow must be an integer in [1, ${MAX_PUBLIC_INDEX}], got ${indexWindow}`,
      );
    }
  }

  /** @param nowSeconds unix seconds used for timelock maturity; defaults to the latest block timestamp. */
  public async scan(
    fromBlock: number = 0,
    nowSeconds?: bigint,
  ): Promise<DiscoveredPublicMemo[]> {
    const memoFilter = this.eventFilter("NewPublicMemo");
    const spentFilter = this.eventFilter("PublicMemoSpent");
    const now = nowSeconds ?? (await this.chainTime());

    const memoLogs = await this.contract.queryFilter(memoFilter, fromBlock);
    const spentLogs = await this.contract.queryFilter(spentFilter, fromBlock);

    const spent = this.spentMemoIds(spentLogs);
    let pending: EmittedPublicMemo[] = [];
    for (const log of memoLogs) {
      const memo = this.parseMemoLog(log);
      if (memo) pending.push(memo);
    }

    const found: DiscoveredPublicMemo[] = [];
    let derived = 0n;
    let target = BigInt(this.indexWindow);

    while (derived < target) {
      const keys = await this.deriveOwnerKeys(derived, target);
      derived = target;

      const matched = new Set<EmittedPublicMemo>();
      let highestMatch = -1n;
      for (const memo of pending) {
        const key = await this.recognize(memo, keys);
        if (!key) continue;
        matched.add(memo);
        found.push(this.toDiscovered(memo, key, spent, now));
        if (key.index > highestMatch) highestMatch = key.index;
      }
      if (matched.size > 0) pending = pending.filter((m) => !matched.has(m));

      // Gap limit, as KeyRepository does for private keys: a match near the frontier extends the window.
      if (highestMatch >= 0n) {
        const extended = highestMatch + 1n + BigInt(this.indexWindow);
        if (extended > target) {
          target = extended > MAX_PUBLIC_INDEX ? MAX_PUBLIC_INDEX : extended;
        }
      }
    }

    return found.sort((a, b) => {
      if (a.blockNumber !== b.blockNumber) return a.blockNumber - b.blockNumber;
      return a.logIndex - b.logIndex;
    });
  }

  private async recognize(
    memo: EmittedPublicMemo,
    keys: PublicOwnerKey[],
  ): Promise<PublicOwnerKey | null> {
    for (const key of keys) {
      const candidate = await calculatePublicMemoId(
        new Fr(memo.value),
        memo.assetId,
        new Fr(memo.timelock),
        new Fr(key.pub[0]),
        new Fr(key.pub[1]),
        memo.salt,
      );
      if (candidate.equals(memo.memoId)) return key;
    }
    return null;
  }

  // Every candidate is scalar*Base8, hence already in the prime-order subgroup; the on-chain owner
  // validation exists for points the SDK did not derive.
  private async deriveOwnerKeys(
    from: bigint,
    to: bigint,
  ): Promise<PublicOwnerKey[]> {
    const keys: PublicOwnerKey[] = [];
    for (let index = from; index < to; index++) {
      const scalar = await derivePublicIncomingKey(this.viewKey, index);
      keys.push({ index, scalar, pub: publicKey(scalar) });
    }
    return keys;
  }

  private toDiscovered(
    memo: EmittedPublicMemo,
    key: PublicOwnerKey,
    spent: Set<string>,
    now: bigint,
  ): DiscoveredPublicMemo {
    // Mirrors public_claim: (timelock == 0) | (current_timestamp >= timelock).
    const matured = memo.timelock === 0n || now >= memo.timelock;
    const isSpent = spent.has(memo.memoId.toString());
    return {
      memoId: memo.memoId,
      ownerIndex: key.index,
      ownerPub: key.pub,
      recipientSk: key.scalar,
      asset: memo.asset,
      assetId: memo.assetId,
      value: memo.value,
      timelock: memo.timelock,
      salt: memo.salt,
      spent: isSpent,
      matured,
      claimable: !isSpent && matured,
      blockNumber: memo.blockNumber,
      logIndex: memo.logIndex,
      txHash: memo.txHash,
    };
  }

  private parseMemoLog(log: EventLog | Log): EmittedPublicMemo | null {
    if (!("args" in log)) return null;
    const event = log as EventLog;
    try {
      const value = BigInt(event.args["value"]);
      if (value === 0n || value >= TWO_POW_128) {
        throw new Error(
          `value ${value} is outside the (0, 2^128) range publicTransfer enforces`,
        );
      }
      const timelock = BigInt(event.args["timelock"]);
      if (timelock >= TWO_POW_64) {
        throw new Error(
          `timelock ${timelock} exceeds the u64 bound public_claim compares against`,
        );
      }
      const asset = String(event.args["asset"]);
      return {
        memoId: toFr(event.args["memoId"] as string),
        asset,
        assetId: addressToFr(asset),
        value,
        timelock,
        salt: toFr(event.args["salt"] as string | bigint),
        blockNumber: log.blockNumber,
        logIndex: log.index,
        txHash: log.transactionHash,
      };
    } catch (err) {
      this.warn("NewPublicMemo", log, err);
      return null;
    }
  }

  private spentMemoIds(logs: Array<EventLog | Log>): Set<string> {
    const spent = new Set<string>();
    for (const log of logs) {
      if (!("args" in log)) continue;
      const event = log as EventLog;
      try {
        spent.add(toFr(event.args["memoId"] as string).toString());
      } catch (err) {
        this.warn("PublicMemoSpent", log, err);
      }
    }
    return spent;
  }

  private eventFilter(
    name: "NewPublicMemo" | "PublicMemoSpent",
  ): ContractEventName {
    const factory = this.contract.filters[name];
    if (typeof factory !== "function") {
      throw new PublicMemoScanError(
        `the contract ABI declares no ${name} event; construct the scanner with a DarkPool instance`,
      );
    }
    return factory();
  }

  private async chainTime(): Promise<bigint> {
    const provider = this.contract.runner?.provider;
    if (!provider) {
      throw new PublicMemoScanError(
        "cannot read chain time for the timelock check: the contract has no provider; pass nowSeconds to scan()",
      );
    }
    const block = await provider.getBlock("latest");
    if (!block) {
      throw new PublicMemoScanError(
        "cannot read chain time for the timelock check: the provider returned no latest block; pass nowSeconds to scan()",
      );
    }
    return BigInt(block.timestamp);
  }

  private warn(where: string, log: EventLog | Log, err: unknown): void {
    const msg = err instanceof Error ? err.message : "unknown error";
    console.warn(
      `[PublicMemoScanner] ${where} skipped (block=${log.blockNumber}, tx=${log.transactionHash}): ${msg}`,
    );
  }
}
