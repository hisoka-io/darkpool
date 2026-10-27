import { Fr } from "@aztec/foundation/fields";
import { DARK_POOL_INTERFACE, EVENT_TOPICS } from "../abi.js";
import type { ChainReader } from "../chain/chainReader.js";
import { invalidResponse, type BlockRef } from "../chain/rpc.js";
import { readAtStableHead, type LogSource } from "../chain/logs.js";
import { deploymentBlock, type ChainConfig } from "../config.js";
import { describeCause } from "../errors.js";
import type { NoteStore } from "../store/noteStore.js";

export interface NullifierSweepDeps {
  readonly config: ChainConfig;
  readonly chain: Pick<ChainReader, "latest" | "blockByNumber">;
  readonly logs: LogSource;
}

/**
 * Marks spent every stored note whose nullifier the pool has published, reading the WHOLE public
 * `NullifierSpent` set from where the last sweep stopped to `latest`. Never a per-nullifier query: asking
 * the node about our own nullifiers tells it which notes are ours.
 */
export async function sweepNullifiers(
  deps: NullifierSweepDeps,
  notes: NoteStore,
): Promise<BlockRef> {
  const from = Math.max(deploymentBlock(deps.config), notes.sweptThrough + 1);
  const { head, value } = await readAtStableHead(
    deps.chain,
    async (h, logsTo) =>
      from <= h.number
        ? logsTo([EVENT_TOPICS.NullifierSpent], from)
        : Promise.resolve([]),
    deps.logs,
  );
  const spends = value.map((log) => {
    let nullifier: unknown;
    try {
      nullifier = DARK_POOL_INTERFACE.parseLog({
        topics: [...log.topics],
        data: log.data,
      })?.args[0];
    } catch (cause) {
      return invalidResponse(
        "eth_getLogs NullifierSpent",
        log,
        `does not decode: ${describeCause(cause)}`,
      );
    }
    let field: Fr;
    try {
      if (typeof nullifier !== "string") throw new Error("no nullifier");
      field = new Fr(BigInt(nullifier));
    } catch (cause) {
      return invalidResponse(
        "eth_getLogs NullifierSpent",
        log,
        `carries no field element: ${describeCause(cause)}`,
      );
    }
    return {
      nullifier: field,
      block: { number: log.blockNumber, hash: log.blockHash },
      txHash: log.transactionHash,
    };
  });
  await notes.markSpent(spends, head.number);
  return head;
}
