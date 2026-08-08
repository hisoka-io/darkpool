import { ParsedStatePayload, UnspentNote } from "../wire/payload.js";
import { PssStateError } from "../state/errors.js";

export interface SpentOracle {
  spentBetween(
    fromBlock: number,
    toBlock: number,
  ): Promise<ReadonlySet<string>>;
}

export interface NullifierLog {
  readonly nullifier: string;
  readonly blockNumber: number;
}

// The whole public set, never a filter on our own nullifiers. Asking the node which of these are ours
// tells it which notes are ours, which is the leak the shielded pool exists to prevent, so the cost of
// downloading every spend is the price of the property.
export type NullifierLogSource = (
  fromBlock: number,
  toBlock: number,
) => Promise<readonly NullifierLog[]>;

export interface LogSweepOptions {
  readonly source: NullifierLogSource;
  readonly chunkBlocks: number;
}

export function createLogSweepOracle(options: LogSweepOptions): SpentOracle {
  if (!Number.isInteger(options.chunkBlocks) || options.chunkBlocks < 1) {
    throw new PssStateError(
      `spent scan chunk must be a positive integer, got ${options.chunkBlocks}`,
    );
  }
  return {
    async spentBetween(fromBlock, toBlock) {
      const spent = new Set<string>();
      for (
        let start = fromBlock;
        start <= toBlock;
        start += options.chunkBlocks
      ) {
        const end = Math.min(start + options.chunkBlocks - 1, toBlock);
        for (const log of await options.source(start, end)) {
          spent.add(log.nullifier.toLowerCase());
        }
      }
      return spent;
    },
  };
}

export interface PruneResult {
  readonly payload: ParsedStatePayload;
  readonly dropped: readonly UnspentNote[];
  readonly checkedThroughBlock: number;
}

/**
 * Membership-tests the WHOLE merged note set rather than a block range above `nullifierCheckedAt`.
 * The merge unions notes from every input while taking the max checkpoint over them, so a note one
 * device correctly pruned is reinstated by another's union and then covered by the higher checkpoint;
 * a range scan from the checkpoint would never revisit it. Testing the whole set is also what the
 * merge rule says literally: union by leaf index, minus anything the chain shows spent.
 */
export async function pruneSpentNotes(
  payload: ParsedStatePayload,
  oracle: SpentOracle,
  fromBlock: number,
  toBlock: number,
): Promise<PruneResult> {
  if (toBlock < fromBlock) {
    throw new PssStateError(
      `spent sweep range is inverted: ${fromBlock}..${toBlock}`,
    );
  }
  const spent = await oracle.spentBetween(fromBlock, toBlock);
  const kept: UnspentNote[] = [];
  const dropped: UnspentNote[] = [];
  for (const note of payload.known.unspentNotes) {
    (spent.has(note.nullifier.toLowerCase()) ? dropped : kept).push(note);
  }
  const checkedThroughBlock = Math.max(
    payload.known.nullifierCheckedAt.block,
    toBlock,
  );
  return {
    payload: {
      known: {
        ...payload.known,
        unspentNotes: kept,
        nullifierCheckedAt: { block: checkedThroughBlock },
      },
      extra: payload.extra,
    },
    dropped,
    checkedThroughBlock,
  };
}

export interface SpendableInput {
  readonly note: UnspentNote;
  readonly leafBlock: number;
}

/**
 * A note may only be spent once the spent-nullifier check has run past its leaf's block. Returning the
 * note rather than a boolean makes the guard the only way to obtain a spendable value, so a caller
 * cannot read the note out and ignore the answer.
 */
export function spendableNote(
  input: SpendableInput,
  checkedThroughBlock: number,
): UnspentNote {
  if (input.leafBlock > checkedThroughBlock) {
    throw new PssStateError(
      `note at leaf ${input.note.leafIndex} is not spendable: its block ${input.leafBlock} is above ` +
        `the spent-nullifier check, which has run through block ${checkedThroughBlock}`,
    );
  }
  return input.note;
}
