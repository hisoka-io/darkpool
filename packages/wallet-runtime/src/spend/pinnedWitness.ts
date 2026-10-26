import type { Fr } from "@aztec/foundation/fields";
import { TREE_DEPTH } from "@hisoka/wallets";
import { foldPath } from "@hisoka/wallets/tx";
import type { ChainReader, TreeState } from "../chain/chainReader.js";
import type { TreeWitness, WitnessPort } from "../discovery/ports.js";
import { WalletRuntimeError, describeCause } from "../errors.js";

export interface SpendInput {
  readonly leafIndex: number;
  /** The note commitment the store holds for this position. */
  readonly commitment: Fr;
}

export interface WitnessChecks {
  readonly witnesses: WitnessPort;
  readonly chain: Pick<ChainReader, "isKnownRoot">;
}

function witnessMismatch(
  input: SpendInput,
  pin: TreeState,
  why: string,
  cause?: unknown,
): never {
  throw new WalletRuntimeError(
    "WITNESS_MISMATCH",
    `witness for leaf ${input.leafIndex} at tree size ${pin.leafCount} ${why}`,
    { leafIndex: String(input.leafIndex), leafCount: String(pin.leafCount) },
    cause,
  );
}

/**
 * The witness for one spend input, taken in the tree pinned for the whole action and accepted only when it
 * names the stored note, folds to its own root, that root is the pinned root, and the pool still knows it.
 * Runs in that order and throws at the first failure, so nothing after it (assembly, proving) sees the path.
 */
export async function checkedWitness(
  checks: WitnessChecks,
  pin: TreeState,
  input: SpendInput,
): Promise<TreeWitness> {
  if (
    !Number.isSafeInteger(input.leafIndex) ||
    input.leafIndex < 1 ||
    input.leafIndex >= pin.leafCount
  ) {
    witnessMismatch(
      input,
      pin,
      "is outside the pinned tree [1, leafCount); the note is not confirmed at the pin",
    );
  }

  const w = await checks.witnesses.witness(input.leafIndex, pin.leafCount);
  if (w.leafIndex !== input.leafIndex || w.leafCount !== pin.leafCount) {
    witnessMismatch(
      input,
      pin,
      `came back for leaf ${w.leafIndex} at tree size ${w.leafCount}`,
    );
  }
  if (!w.leaf.equals(input.commitment)) {
    throw new WalletRuntimeError(
      "LEAF_MISMATCH",
      `tree leaf ${w.leaf.toString()} at index ${input.leafIndex} is not the stored note ${input.commitment.toString()}`,
      {
        leafIndex: String(input.leafIndex),
        expected: input.commitment.toString(),
        actual: w.leaf.toString(),
      },
    );
  }
  if (w.siblings.length !== TREE_DEPTH) {
    witnessMismatch(
      input,
      pin,
      `has ${w.siblings.length} siblings, the circuit takes ${TREE_DEPTH}`,
    );
  }

  let folded: Fr;
  try {
    folded = await foldPath(w.leaf, w.leafIndex, w.siblings);
  } catch (cause) {
    return witnessMismatch(
      input,
      pin,
      `does not fold: ${describeCause(cause)}`,
      cause,
    );
  }
  if (!folded.equals(w.root)) {
    witnessMismatch(
      input,
      pin,
      `folds to ${folded.toString()}, not its claimed root ${w.root.toString()}`,
    );
  }
  if (!w.root.equals(pin.root)) {
    throw new WalletRuntimeError(
      "ROOT_PIN_MISMATCH",
      `witness root ${w.root.toString()} is not the root pinned at block ${pin.block.number} (${pin.root.toString()})`,
      { pinned: pin.root.toString(), witness: w.root.toString() },
    );
  }
  if (!(await checks.chain.isKnownRoot(pin.root, "latest"))) {
    throw new WalletRuntimeError(
      "ROOT_UNKNOWN",
      `pinned root ${pin.root.toString()} from block ${pin.block.number} is not a known root at latest; the pin left the canonical chain`,
      { root: pin.root.toString(), block: String(pin.block.number) },
    );
  }
  return w;
}

/** The witness port wallets `assemble*` takes once it names the expected index (leaf plus index). */
export interface PinnedWitnessSource {
  witnessFor(
    leaf: Fr,
    expectedLeafIndex: number,
  ): Promise<{
    readonly leafIndex: number;
    readonly siblings: readonly Fr[];
    readonly root: Fr;
  }>;
}

/**
 * Hands assembly only checked witnesses, every one at the same pinned tree size, for exactly the notes the
 * plan leased. The live tree may grow while an action assembles; the pin does not move, so a join's two paths
 * always come from one tree.
 */
export function pinnedWitnessSource(
  checks: WitnessChecks,
  pin: TreeState,
  expected: ReadonlyMap<number, Fr>,
): PinnedWitnessSource {
  return {
    async witnessFor(leaf, expectedLeafIndex) {
      const planned = expected.get(expectedLeafIndex);
      if (planned === undefined || !planned.equals(leaf)) {
        throw new WalletRuntimeError(
          "LEAF_MISMATCH",
          `assembly asked for leaf ${leaf.toString()} at index ${expectedLeafIndex}, which is not an input this plan leased`,
          { leafIndex: String(expectedLeafIndex), actual: leaf.toString() },
        );
      }
      const w = await checkedWitness(checks, pin, {
        leafIndex: expectedLeafIndex,
        commitment: planned,
      });
      return { leafIndex: w.leafIndex, siblings: w.siblings, root: w.root };
    },
  };
}
