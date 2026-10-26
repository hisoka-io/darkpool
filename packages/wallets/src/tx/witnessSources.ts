/**
 * `MerkleWitnessSource` implementations.
 *
 * All of them are UNTRUSTED by construction, and that is a property of the protocol rather than of any
 * adapter: roots are retained on chain forever, so any historical root is provable against, and a path that
 * folds to one places a real inserted copy of the leaf at its index. A leaf value can sit at several indices
 * (a replayed identical deposit), so every source returns the path for the caller's expected index or fails.
 * A wrong or hostile witness therefore makes a proof FAIL, it can never make one prove something false. Each
 * source below still verifies locally before returning, so a bad answer surfaces here with a typed error
 * instead of as an opaque proving failure minutes later.
 */
import { Fr } from "@aztec/foundation/fields";
import { Poseidon } from "../crypto/Poseidon.js";
import { toFr } from "../crypto/fields.js";
import { LeanIMT } from "../merkle/LeanIMT.js";
import type { MerkleWitnessSource } from "./ports.js";

export class WitnessSourceError extends Error {
  constructor(
    readonly reason:
      | "LEAF_NOT_FOUND"
      | "LEAF_INDEX_MISMATCH"
      | "INVALID_LEAF_INDEX"
      | "MALFORMED_RESPONSE"
      | "ROOT_MISMATCH"
      | "TRANSPORT",
    message: string,
  ) {
    super(message);
    this.name = "WitnessSourceError";
  }
}

/**
 * Fold a path exactly as `lean_imt_inclusion_proof` does, INCLUDING the level in every hash.
 *
 * The level binds every sibling to its depth. Without it a sibling could be relocated between levels to
 * reproduce one root at an index where the leaf was never inserted, which drains the pool.
 * Any change here must land in the Noir and Solidity siblings in the same commit.
 */
export async function foldPath(
  leaf: Fr,
  leafIndex: number,
  siblings: readonly Fr[],
): Promise<Fr> {
  let current = leaf;
  for (let i = 0; i < siblings.length; i++) {
    const sibling = siblings[i]!;
    const bit = (BigInt(leafIndex) >> BigInt(i)) & 1n;
    if (sibling.toBigInt() !== 0n) {
      const left = bit === 1n ? sibling : current;
      const right = bit === 1n ? current : sibling;
      current = await Poseidon.hash([left, right, toFr(BigInt(i))]);
    } else if (bit === 1n) {
      throw new WitnessSourceError(
        "MALFORMED_RESPONSE",
        `non-canonical leaf index: right child at empty level ${i}`,
      );
    }
  }
  return current;
}

/**
 * The local tree. Correct and trust-free, but it costs O(pool) bandwidth to build, because the only way to
 * know every sibling is to have seen every note. Right for tests, for the W7 scenario and for a desktop
 * wallet willing to full-sync; wrong for a phone.
 */
export class LocalTreeWitnessSource implements MerkleWitnessSource {
  constructor(private readonly tree: LeanIMT) {}

  async witnessFor(
    leaf: Fr,
    expectedLeafIndex: number,
  ): Promise<{
    leafIndex: number;
    siblings: readonly Fr[];
    root: Fr;
  }> {
    assertLeafIndex(expectedLeafIndex);
    const atIndex = this.tree.levels[0]?.[expectedLeafIndex];
    if (atIndex === undefined) {
      throw new WitnessSourceError(
        "LEAF_NOT_FOUND",
        `leaf index ${expectedLeafIndex} is beyond the local tree (synced to ${this.tree.nextLeafIndex} leaves)`,
      );
    }
    if (!atIndex.equals(leaf)) {
      throw new WitnessSourceError(
        "LEAF_INDEX_MISMATCH",
        `local tree holds ${atIndex.toString()} at index ${expectedLeafIndex}, not leaf ${leaf.toString()}`,
      );
    }
    return {
      leafIndex: expectedLeafIndex,
      siblings: this.tree.getMerklePath(expectedLeafIndex),
      root: this.tree.getRoot(),
    };
  }
}

function assertLeafIndex(leafIndex: number): void {
  if (!Number.isSafeInteger(leafIndex) || leafIndex < 0) {
    throw new WitnessSourceError(
      "INVALID_LEAF_INDEX",
      `expected leaf index ${leafIndex} is not a non-negative integer`,
    );
  }
}

/**
 * Minimal transport so a caller can supply fetch, an extension port, or a mixnet round trip. The index tells
 * the server which copy of a duplicated leaf to serve; the leaf already reveals the position to it.
 */
export type WitnessTransport = (
  leafHex: string,
  leafIndex: number,
) => Promise<{ leafIndex: number; siblings: string[]; root: string }>;

/**
 * A remote indexer.
 *
 * Deliberately cheap insurance: it needs no trust, so it is safe to ship long before Raven's private
 * retrieval lands, and it is a component we expect to retire rather than harden. It DOES leak which leaf you
 * asked about to whoever serves it, which is exactly the privacy Raven exists to restore, so treat it as an
 * interim adapter and not the end state.
 */
export class IndexerWitnessSource implements MerkleWitnessSource {
  constructor(
    private readonly transport: WitnessTransport,
    private readonly depth = 32,
  ) {}

  async witnessFor(
    leaf: Fr,
    expectedLeafIndex: number,
  ): Promise<{
    leafIndex: number;
    siblings: readonly Fr[];
    root: Fr;
  }> {
    assertLeafIndex(expectedLeafIndex);
    let raw: { leafIndex: number; siblings: string[]; root: string };
    try {
      raw = await this.transport(leaf.toString(), expectedLeafIndex);
    } catch (e) {
      throw new WitnessSourceError(
        "TRANSPORT",
        `witness lookup failed: ${e instanceof Error ? e.message : String(e)}`,
      );
    }

    if (
      !Number.isInteger(raw.leafIndex) ||
      raw.leafIndex < 0 ||
      !Array.isArray(raw.siblings) ||
      raw.siblings.length !== this.depth ||
      typeof raw.root !== "string"
    ) {
      throw new WitnessSourceError(
        "MALFORMED_RESPONSE",
        `indexer returned a witness that is not ${this.depth} siblings plus an index and a root`,
      );
    }
    if (raw.leafIndex !== expectedLeafIndex) {
      throw new WitnessSourceError(
        "LEAF_INDEX_MISMATCH",
        `indexer placed leaf ${leaf.toString()} at index ${raw.leafIndex}, expected ${expectedLeafIndex}`,
      );
    }

    const siblings = raw.siblings.map((s) => Fr.fromString(s));
    const root = Fr.fromString(raw.root);

    // Verify BEFORE returning. The caller cannot be tricked, but it can be made to waste a proof, and an
    // error naming the indexer is far more actionable than a proving failure naming nothing.
    const recomputed = await foldPath(leaf, raw.leafIndex, siblings);
    if (!recomputed.equals(root)) {
      throw new WitnessSourceError(
        "ROOT_MISMATCH",
        `indexer witness does not reproduce its own root: folded ${recomputed.toString()}, claimed ${root.toString()}`,
      );
    }

    return { leafIndex: raw.leafIndex, siblings, root };
  }
}
