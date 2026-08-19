/**
 * The ports transaction assembly depends on.
 *
 * Every one is an interface the CONSUMER implements, never a class this package constructs. That is not
 * style: `@hisoka/prover` depends on `@hisoka/wallets`, so wallets importing the prover would be a cycle,
 * and no single backend serves node, a browser, an MV3 extension, mobile and a relayer at once.
 */
import { Fr } from "@aztec/foundation/fields";
import { Point } from "@zk-kit/baby-jubjub";

/** Circuits an implementation may be asked for. Mirrors the on-chain circuit ids. */
export type CircuitId =
  | "deposit"
  | "withdraw"
  | "transfer"
  | "split"
  | "join"
  | "public_claim"
  | "withdraw_multisig"
  | "transfer_multisig"
  | "split_multisig"
  | "join_multisig"
  | "swap_intent"
  | "swap_settle";

export interface ProofData {
  readonly proof: Uint8Array;
  readonly publicInputs: readonly string[];
}

/**
 * Proving. ALWAYS LOCAL.
 *
 * The witness contains the owner's BabyJubJub spend scalar in clear, so an implementation that ships the
 * witness anywhere off-device is a total custody break, not a performance trade. This port exists so each
 * environment can supply its own LOCAL backend (bb.js in a worker or offscreen document, native on mobile),
 * never to offload the work.
 */
export interface ProverPort {
  /** What this backend can actually prove here. `swap_settle` is native-only; a WASM backend must omit it. */
  capabilities(): Promise<{
    readonly circuits: readonly CircuitId[];
    readonly recursive: boolean;
    readonly environment: "native" | "wasm";
  }>;
  prove(circuit: CircuitId, witness: unknown): Promise<ProofData>;
}

/**
 * Where a spend's Merkle witness comes from.
 *
 * Keyed by the LEAF, not by an index: `pathFor(leafIndex)` would hand the provider the exact position of
 * the note you are about to spend, which is the one thing a private-retrieval layer exists to hide.
 *
 * It needs NO TRUST. Roots are retained forever on chain, so any historical root is provable against; and
 * because `leaf_index` is uniquely determined by (leaf, root), a wrong or malicious witness can only make a
 * proof FAIL, never make it prove something false. Callers must still verify: recompute the root locally and
 * check it is known on chain.
 */
export interface MerkleWitnessSource {
  witnessFor(leaf: Fr): Promise<{
    readonly leafIndex: number;
    readonly siblings: readonly Fr[];
    readonly root: Fr;
  }>;
}

/** The three chain reads assembly needs, and nothing else. Keeps `ethers` out of this package. */
export interface ChainView {
  isKnownRoot(root: Fr): Promise<boolean>;
  /** `(x, y, version)`. The version is the anchor: a rotation mid-flight invalidates an in-progress build. */
  complianceKey(): Promise<{
    readonly point: Point<bigint>;
    readonly version: number;
  }>;
  nextLeafIndex(): Promise<number>;
}

/** Read-only view of spendable notes. Async so IndexedDB, chrome.storage and sqlite all satisfy it. */
export interface NoteSource {
  unspent(assetId?: Fr): Promise<
    readonly {
      readonly leafIndex: number;
      readonly assetId: Fr;
      readonly value: bigint;
    }[]
  >;
}

/**
 * Exclusive claim on a note for the duration of an assembly.
 *
 * Two devices under one seed will otherwise select the same note, and the loser burns a proof and an
 * ephemeral index. The lease is durable because the losing device may be the one that crashes.
 */
export interface NoteLease {
  acquire(leafIndices: readonly number[], planId: string): Promise<boolean>;
  release(planId: string): Promise<void>;
}

/**
 * Randomness, injected rather than ambient so a test can pin it and an audit can find it.
 *
 * `nextMemoEphemeral` is a SAMPLER, not a value: the memo ephemeral is rejection-sampled until its public
 * key has even y, so handing back one fixed scalar makes that loop non-terminating.
 */
export interface EntropySource {
  nextMemoEphemeral(): Fr;
  salt(): Fr;
}
