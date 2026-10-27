import type { Fr } from "@aztec/foundation/fields";
import type { HowlNoteRecord } from "@hisoka/wallets";
import type { BlockRef } from "../chain/rpc.js";
import type { ChainConfig } from "../config.js";
import { WalletRuntimeError } from "../errors.js";
import type {
  DiscoveryHead,
  DiscoveryPort,
  TagMatches,
  TreeWitness,
  WitnessPort,
} from "../discovery/ports.js";

/**
 * The members of Raven's Howl client this adapter maps. Structural, so the runtime takes no package edge on a
 * Raven-owned, unpublished client. Member names and result shapes follow the current client and are
 * provisional until Raven's interface v2.1 is final; only this file changes when it is.
 */
export interface RavenHowlClient {
  /** Brings the client's feed and tree to Raven's head; `rewoundTo` when it dropped state in a reorg. */
  sync(): Promise<{
    readonly leafCount: number;
    readonly root: Fr;
    readonly block: BlockRef;
    readonly rewoundTo?: number;
  }>;
  /** Every 6-byte prefix match per tag, positions ascending, one record per position. */
  probeFirst(tags: readonly Fr[]): Promise<
    readonly {
      readonly tag: Fr;
      readonly positions: readonly number[];
      readonly records: readonly HowlNoteRecord[];
    }[]
  >;
  /** The leaf at a position from a Merkle block the client verified against a header root. */
  confirmNote(
    leafIndex: number,
  ): Promise<
    | { readonly status: "confirmed"; readonly leaf: Fr }
    | { readonly status: "unconfirmed" }
    | { readonly status: "phantom" }
  >;
  merkleWitness(
    leafIndex: number,
    leafCount: number,
  ): Promise<{
    readonly leaf: Fr;
    readonly siblings: readonly Fr[];
    readonly root: Fr;
  }>;
  /** The pool Raven serves, when its interface exposes it. */
  deployment?(): Promise<{ readonly chainId: bigint; readonly pool: string }>;
}

/**
 * `DiscoveryPort` and `WitnessPort` over Raven. Raven answers cells, the prefix feed and Merkle blocks only:
 * compliance history, public memos and nullifiers come from the pool's logs, never from here. Every answer
 * is re-checked by the runtime (port contract, leaf check, witness fold and on-chain root), so Raven can at
 * worst hide notes.
 */
export class RavenDiscovery implements DiscoveryPort, WitnessPort {
  constructor(
    private readonly client: RavenHowlClient,
    private readonly config: ChainConfig,
  ) {}

  async sync(): Promise<DiscoveryHead> {
    if (this.client.deployment !== undefined) {
      const served = await this.client.deployment();
      const chainId = BigInt(this.config.deployment.chain_id);
      const pool = this.config.deployment.dark_pool.toLowerCase();
      if (served.chainId !== chainId || served.pool.toLowerCase() !== pool) {
        throw new WalletRuntimeError(
          "DEPLOYMENT_MISMATCH",
          `Raven serves pool ${served.pool} on chain ${served.chainId}; this wallet is configured for ${pool} on chain ${chainId}`,
          {
            expected: `${chainId}:${pool}`,
            actual: `${served.chainId}:${served.pool.toLowerCase()}`,
          },
        );
      }
    }
    const head = await this.client.sync();
    return {
      leafCount: head.leafCount,
      root: head.root,
      block: head.block,
      ...(head.rewoundTo === undefined ? {} : { rewoundTo: head.rewoundTo }),
    };
  }

  async match(tags: readonly Fr[]): Promise<readonly TagMatches[]> {
    const probed = await this.client.probeFirst(tags);
    return probed.map((p) => ({
      tag: p.tag,
      positions: p.positions,
      records: p.records,
      blocks: p.positions.map(() => null),
    }));
  }

  async leafAt(leafIndex: number): Promise<Fr | "unheld"> {
    const answer = await this.client.confirmNote(leafIndex);
    if (answer.status === "confirmed") return answer.leaf;
    if (answer.status === "unconfirmed") return "unheld";
    throw new WalletRuntimeError(
      "LEAF_MISMATCH",
      `Raven reports leaf ${leafIndex} as a phantom cell: its row has no leaf in the verified tree`,
      { leafIndex: String(leafIndex) },
    );
  }

  async witness(leafIndex: number, leafCount: number): Promise<TreeWitness> {
    const w = await this.client.merkleWitness(leafIndex, leafCount);
    return {
      leafIndex,
      leafCount,
      leaf: w.leaf,
      siblings: w.siblings,
      root: w.root,
    };
  }
}
