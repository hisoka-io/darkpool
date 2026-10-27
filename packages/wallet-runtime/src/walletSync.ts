import type { CompleteComplianceHistory, IDarkAccount } from "@hisoka/wallets";
import type { ChainReader } from "./chain/chainReader.js";
import { stillCanonical, type LogSource } from "./chain/logs.js";
import type { BlockId, BlockRef } from "./chain/rpc.js";
import type { ChainConfig } from "./config.js";
import type { DiscoveryHead, DiscoveryPort } from "./discovery/ports.js";
import {
  discoverWallet,
  storedFrom,
  type UnopenableRow,
} from "./discovery/sync.js";
import { sweepNullifiers } from "./history/nullifiers.js";
import {
  mirrorNotes,
  reverifyPssHints,
  type MirrorResult,
  type PssStatePort,
} from "./pss/noteMirror.js";
import {
  noteKey,
  nullifierHex,
  type NoteStore,
  type RollbackResult,
} from "./store/noteStore.js";

export interface WalletSyncDeps {
  readonly config: ChainConfig;
  readonly chain: Pick<
    ChainReader,
    "latest" | "blockByNumber" | "confirmedHead"
  >;
  readonly logs: LogSource;
  readonly discovery: DiscoveryPort;
  readonly notes: NoteStore;
  readonly account: Pick<
    IDarkAccount,
    "getSelfEphemeral" | "getSelfSpendPub" | "getIncomingKey"
  >;
  /** The complete compliance history from the runtime's producer. */
  readonly history: () => Promise<CompleteComplianceHistory>;
  /** Highest self ephemeral index reserved and highest incoming address index issued (PSS counters). */
  readonly highWater: () => Promise<{
    readonly self: number;
    readonly incoming: number;
  }>;
  /** When given, PSS hints are re-verified and confirmed notes mirrored into it. */
  readonly pss?: PssStatePort;
}

export interface SyncReport {
  readonly head: DiscoveryHead;
  /** What a reorg rollback undid this sync, if one ran. */
  readonly rolledBack: RollbackResult | null;
  /** Notes discovery found at this head, new or already stored. */
  readonly found: number;
  readonly unopenable: readonly UnopenableRow[];
  readonly phantoms: readonly number[];
  readonly hints: { readonly confirmed: number; readonly rejected: number };
  readonly sweptTo: BlockRef;
  readonly mirror: MirrorResult | null;
}

/**
 * The newest block the store recorded that is still canonical, no deeper than `maxReorgBlocks` below the
 * cursor; null when none is (the store then undoes everything).
 */
async function storeAncestor(
  deps: Pick<WalletSyncDeps, "chain" | "config" | "notes">,
  cursor: BlockId,
): Promise<BlockId | null> {
  const floor = cursor.number - deps.config.maxReorgBlocks;
  const points = new Map<number, BlockId>();
  for (const n of deps.notes.notes) {
    points.set(n.block.number, n.block);
    if (n.spent !== null) points.set(n.spent.block.number, n.spent.block);
  }
  const candidates = [...points.values()]
    .filter((b) => b.number >= floor && b.number < cursor.number)
    .sort((a, b) => b.number - a.number);
  for (const point of candidates) {
    if (await stillCanonical(deps.chain, point)) return point;
  }
  return null;
}

/**
 * One wallet sync, in order: discovery to `latest`, a local rollback when the chain reorged under what the
 * store holds, note discovery over the self and incoming families, re-verification of PSS hints against
 * what discovery found, the whole-set nullifier sweep, and the PSS mirror at the PSS write depth.
 *
 * A reorg is seen two ways: the discovery adapter reports `rewoundTo` (it dropped leaves), or the store's
 * cursor is no longer canonical (a reorg the adapter absorbed without dropping a leaf can still have moved
 * a spend). Either way the store rolls back in one write before anything new is recorded.
 */
export async function syncWallet(deps: WalletSyncDeps): Promise<SyncReport> {
  const { notes } = deps;
  const head = await deps.discovery.sync();

  let rolledBack: RollbackResult | null = null;
  if (head.rewoundTo !== undefined) {
    rolledBack = await notes.rollback(head.ancestor ?? null, head.rewoundTo);
  } else if (
    notes.cursor !== null &&
    !(await stillCanonical(deps.chain, notes.cursor))
  ) {
    rolledBack = await notes.rollback(
      await storeAncestor(deps, notes.cursor),
      Number.POSITIVE_INFINITY,
    );
  }

  const history = await deps.history();
  const found = await discoverWallet(
    deps.discovery,
    head,
    deps.account,
    history,
    await deps.highWater(),
    deps.config.maxOccurrencesPerTag,
  );
  await notes.record(found.notes.map(storedFrom), head.block);

  let hints = { confirmed: 0, rejected: 0 };
  if (deps.pss !== undefined) {
    const byHint = new Map(
      found.notes.map((n) => [
        `${n.leafIndex}:${nullifierHex(n.nullifier)}:${n.block.hash}`,
        n,
      ]),
    );
    hints = await reverifyPssHints(deps.pss, notes, async (hint) => {
      // PSS only ever holds confirmed notes, so a hint above this head is a node lagging behind, not a lie.
      if (hint.block > head.block.number) return { kind: "pending" };
      const match = byHint.get(
        `${hint.leafIndex}:${hint.nullifier}:${hint.blockHash}`,
      );
      if (match === undefined) {
        return {
          kind: "rejected",
          reason: `discovery at block ${head.block.number} finds no note at leaf ${hint.leafIndex} with that nullifier in block ${hint.blockHash}`,
        };
      }
      const stored = notes.find(noteKey(match));
      return stored === undefined
        ? { kind: "confirmed", note: storedFrom(match) }
        : { kind: "confirmed", note: stored };
    });
  }

  const sweptTo = await sweepNullifiers(deps, notes);

  let mirror: MirrorResult | null = null;
  if (deps.pss !== undefined) {
    const pssHead = await deps.chain.confirmedHead(
      deps.config.confirmations.pssWrite,
    );
    mirror = await mirrorNotes(deps.pss, notes, pssHead);
  }

  return {
    head,
    rolledBack,
    found: found.notes.length,
    unopenable: found.unopenable,
    phantoms: found.phantoms,
    hints,
    sweptTo,
    mirror,
  };
}
