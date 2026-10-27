import type { CompleteComplianceHistory, IDarkAccount } from "@hisoka/wallets";
import type { ChainReader } from "./chain/chainReader.js";
import {
  newestCanonical,
  stillCanonical,
  type LogSource,
} from "./chain/logs.js";
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
  type PlanRecord,
  type Reorg,
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
  /** Submitted plans this sync settled because their deadline passed at the confirmed head. */
  readonly settled: readonly PlanRecord[];
  readonly mirror: MirrorResult | null;
}

function blockKey(b: BlockId): string {
  return `${b.number}:${b.hash}`;
}

/** Every block the store recorded something at: cursor, earlier heads, inclusions, spends, submissions. */
function recordedBlocks(notes: NoteStore): BlockId[] {
  const points = new Map<string, BlockId>();
  const add = (b: BlockId | null | undefined): void => {
    if (b !== null && b !== undefined) points.set(blockKey(b), b);
  };
  add(notes.cursor);
  for (const h of notes.heads) add(h);
  for (const n of notes.notes) {
    add(n.block);
    add(n.spent?.block);
  }
  for (const p of notes.plans) add(p.submission?.block);
  return [...points.values()];
}

/**
 * Whether the chain reorged under what the store recorded, from block hashes alone. The cursor and anything
 * recorded above it (spends, submissions) are checked first; when all are still canonical nothing moved.
 * Otherwise every recorded block within `maxReorgBlocks` of the cursor is checked one by one, and the newest
 * recorded block at or below that bound must still be canonical (else `REORG_TOO_DEEP`, nothing changes).
 * The result names exactly the recorded blocks that left the chain, so the rollback never touches a note in a
 * block still on it.
 */
async function establishReorg(
  deps: Pick<WalletSyncDeps, "chain" | "config" | "notes">,
): Promise<Reorg | null> {
  const cursor = deps.notes.cursor;
  if (cursor === null) return null;
  const { maxReorgBlocks } = deps.config;
  const floor = cursor.number - maxReorgBlocks;
  const points = recordedBlocks(deps.notes);
  const alive = new Map<string, boolean>();
  const check = async (b: BlockId): Promise<boolean> => {
    const known = alive.get(blockKey(b));
    if (known !== undefined) return known;
    const canonical = await stillCanonical(deps.chain, b);
    alive.set(blockKey(b), canonical);
    return canonical;
  };

  let moved = false;
  for (const b of points.filter((p) => p.number >= cursor.number)) {
    if (!(await check(b))) moved = true;
  }
  if (!moved) return null;

  for (const b of points.filter((p) => p.number > floor)) await check(b);
  const orphaned = points.filter((b) => alive.get(blockKey(b)) === false);
  const anchor = await newestCanonical(
    deps.chain,
    [
      ...orphaned.filter((b) => b.number <= floor),
      ...points.filter((p) => p.number <= floor && !alive.has(blockKey(p))),
    ],
    floor,
    maxReorgBlocks,
  );
  const lowest = Math.min(...orphaned.map((b) => b.number));
  const ancestor = [
    ...points.filter(
      (b) =>
        alive.get(blockKey(b)) === true &&
        b.number < lowest &&
        b.number <= cursor.number,
    ),
    ...(anchor === null ? [] : [anchor]),
  ].reduce<BlockId | null>(
    (best, b) => (best === null || b.number > best.number ? b : best),
    null,
  );
  return { ancestor, orphaned };
}

/**
 * One wallet sync, in order: discovery to `latest`, a local rollback when the chain reorged under what the
 * store holds, note discovery over the self and incoming families, re-verification of PSS hints against
 * what discovery found, the whole-set nullifier sweep, the settlement of submitted plans whose deadline
 * passed, and the PSS mirror at the PSS write depth.
 *
 * The reorg is established from the block hashes the store recorded, never from the adapter's report alone:
 * an adapter rewind (or one it absorbed during a spend's preflight) says leaves moved, but only a hash that
 * left the chain says which notes did. The store rolls back exactly those, in one write, before anything new
 * is recorded.
 */
export async function syncWallet(deps: WalletSyncDeps): Promise<SyncReport> {
  const { notes } = deps;
  const head = await deps.discovery.sync();

  const reorg = await establishReorg(deps);
  const rolledBack = reorg === null ? null : await notes.rollback(reorg);

  const history = await deps.history();
  const found = await discoverWallet(
    deps.discovery,
    head,
    deps.account,
    history,
    await deps.highWater(),
    deps.config.maxOccurrencesPerTag,
  );
  await notes.record(found.notes.map(storedFrom), {
    head: head.block,
    maxReorgBlocks: deps.config.maxReorgBlocks,
  });

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
  const confirmed = await deps.chain.confirmedHead(
    deps.config.confirmations.spendableNotes,
  );
  const settled = await notes.settleSubmitted({
    confirmedHead: confirmed.number,
    sweptThrough: notes.sweptThrough,
    now: confirmed.timestamp,
  });

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
    settled,
    mirror,
  };
}
