import { Fr } from "@aztec/foundation/fields";
import {
  genesisLeaf,
  HOWL_NOTE_LAYOUT_VERSION,
  LeanIMT,
  TREE_DEPTH,
  type HowlNoteRecord,
} from "@hisoka/wallets";
import { DARK_POOL_INTERFACE, EVENT_TOPICS } from "../../abi.js";
import type { ChainReader } from "../../chain/chainReader.js";
import {
  readAtStableHead,
  stillCanonical,
  MAX_STABLE_READ_ATTEMPTS,
  type LogSource,
  type RawLog,
} from "../../chain/logs.js";
import type { BlockId, BlockRef } from "../../chain/rpc.js";
import { deploymentBlock, type ChainConfig } from "../../config.js";
import { describeCause, WalletRuntimeError } from "../../errors.js";
import { runtimeKey, type RuntimeStore } from "../../store/runtimeStore.js";
import type {
  DiscoveryHead,
  DiscoveryPort,
  TagMatches,
  TreeWitness,
  WitnessPort,
} from "../../discovery/ports.js";
import { tagOf, toRecord, type ChainNoteEvent } from "./record.js";

/** Leaves per persisted page; a sync rewrites only the pages it touched. */
export const SELF_INDEX_PAGE_LEAVES = 1024;

export interface SelfIndexDeps {
  readonly config: ChainConfig;
  readonly chain: Pick<
    ChainReader,
    "latest" | "blockByNumber" | "treeState" | "confirmedHead"
  >;
  readonly logs: LogSource;
  readonly store: RuntimeStore;
}

interface IndexedLeaf {
  readonly leaf: Fr;
  readonly block: BlockId;
  /** Null only for the genesis leaf. */
  readonly record: HowlNoteRecord | null;
  readonly tag: Fr | null;
}

interface Meta {
  readonly leafCount: number;
  readonly processed: BlockId | null;
  /** Recent sync heads, newest last: the walk-back points between leaf blocks. */
  readonly heads: readonly BlockId[];
}

const NOTE_TOPICS: readonly [string, ...string[]] = [
  EVENT_TOPICS.LeafInserted,
  EVENT_TOPICS.NewNote,
  EVENT_TOPICS.NewPrivateMemo,
  EVENT_TOPICS.GenesisSeeded,
];

const META_VERSION = 1;

class StaleHead extends Error {}

/**
 * Discovery and Merkle paths from the pool's own logs, for solvers, servers and full-sync desktop wallets.
 *
 * Every `LeafInserted` is replayed into a local LeanIMT and its `newRoot` must match, every leaf must carry
 * exactly one note event with the same commitment, and after each sync the local `(leafCount, root)` must
 * equal the pool's at the same block hash, which is what catches an RPC that drops logs. The RPC sees one
 * unfiltered full-history download and nothing per note.
 *
 * Two trees: the head tree (every leaf to `latest`) answers occupancy and root checks; the confirmed tree
 * (leaves up to the confirmed head for spendable notes) answers spend paths. A path is always for an explicit
 * tree size and any other size is rebuilt from the stored leaves, so a sync that lands while an action is
 * assembling cannot move the tree its pin names.
 */
export class SelfIndexDiscovery implements DiscoveryPort, WitnessPort {
  #leaves: IndexedLeaf[] = [];
  #byTag = new Map<string, number[]>();
  #head = new LeanIMT(TREE_DEPTH);
  #confirmed = new LeanIMT(TREE_DEPTH);
  #meta: Meta = { leafCount: 0, processed: null, heads: [] };
  #lock: Promise<void> = Promise.resolve();
  #storedPages = 0;

  private constructor(private readonly deps: SelfIndexDeps) {}

  static async open(deps: SelfIndexDeps): Promise<SelfIndexDiscovery> {
    const index = new SelfIndexDiscovery(deps);
    await index.#load();
    return index;
  }

  /** Leaves in the confirmed tree: the tree size a spend pins. */
  get confirmedLeafCount(): number {
    return this.#confirmed.nextLeafIndex;
  }

  get leafCount(): number {
    return this.#leaves.length;
  }

  /** One sync at a time; witnesses are keyed by tree size, so a sync never invalidates a pinned path. */
  sync(): Promise<DiscoveryHead> {
    const run = this.#lock.then(
      () => this.#sync(),
      () => this.#sync(),
    );
    this.#lock = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  async match(tags: readonly Fr[]): Promise<readonly TagMatches[]> {
    return tags.map((tag) => {
      const positions = this.#byTag.get(tag.toString()) ?? [];
      const rows = positions.map((p) => this.#leaves[p]);
      return {
        tag,
        positions: [...positions],
        records: rows.map((r) => r?.record ?? missing(tag)),
        blocks: rows.map((r) => r?.block ?? null),
      };
    });
  }

  async leafAt(leafIndex: number): Promise<Fr | "unheld"> {
    return this.#leaves[leafIndex]?.leaf ?? "unheld";
  }

  async witness(leafIndex: number, leafCount: number): Promise<TreeWitness> {
    if (
      !Number.isSafeInteger(leafIndex) ||
      !Number.isSafeInteger(leafCount) ||
      leafIndex < 0 ||
      leafIndex >= leafCount ||
      leafCount > this.#leaves.length
    ) {
      throw new WalletRuntimeError(
        "WITNESS_MISMATCH",
        `self-index holds ${this.#leaves.length} leaves and cannot give leaf ${leafIndex} at tree size ${leafCount}`,
        { leafIndex: String(leafIndex), leafCount: String(leafCount) },
      );
    }
    let tree: LeanIMT;
    if (leafCount === this.#confirmed.nextLeafIndex) tree = this.#confirmed;
    else if (leafCount === this.#head.nextLeafIndex) tree = this.#head;
    else tree = await buildTree(this.#leaves.slice(0, leafCount));
    const leaf = this.#leaves[leafIndex]?.leaf ?? Fr.ZERO;
    return {
      leafIndex,
      leafCount,
      leaf,
      siblings: tree.getMerklePath(leafIndex),
      root: tree.getRoot(),
    };
  }

  async #sync(): Promise<DiscoveryHead> {
    let rewound: { rewoundTo: number; ancestor: BlockId | null } | null = null;
    for (let attempt = 1; attempt <= MAX_STABLE_READ_ATTEMPTS; attempt++) {
      const dropped = await this.#rewindIfReorged();
      if (dropped !== null) {
        rewound =
          rewound === null || dropped.rewoundTo < rewound.rewoundTo
            ? dropped
            : rewound;
      }
      try {
        const head = await this.#advance();
        return {
          ...head,
          ...(rewound === null
            ? {}
            : {
                rewoundTo: rewound.rewoundTo,
                ...(rewound.ancestor === null
                  ? {}
                  : { ancestor: rewound.ancestor }),
              }),
        };
      } catch (e) {
        if (e instanceof StaleHead) continue;
        throw e;
      }
    }
    throw new WalletRuntimeError(
      "HEAD_REORGED",
      `self-index sync met a reorg on each of ${MAX_STABLE_READ_ATTEMPTS} attempts`,
      { attempts: String(MAX_STABLE_READ_ATTEMPTS), head: "" },
    );
  }

  /** Reads every note log to a stable head, replays it, checks it against the pool, then persists. */
  async #advance(): Promise<DiscoveryHead> {
    const from =
      this.#meta.processed === null
        ? deploymentBlock(this.deps.config)
        : this.#meta.processed.number + 1;
    const { head, value: logs } = await readAtStableHead(
      this.deps.chain,
      async (h, logsTo) =>
        from <= h.number ? logsTo(NOTE_TOPICS, from) : Promise.resolve([]),
      this.deps.logs,
    );

    const firstNew = this.#leaves.length;
    const staged = await stageLogs(
      logs,
      firstNew,
      from,
      head.number,
      this.deps.config,
    );
    try {
      for (const entry of staged) {
        const root = await this.#head.insert(entry.leaf);
        if (!root.equals(entry.newRoot)) {
          throw new WalletRuntimeError(
            "TREE_ROOT_MISMATCH",
            `replaying leaf ${this.#head.nextLeafIndex - 1} gives root ${root.toString()}, the log says ${entry.newRoot.toString()}`,
            {
              leafCount: String(this.#head.nextLeafIndex),
              local: root.toString(),
              chain: entry.newRoot.toString(),
            },
          );
        }
        this.#leaves.push(entry.indexed);
      }
      if (this.#leaves.length > 0) {
        const state = await this.deps.chain.treeState(head);
        if (
          state.leafCount !== this.#leaves.length ||
          !state.root.equals(this.#head.getRoot())
        ) {
          throw new WalletRuntimeError(
            "TREE_ROOT_MISMATCH",
            `after replay the local tree is (${this.#leaves.length}, ${this.#head.getRoot().toString()}) and the pool at block ${head.number} is (${state.leafCount}, ${state.root.toString()}): the log source dropped or invented leaves`,
            {
              leafCount: String(state.leafCount),
              local: this.#head.getRoot().toString(),
              chain: state.root.toString(),
            },
          );
        }
      }
    } catch (e) {
      await this.#truncate(firstNew);
      if (
        e instanceof WalletRuntimeError &&
        !(await stillCanonical(this.deps.chain, head))
      ) {
        throw new StaleHead();
      }
      throw e;
    }

    for (let i = firstNew; i < this.#leaves.length; i++) this.#indexTag(i);
    await this.#advanceConfirmed(head);
    const processed: BlockId = { number: head.number, hash: head.hash };
    const floor = head.number - this.deps.config.maxReorgBlocks;
    this.#meta = {
      leafCount: this.#leaves.length,
      processed,
      heads: [
        ...this.#meta.heads.filter(
          (h) => h.number >= floor && h.number < head.number,
        ),
        processed,
      ],
    };
    await this.#persist(firstNew);
    return {
      leafCount: this.#leaves.length,
      root: this.#head.getRoot(),
      block: head,
    };
  }

  /**
   * When the processed head is no longer canonical, walks the stored block hashes newest first, no deeper
   * than `maxReorgBlocks`, to the newest one still canonical, and drops every leaf above it. Past that
   * depth the index starts over from the deployment block.
   */
  async #rewindIfReorged(): Promise<{
    rewoundTo: number;
    ancestor: BlockId | null;
  } | null> {
    const processed = this.#meta.processed;
    if (processed === null) return null;
    if (await stillCanonical(this.deps.chain, processed)) return null;

    const floor = processed.number - this.deps.config.maxReorgBlocks;
    const points = new Map<number, BlockId>();
    for (const h of this.#meta.heads) points.set(h.number, h);
    for (const l of this.#leaves) points.set(l.block.number, l.block);
    const candidates = [...points.values()]
      .filter((b) => b.number >= floor && b.number < processed.number)
      .sort((a, b) => b.number - a.number);
    for (const point of candidates) {
      if (await stillCanonical(this.deps.chain, point)) {
        const keep = this.#leaves.findIndex(
          (l) => l.block.number > point.number,
        );
        const rewoundTo = keep === -1 ? this.#leaves.length : keep;
        await this.#truncate(rewoundTo);
        this.#meta = {
          leafCount: this.#leaves.length,
          processed: point,
          heads: this.#meta.heads.filter((h) => h.number <= point.number),
        };
        await this.#persist(rewoundTo);
        return { rewoundTo, ancestor: point };
      }
    }
    // Deeper than maxReorgBlocks: correct but slow, start over.
    await this.#truncate(0);
    this.#meta = { leafCount: 0, processed: null, heads: [] };
    await this.#persist(0);
    return { rewoundTo: 0, ancestor: null };
  }

  async #advanceConfirmed(head: BlockRef): Promise<void> {
    const confirmed = await this.deps.chain.confirmedHead(
      this.deps.config.confirmations.spendableNotes,
    );
    const limit = Math.min(confirmed.number, head.number);
    let count = 0;
    while (
      count < this.#leaves.length &&
      (this.#leaves[count]?.block.number ?? Infinity) <= limit
    ) {
      count += 1;
    }
    if (count < this.#confirmed.nextLeafIndex) {
      this.#confirmed = await buildTree(this.#leaves.slice(0, count));
      return;
    }
    for (let i = this.#confirmed.nextLeafIndex; i < count; i++) {
      const leaf = this.#leaves[i];
      if (leaf !== undefined) await this.#confirmed.insert(leaf.leaf);
    }
  }

  /** Drops every leaf at or above `count` from the leaves, the tag index and both trees. */
  async #truncate(count: number): Promise<void> {
    if (count >= this.#leaves.length && count >= this.#head.nextLeafIndex) {
      return;
    }
    this.#leaves = this.#leaves.slice(0, count);
    this.#byTag = new Map();
    for (let i = 0; i < this.#leaves.length; i++) this.#indexTag(i);
    this.#head = await buildTree(this.#leaves);
    if (this.#confirmed.nextLeafIndex > count) {
      this.#confirmed = await buildTree(this.#leaves);
    }
  }

  #indexTag(i: number): void {
    const tag = this.#leaves[i]?.tag;
    if (tag === null || tag === undefined) return;
    const key = tag.toString();
    const list = this.#byTag.get(key);
    if (list === undefined) this.#byTag.set(key, [i]);
    else list.push(i);
  }

  #key(...parts: string[]): string {
    return runtimeKey(this.deps.config.deployment, "selfIndex", ...parts);
  }

  /** Rewrites the pages from `fromLeaf` on and the meta in one atomic batch; pages past the end are deleted. */
  async #persist(fromLeaf: number): Promise<void> {
    const writes: [string, string | null][] = [];
    const firstPage = Math.floor(fromLeaf / SELF_INDEX_PAGE_LEAVES);
    const pages = Math.ceil(this.#leaves.length / SELF_INDEX_PAGE_LEAVES);
    const storedPages = this.#storedPages;
    for (let p = firstPage; p < Math.max(pages, storedPages); p++) {
      if (p >= pages) {
        writes.push([this.#key("page", String(p)), null]);
        continue;
      }
      const slice = this.#leaves.slice(
        p * SELF_INDEX_PAGE_LEAVES,
        (p + 1) * SELF_INDEX_PAGE_LEAVES,
      );
      writes.push([
        this.#key("page", String(p)),
        JSON.stringify(slice.map(encodeLeaf)),
      ]);
    }
    writes.push([
      this.#key("meta"),
      JSON.stringify({ v: META_VERSION, ...this.#meta }),
    ]);
    await this.deps.store.setMany(writes);
    this.#storedPages = pages;
  }

  async #load(): Promise<void> {
    const raw = await this.deps.store.get(this.#key("meta"));
    if (raw === null) return;
    try {
      const meta = JSON.parse(raw) as {
        v: unknown;
        leafCount: number;
        processed: BlockId | null;
        heads: BlockId[];
      };
      if (meta.v !== META_VERSION)
        throw new Error(`meta version ${String(meta.v)}`);
      const pages = Math.ceil(meta.leafCount / SELF_INDEX_PAGE_LEAVES);
      const leaves: IndexedLeaf[] = [];
      for (let p = 0; p < pages; p++) {
        const page = await this.deps.store.get(this.#key("page", String(p)));
        if (page === null) throw new Error(`page ${p} is missing`);
        for (const entry of JSON.parse(page) as EncodedLeaf[]) {
          leaves.push(decodeLeaf(entry, leaves.length));
        }
      }
      if (leaves.length !== meta.leafCount)
        throw new Error(
          `${leaves.length} leaves stored, meta says ${meta.leafCount}`,
        );
      this.#leaves = leaves;
      this.#meta = {
        leafCount: meta.leafCount,
        processed: meta.processed,
        heads: meta.heads,
      };
      this.#storedPages = pages;
      for (let i = 0; i < leaves.length; i++) this.#indexTag(i);
      this.#head = await buildTree(leaves);
    } catch (cause) {
      throw new WalletRuntimeError(
        "STORE_CORRUPT",
        `the self-index state does not load: ${describeCause(cause)}`,
        { key: this.#key("meta") },
        cause,
      );
    }
  }
}

async function buildTree(leaves: readonly IndexedLeaf[]): Promise<LeanIMT> {
  const tree = new LeanIMT(TREE_DEPTH);
  for (const l of leaves) await tree.insert(l.leaf);
  return tree;
}

/** A tag index entry always has a row; this is the shape a lookup returns if it ever does not. */
function missing(tag: Fr): never {
  throw new WalletRuntimeError(
    "STORE_CORRUPT",
    `self-index tag ${tag.toString()} points at a leaf it does not hold`,
    { key: "selfIndex.tags" },
  );
}

interface StagedLeaf {
  readonly leaf: Fr;
  readonly newRoot: Fr;
  readonly indexed: IndexedLeaf;
}

function word(value: unknown, log: RawLog, what: string): Fr {
  if (typeof value !== "bigint" && typeof value !== "string") {
    throw logGap(
      log.blockNumber,
      log.blockNumber,
      -1,
      `${what} does not decode`,
    );
  }
  try {
    return new Fr(BigInt(value));
  } catch (cause) {
    throw logGap(
      log.blockNumber,
      log.blockNumber,
      -1,
      `${what} is not a field element: ${describeCause(cause)}`,
    );
  }
}

function logGap(
  fromBlock: number,
  toBlock: number,
  expectedLeaf: number,
  why: string,
): WalletRuntimeError {
  return new WalletRuntimeError(
    "LOG_GAP",
    `pool logs in [${fromBlock}, ${toBlock}] do not form a complete leaf sequence: ${why}`,
    {
      fromBlock: String(fromBlock),
      toBlock: String(toBlock),
      expectedLeaf: String(expectedLeaf),
    },
  );
}

/**
 * Decodes one sync's logs into leaves in insertion order and checks their structure: contiguous leaf
 * indices from `firstLeaf`, exactly one note event per non-genesis leaf with the leaf as its commitment,
 * and a genesis leaf that is this chain's.
 */
async function stageLogs(
  logs: readonly RawLog[],
  firstLeaf: number,
  fromBlock: number,
  toBlock: number,
  config: ChainConfig,
): Promise<StagedLeaf[]> {
  const inserted: { index: number; leaf: Fr; newRoot: Fr; log: RawLog }[] = [];
  const events = new Map<number, { event: ChainNoteEvent; log: RawLog }>();
  let genesisSeeded: { chainId: bigint; leaf: Fr } | null = null;

  for (const log of logs) {
    const parsed = DARK_POOL_INTERFACE.parseLog({
      topics: [...log.topics],
      data: log.data,
    });
    if (parsed === null) {
      throw logGap(
        fromBlock,
        toBlock,
        firstLeaf,
        `log ${log.logIndex} in block ${log.blockNumber} does not decode`,
      );
    }
    const args = [...parsed.args];
    if (parsed.name === "LeafInserted") {
      inserted.push({
        index: Number(args[0]),
        leaf: word(args[1], log, "LeafInserted.leaf"),
        newRoot: word(args[2], log, "LeafInserted.newRoot"),
        log,
      });
    } else if (parsed.name === "GenesisSeeded") {
      genesisSeeded = {
        chainId: BigInt(args[0] as bigint),
        leaf: word(args[1], log, "GenesisSeeded.genesisLeaf"),
      };
    } else if (parsed.name === "NewNote" || parsed.name === "NewPrivateMemo") {
      const leafIndex = Number(args[0]);
      const ct = (
        args[parsed.name === "NewNote" ? 3 : 5] as readonly unknown[]
      ).map((w, i) => word(w, log, `${parsed.name}.packedCiphertext[${i}]`));
      const event: ChainNoteEvent =
        parsed.name === "NewNote"
          ? {
              kind: "NEW_NOTE",
              leafIndex,
              commitment: word(args[1], log, "NewNote.commitment"),
              ephemeralX: word(args[2], log, "NewNote.ephemeralPK_x"),
              packedCiphertext: ct,
            }
          : {
              kind: "NEW_MEMO",
              leafIndex,
              commitment: word(args[1], log, "NewPrivateMemo.commitment"),
              tag: word(args[2], log, "NewPrivateMemo.tag"),
              ephemeralX: word(args[3], log, "NewPrivateMemo.ephemeralPK_x"),
              cekWrap: word(args[4], log, "NewPrivateMemo.cekWrap"),
              packedCiphertext: ct,
            };
      if (events.has(leafIndex)) {
        throw logGap(
          fromBlock,
          toBlock,
          leafIndex,
          `leaf ${leafIndex} has two note events`,
        );
      }
      events.set(leafIndex, { event, log });
    }
  }

  const staged: StagedLeaf[] = [];
  let expected = firstLeaf;
  for (const ins of inserted) {
    if (ins.index !== expected) {
      throw logGap(
        fromBlock,
        toBlock,
        expected,
        `LeafInserted(${ins.index}) arrived where leaf ${expected} was due`,
      );
    }
    const block: BlockId = {
      number: ins.log.blockNumber,
      hash: ins.log.blockHash,
    };
    if (ins.index === 0) {
      const chainId = BigInt(config.deployment.chain_id);
      const expectedGenesis = await genesisLeaf(chainId);
      if (
        !ins.leaf.equals(expectedGenesis) ||
        genesisSeeded === null ||
        genesisSeeded.chainId !== chainId ||
        !genesisSeeded.leaf.equals(ins.leaf)
      ) {
        throw new WalletRuntimeError(
          "GENESIS_MISMATCH",
          `leaf 0 is ${ins.leaf.toString()}; chain ${chainId} seeds ${expectedGenesis.toString()} and GenesisSeeded ${genesisSeeded === null ? "is absent" : `says chain ${genesisSeeded.chainId}, leaf ${genesisSeeded.leaf.toString()}`}`,
          { chainId: chainId.toString() },
        );
      }
      staged.push({
        leaf: ins.leaf,
        newRoot: ins.newRoot,
        indexed: { leaf: ins.leaf, block, record: null, tag: null },
      });
    } else {
      const note = events.get(ins.index);
      if (note === undefined || !note.event.commitment.equals(ins.leaf)) {
        throw logGap(
          fromBlock,
          toBlock,
          ins.index,
          note === undefined
            ? `leaf ${ins.index} has no NewNote or NewPrivateMemo`
            : `leaf ${ins.index} is ${ins.leaf.toString()} but its note event commits to ${note.event.commitment.toString()}`,
        );
      }
      events.delete(ins.index);
      staged.push({
        leaf: ins.leaf,
        newRoot: ins.newRoot,
        indexed: {
          leaf: ins.leaf,
          block,
          record: toRecord(note.event),
          tag: tagOf(note.event),
        },
      });
    }
    expected += 1;
  }
  const orphan = [...events.keys()][0];
  if (orphan !== undefined) {
    throw logGap(
      fromBlock,
      toBlock,
      orphan,
      `a note event names leaf ${orphan}, which no LeafInserted in range inserted`,
    );
  }
  return staged;
}

interface EncodedLeaf {
  readonly l: string;
  readonly b: readonly [number, string];
  readonly r: null | {
    readonly k: number;
    readonly p: string;
    readonly e: string;
    readonly w: string;
    readonly c: readonly string[];
  };
  readonly t: string | null;
}

function encodeLeaf(l: IndexedLeaf): EncodedLeaf {
  return {
    l: l.leaf.toString(),
    b: [l.block.number, l.block.hash],
    r:
      l.record === null
        ? null
        : {
            k: l.record.recordKind,
            p: Buffer.from(l.record.commitmentPrefix).toString("hex"),
            e: l.record.ephemeralPkX.toString(),
            w: l.record.cekWrap.toString(),
            c: l.record.ciphertextKept.map((w) => w.toString()),
          },
    t: l.tag === null ? null : l.tag.toString(),
  };
}

function decodeLeaf(e: EncodedLeaf, leafIndex: number): IndexedLeaf {
  const leaf = new Fr(BigInt(e.l));
  const block: BlockId = { number: e.b[0], hash: e.b[1] };
  if (e.r === null) return { leaf, block, record: null, tag: null };
  const kind = e.r.k;
  if (kind !== 0 && kind !== 1) throw new Error(`record kind ${kind}`);
  return {
    leaf,
    block,
    record: {
      layoutVersion: HOWL_NOTE_LAYOUT_VERSION,
      recordKind: kind,
      leafIndex,
      commitmentPrefix: Uint8Array.from(Buffer.from(e.r.p, "hex")),
      ephemeralPkX: new Fr(BigInt(e.r.e)),
      cekWrap: new Fr(BigInt(e.r.w)),
      ciphertextKept: e.r.c.map((w) => new Fr(BigInt(w))),
    },
    tag: e.t === null ? null : new Fr(BigInt(e.t)),
  };
}
