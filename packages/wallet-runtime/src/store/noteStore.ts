import { Fr } from "@aztec/foundation/fields";
import type { Note } from "@hisoka/wallets";
import type { DroppedNote } from "@hisoka/pss-client";
import type { BlockId } from "../chain/rpc.js";
import { describeCause, WalletRuntimeError } from "../errors.js";
import type { RuntimeStore } from "./runtimeStore.js";

export type NoteOrigin = "self" | "incoming";
export type NoteVerification = "verified" | "unverified";

/**
 * One note this wallet owns. Identity is `(leafIndex, commitment)`: after a reorg the same leaf index can hold
 * a different leaf, so the index alone does not name a note.
 */
export interface StoredNote {
  readonly leafIndex: number;
  readonly commitment: Fr;
  readonly note: Note;
  readonly nullifier: Fr;
  readonly origin: NoteOrigin;
  /** Self ephemeral index, or the incoming address index. */
  readonly derivationIndex: number;
  /** Compliance epoch that opened a self note; null for an incoming note. */
  readonly complianceVersion: number | null;
  /** Inclusion block. */
  readonly block: BlockId;
  readonly verification: NoteVerification;
  readonly spent: null | { readonly block: BlockId; readonly txHash: string };
  /** Written to PSS at least once, so dropping it must leave a tombstone there. */
  readonly mirrored: boolean;
}

export type PlanStatus =
  | "assembling"
  | "proving"
  | "submitted"
  | "included"
  | "reverted"
  | "orphaned"
  | "failed";

/** One user action and the notes it holds. */
export interface PlanRecord {
  readonly planId: string;
  readonly status: PlanStatus;
  /** Keys of the notes this plan leases (inputs and, on the Nox path, the fee note). */
  readonly leased: readonly string[];
  /** Chain time after which the lease no longer holds the notes. */
  readonly leaseUntil: bigint;
  readonly submission: null | {
    readonly txHash: string;
    readonly block: BlockId | null;
  };
  /** Nox `executionId` and `validUntilUnix` of an `unknown` paid result, kept so a retry resumes. */
  readonly resume: null | {
    readonly executionId: string;
    readonly validUntilUnix: bigint;
  };
}

export type NoteState =
  | "pending"
  | "spendable"
  | "spent-pending"
  | "spent"
  | "unverified";

/** What the chain says about how far the wallet's view reaches. */
export interface NoteView {
  /** `confirmedHead(spendableNotes).number`. */
  readonly confirmedHead: number;
  /** The whole-set nullifier sweep has covered every block up to this one. */
  readonly sweptThrough: number;
  /** Chain time, for lease expiry. */
  readonly now: bigint;
}

const LIVE: ReadonlySet<PlanStatus> = new Set([
  "assembling",
  "proving",
  "submitted",
]);

export function noteKey(note: {
  readonly leafIndex: number;
  readonly commitment: Fr;
}): string {
  return `${note.leafIndex}:${note.commitment.toString()}`;
}

interface State {
  readonly notes: readonly StoredNote[];
  readonly plans: readonly PlanRecord[];
  /** The discovery head every stored note was found against; null before the first sync. */
  readonly cursor: BlockId | null;
  readonly sweptThrough: number;
  /** Notes a rollback dropped after they reached PSS; the next mirror write tombstones them. */
  readonly pendingTombstones: readonly DroppedNote[];
}

const EMPTY: State = {
  notes: [],
  plans: [],
  cursor: null,
  sweptThrough: -1,
  pendingTombstones: [],
};

/** What one rollback changed, for the caller's re-sync and for tests. */
export interface RollbackResult {
  readonly droppedNotes: readonly StoredNote[];
  readonly unspent: readonly StoredNote[];
  readonly orphanedPlans: readonly string[];
}

/**
 * The wallet's durable note set, its leases and its plan journal, kept as ONE document under one key so every
 * change, a reorg rollback included, lands in a single atomic write: a crash can never leave the notes rolled
 * back while the plans still lease them, or the cursor moved past notes that were dropped.
 */
export class NoteStore {
  #state: State = EMPTY;
  #tail: Promise<void> = Promise.resolve();

  private constructor(
    private readonly store: RuntimeStore,
    private readonly key: string,
  ) {}

  /** `key` should come from `runtimeKey(deployment, accountTag, "notes")`. */
  static async open(store: RuntimeStore, key: string): Promise<NoteStore> {
    const notes = new NoteStore(store, key);
    const raw = await store.get(key);
    if (raw !== null) notes.#state = decodeState(raw, key);
    return notes;
  }

  get notes(): readonly StoredNote[] {
    return this.#state.notes;
  }

  get plans(): readonly PlanRecord[] {
    return this.#state.plans;
  }

  get cursor(): BlockId | null {
    return this.#state.cursor;
  }

  get sweptThrough(): number {
    return this.#state.sweptThrough;
  }

  get pendingTombstones(): readonly DroppedNote[] {
    return this.#state.pendingTombstones;
  }

  find(key: string): StoredNote | undefined {
    return this.#state.notes.find((n) => noteKey(n) === key);
  }

  state(note: StoredNote, view: NoteView): NoteState {
    if (note.verification === "unverified") return "unverified";
    if (note.spent !== null) {
      return note.spent.block.number <= view.confirmedHead
        ? "spent"
        : "spent-pending";
    }
    if (this.#leasedBy(noteKey(note), view.now) !== null)
      return "spent-pending";
    if (
      note.block.number > view.confirmedHead ||
      note.block.number > view.sweptThrough
    ) {
      return "pending";
    }
    return "spendable";
  }

  spendable(view: NoteView): readonly StoredNote[] {
    return this.#state.notes.filter((n) => this.state(n, view) === "spendable");
  }

  /**
   * Adds notes and, when discovery found them, advances its cursor in the same write. A known note is
   * updated in place and keeps its spent mark and mirror flag.
   */
  async record(
    found: readonly StoredNote[],
    cursor: BlockId | null,
  ): Promise<void> {
    await this.#commit((s) => {
      const byKey = new Map(s.notes.map((n) => [noteKey(n), n]));
      for (const note of found) {
        const known = byKey.get(noteKey(note));
        byKey.set(
          noteKey(note),
          known === undefined
            ? note
            : {
                ...note,
                spent: known.spent,
                mirrored: known.mirrored,
                verification:
                  known.verification === "verified"
                    ? "verified"
                    : note.verification,
              },
        );
      }
      return {
        ...s,
        notes: sortNotes([...byKey.values()]),
        cursor: cursor ?? s.cursor,
      };
    });
  }

  /** Applies a whole-set nullifier sweep through `throughBlock`. */
  async markSpent(
    spends: readonly {
      readonly nullifier: Fr;
      readonly block: BlockId;
      readonly txHash: string;
    }[],
    throughBlock: number,
  ): Promise<void> {
    const byNullifier = new Map(spends.map((s) => [s.nullifier.toString(), s]));
    await this.#commit((s) => ({
      ...s,
      notes: s.notes.map((n) => {
        const spend = byNullifier.get(n.nullifier.toString());
        if (spend === undefined || n.spent !== null) return n;
        return { ...n, spent: { block: spend.block, txHash: spend.txHash } };
      }),
      sweptThrough: Math.max(s.sweptThrough, throughBlock),
    }));
  }

  async setVerification(
    key: string,
    verification: NoteVerification,
  ): Promise<void> {
    await this.#commit((s) => ({
      ...s,
      notes: s.notes.map((n) =>
        noteKey(n) === key ? { ...n, verification } : n,
      ),
    }));
  }

  /** Records that these notes reached PSS and that the pending tombstones were written beside them. */
  async markMirrored(
    keys: readonly string[],
    tombstonesWritten: readonly DroppedNote[],
  ): Promise<void> {
    const mirrored = new Set(keys);
    const written = new Set(tombstonesWritten.map(tombstoneKey));
    await this.#commit((s) => ({
      ...s,
      notes: s.notes.map((n) =>
        mirrored.has(noteKey(n)) ? { ...n, mirrored: true } : n,
      ),
      pendingTombstones: s.pendingTombstones.filter(
        (t) => !written.has(tombstoneKey(t)),
      ),
    }));
  }

  /**
   * Drops a note (when `key` names one) and queues a tombstone, so a stale device cannot write a hint the
   * chain does not back into PSS again.
   */
  async discard(
    key: string | null,
    tombstone: DroppedNote | null,
  ): Promise<void> {
    await this.#commit((s) => ({
      ...s,
      notes: key === null ? s.notes : s.notes.filter((n) => noteKey(n) !== key),
      pendingTombstones:
        tombstone === null
          ? s.pendingTombstones
          : [...s.pendingTombstones, tombstone],
    }));
  }

  /**
   * Leases `keys` for `planId` until chain time `leaseUntil`. Fails `LEASE_HELD` when any key is held by another
   * live plan whose lease has not expired; nothing is leased then.
   */
  async acquire(
    planId: string,
    keys: readonly string[],
    leaseUntil: bigint,
    now: bigint,
  ): Promise<void> {
    await this.#commit((s) => {
      for (const key of keys) {
        const holder = leaseHolder(s, key, now);
        if (holder !== null && holder !== planId) {
          throw new WalletRuntimeError(
            "LEASE_HELD",
            `note ${key} is leased by plan ${holder} until its lease expires`,
            { leafIndex: key.split(":")[0] ?? key, planId: holder },
          );
        }
      }
      const existing = s.plans.find((p) => p.planId === planId);
      const plan: PlanRecord =
        existing === undefined
          ? {
              planId,
              status: "assembling",
              leased: [...keys],
              leaseUntil,
              submission: null,
              resume: null,
            }
          : {
              ...existing,
              leased: [...new Set([...existing.leased, ...keys])],
              leaseUntil,
            };
      return {
        ...s,
        plans: [...s.plans.filter((p) => p.planId !== planId), plan],
      };
    });
  }

  async updatePlan(
    planId: string,
    change: (plan: PlanRecord) => PlanRecord,
  ): Promise<PlanRecord> {
    return this.#commitWith((s) => {
      const plan = s.plans.find((p) => p.planId === planId);
      if (plan === undefined) {
        throw new WalletRuntimeError(
          "PLAN_UNKNOWN",
          `plan ${planId} is not in the journal`,
          { planId },
        );
      }
      const updated = change(plan);
      return {
        state: {
          ...s,
          plans: s.plans.map((p) => (p.planId === planId ? updated : p)),
        },
        value: updated,
      };
    });
  }

  /**
   * Undoes everything above `ancestor` in ONE write: notes included above it or at a leaf index the
   * discovery source dropped are deleted, spent marks above it are cleared, plans whose submission landed
   * above it become `orphaned` and release their notes, and the cursor and sweep move back to it. Dropped
   * notes that reached PSS are queued as tombstones in the same write. A null `ancestor` (a reorg deeper
   * than the walk-back, re-indexed from the deployment block) undoes everything.
   */
  async rollback(
    ancestor: BlockId | null,
    rewoundTo: number,
  ): Promise<RollbackResult> {
    const above = ancestor === null ? -1 : ancestor.number;
    return this.#commitWith((s) => {
      const dropped: StoredNote[] = [];
      const unspent: StoredNote[] = [];
      const notes: StoredNote[] = [];
      for (const n of s.notes) {
        if (n.block.number > above || n.leafIndex >= rewoundTo) {
          dropped.push(n);
          continue;
        }
        if (n.spent !== null && n.spent.block.number > above) {
          unspent.push(n);
          notes.push({ ...n, spent: null });
          continue;
        }
        notes.push(n);
      }
      const orphanedPlans: string[] = [];
      const plans = s.plans.map((p) => {
        const landed = p.submission?.block ?? null;
        if (
          landed !== null &&
          landed.number > above &&
          (p.status === "included" || p.status === "submitted")
        ) {
          orphanedPlans.push(p.planId);
          return { ...p, status: "orphaned" as const, leased: [] };
        }
        return p;
      });
      const tombstones = dropped
        .filter((n) => n.mirrored)
        .map(
          (n): DroppedNote => ({
            leafIndex: n.leafIndex,
            nullifier: nullifierHex(n.nullifier),
            block: n.block.number,
            blockHash: n.block.hash,
          }),
        );
      const cursor =
        s.cursor === null || s.cursor.number <= above ? s.cursor : ancestor;
      return {
        state: {
          notes,
          plans,
          cursor,
          sweptThrough: Math.min(s.sweptThrough, above),
          pendingTombstones: [...s.pendingTombstones, ...tombstones],
        },
        value: { droppedNotes: dropped, unspent, orphanedPlans },
      };
    });
  }

  #leasedBy(key: string, now: bigint): string | null {
    return leaseHolder(this.#state, key, now);
  }

  /** Serialises every change and resolves only once the new document is durable. */
  #commit(change: (s: State) => State): Promise<void> {
    return this.#commitWith((s) => ({ state: change(s), value: undefined }));
  }

  #commitWith<T>(
    change: (s: State) => { readonly state: State; readonly value: T },
  ): Promise<T> {
    const run = this.#tail.then(async () => {
      const next = change(this.#state);
      await this.store.set(this.key, encodeState(next.state));
      this.#state = next.state;
      return next.value;
    });
    this.#tail = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }
}

function leaseHolder(s: State, key: string, now: bigint): string | null {
  for (const plan of s.plans) {
    if (!LIVE.has(plan.status)) continue;
    if (plan.status !== "submitted" && plan.leaseUntil < now) continue;
    if (plan.leased.includes(key)) return plan.planId;
  }
  return null;
}

function sortNotes(notes: StoredNote[]): StoredNote[] {
  return notes.sort(
    (a, b) =>
      a.leafIndex - b.leafIndex ||
      (a.commitment.toString() < b.commitment.toString() ? -1 : 1),
  );
}

export function nullifierHex(nullifier: Fr): string {
  return `0x${nullifier.toBigInt().toString(16).padStart(64, "0")}`;
}

export function tombstoneKey(t: {
  readonly leafIndex: number;
  readonly nullifier: string;
  readonly blockHash: string;
}): string {
  return `${t.leafIndex}:${t.nullifier}:${t.blockHash}`;
}

const STATE_VERSION = 1;

function blockJson(b: BlockId): BlockId {
  return { number: b.number, hash: b.hash };
}

function encodeState(s: State): string {
  return JSON.stringify({
    v: STATE_VERSION,
    notes: s.notes.map((n) => ({
      leafIndex: n.leafIndex,
      commitment: n.commitment.toString(),
      note: {
        noteVersion: n.note.noteVersion.toString(),
        assetId: n.note.assetId.toString(),
        noteType: n.note.noteType.toString(),
        conditionsHash: n.note.conditionsHash.toString(),
        value: n.note.value.toString(),
        owner: n.note.owner.toString(),
        psi: n.note.psi.toString(),
        parents: n.note.parents.toString(),
      },
      nullifier: n.nullifier.toString(),
      origin: n.origin,
      derivationIndex: n.derivationIndex,
      complianceVersion: n.complianceVersion,
      block: blockJson(n.block),
      verification: n.verification,
      spent:
        n.spent === null
          ? null
          : { block: blockJson(n.spent.block), txHash: n.spent.txHash },
      mirrored: n.mirrored,
    })),
    plans: s.plans.map((p) => ({
      ...p,
      leaseUntil: p.leaseUntil.toString(),
      submission:
        p.submission === null
          ? null
          : {
              txHash: p.submission.txHash,
              block:
                p.submission.block === null
                  ? null
                  : blockJson(p.submission.block),
            },
      resume:
        p.resume === null
          ? null
          : {
              executionId: p.resume.executionId,
              validUntilUnix: p.resume.validUntilUnix.toString(),
            },
    })),
    cursor: s.cursor === null ? null : blockJson(s.cursor),
    sweptThrough: s.sweptThrough,
    pendingTombstones: s.pendingTombstones,
  });
}

type Json = Record<string, unknown>;

function obj(value: unknown, what: string): Json {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${what} is not an object`);
  }
  return value as Json;
}

function arr(value: unknown, what: string): unknown[] {
  if (!Array.isArray(value)) throw new Error(`${what} is not an array`);
  return value;
}

function int(value: unknown, what: string, min = 0): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < min)
    throw new Error(`${what} is not an integer`);
  return value;
}

function str(value: unknown, what: string): string {
  if (typeof value !== "string") throw new Error(`${what} is not a string`);
  return value;
}

function big(value: unknown, what: string): bigint {
  if (typeof value !== "string" || !/^\d+$/.test(value))
    throw new Error(`${what} is not a decimal integer`);
  return BigInt(value);
}

function fr(value: unknown, what: string): Fr {
  return new Fr(BigInt(str(value, what)));
}

function block(value: unknown, what: string): BlockId {
  const b = obj(value, what);
  return {
    number: int(b.number, `${what}.number`),
    hash: str(b.hash, `${what}.hash`),
  };
}

const PLAN_STATUSES: ReadonlySet<string> = new Set([
  "assembling",
  "proving",
  "submitted",
  "included",
  "reverted",
  "orphaned",
  "failed",
]);

/**
 * The document is this device's own durable state, so a parse failure is corruption, not an attack: it fails
 * loud rather than silently starting empty and re-offering leased notes.
 */
function decodeState(raw: string, key: string): State {
  try {
    const s = obj(JSON.parse(raw), "note store");
    if (s.v !== STATE_VERSION) throw new Error(`version ${String(s.v)}`);
    return {
      notes: arr(s.notes, "notes").map((value, i) => {
        const n = obj(value, `notes[${i}]`);
        const note = obj(n.note, `notes[${i}].note`);
        const origin = str(n.origin, "origin");
        if (origin !== "self" && origin !== "incoming")
          throw new Error(`notes[${i}].origin ${origin}`);
        const verification = str(n.verification, "verification");
        if (verification !== "verified" && verification !== "unverified")
          throw new Error(`notes[${i}].verification ${verification}`);
        const spent = n.spent === null ? null : obj(n.spent, "spent");
        return {
          leafIndex: int(n.leafIndex, "leafIndex"),
          commitment: fr(n.commitment, "commitment"),
          note: {
            noteVersion: fr(note.noteVersion, "noteVersion"),
            assetId: fr(note.assetId, "assetId"),
            noteType: fr(note.noteType, "noteType"),
            conditionsHash: fr(note.conditionsHash, "conditionsHash"),
            value: big(note.value, "value"),
            owner: fr(note.owner, "owner"),
            psi: fr(note.psi, "psi"),
            parents: fr(note.parents, "parents"),
          },
          nullifier: fr(n.nullifier, "nullifier"),
          origin,
          derivationIndex: int(n.derivationIndex, "derivationIndex"),
          complianceVersion:
            n.complianceVersion === null
              ? null
              : int(n.complianceVersion, "complianceVersion", 1),
          block: block(n.block, "block"),
          verification,
          spent:
            spent === null
              ? null
              : {
                  block: block(spent.block, "spent.block"),
                  txHash: str(spent.txHash, "spent.txHash"),
                },
          mirrored: n.mirrored === true,
        };
      }),
      plans: arr(s.plans, "plans").map((value, i) => {
        const p = obj(value, `plans[${i}]`);
        const status = str(p.status, "status");
        if (!PLAN_STATUSES.has(status))
          throw new Error(`plans[${i}].status ${status}`);
        const submission =
          p.submission === null ? null : obj(p.submission, "submission");
        const resume = p.resume === null ? null : obj(p.resume, "resume");
        return {
          planId: str(p.planId, "planId"),
          status: status as PlanStatus,
          leased: arr(p.leased, "leased").map((k) => str(k, "leased[]")),
          leaseUntil: big(p.leaseUntil, "leaseUntil"),
          submission:
            submission === null
              ? null
              : {
                  txHash: str(submission.txHash, "submission.txHash"),
                  block:
                    submission.block === null
                      ? null
                      : block(submission.block, "submission.block"),
                },
          resume:
            resume === null
              ? null
              : {
                  executionId: str(resume.executionId, "resume.executionId"),
                  validUntilUnix: big(
                    resume.validUntilUnix,
                    "resume.validUntilUnix",
                  ),
                },
        };
      }),
      cursor: s.cursor === null ? null : block(s.cursor, "cursor"),
      sweptThrough: int(s.sweptThrough, "sweptThrough", -1),
      pendingTombstones: arr(s.pendingTombstones, "pendingTombstones").map(
        (value, i) => {
          const t = obj(value, `pendingTombstones[${i}]`);
          return {
            leafIndex: int(t.leafIndex, "leafIndex"),
            nullifier: str(t.nullifier, "nullifier"),
            block: int(t.block, "block"),
            blockHash: str(t.blockHash, "blockHash"),
          };
        },
      ),
    };
  } catch (cause) {
    throw new WalletRuntimeError(
      "STORE_CORRUPT",
      `the stored note set under ${key} does not parse; it is this device's own state, so it is not replaced: ${describeCause(cause)}`,
      { key },
      cause,
    );
  }
}
