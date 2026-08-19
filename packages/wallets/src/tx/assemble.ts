/**
 * Transaction assembly: turn a spendable note plus an intent into the witness a prover consumes.
 *
 * These functions do NOT prove and do NOT submit. For a shielded action the entrypoint's calldata IS the
 * proof, so nothing downstream of proving can be prepared in advance; the honest seam is the witness.
 *
 * Every circuit invariant below is computed here and never accepted as a parameter. That is deliberate: the
 * deleted MixnetWallet passed real packed parents where transfer demands PARENTS_HIDDEN, and picked join
 * inputs in arbitrary order where the circuit asserts ascending index. Both were unreachable through this
 * surface by construction.
 */
import { Fr } from "@aztec/foundation/fields";
import { Point } from "@zk-kit/baby-jubjub";
import type { DerivedEph } from "../types/ephemeral.js";
import { toFr } from "../crypto/fields.js";
import { packParents, PARENTS_HIDDEN } from "../note/note.js";
import {
  mintSelfNote,
  mintIncomingNote,
  type MintedNote,
} from "../note/mint.js";
import type { ProverNoteInput } from "../public/publicClaim.js";
import type { MerkleWitnessSource } from "./ports.js";

/** A note the wallet holds and can spend, with everything needed to open it. */
export interface SpendableNote {
  readonly note: ProverNoteInput;
  readonly leaf: Fr;
  readonly leafIndex: number;
  /**
   * Opens THIS note, and only this note. For a self note it is the wallet's self-spend key; for a note
   * received from someone else it is the per-address incoming key `in_key_j`. It is NOT the key that should
   * own the outputs: see `selfSpendScalar` on every request below.
   */
  readonly spendScalar: Fr;
}

export interface AssemblyContext {
  readonly compliancePk: Point<bigint>;
  readonly merkle: MerkleWitnessSource;
}

export class AssemblyError extends Error {
  constructor(
    readonly reason: string,
    message: string,
  ) {
    super(message);
    this.name = "AssemblyError";
  }
}

/** Recompute the root from the returned witness and refuse to build on one that does not reproduce it. */
async function openSpend(ctx: AssemblyContext, input: SpendableNote) {
  const w = await ctx.merkle.witnessFor(input.leaf);
  if (w.leafIndex !== input.leafIndex) {
    throw new AssemblyError(
      "MERKLE_INDEX_MISMATCH",
      `merkle source placed the note at index ${w.leafIndex}, wallet has ${input.leafIndex}`,
    );
  }
  return { index: w.leafIndex, path: [...w.siblings], root: w.root };
}

function assertPositive(value: bigint, what: string): void {
  if (value < 0n) {
    throw new AssemblyError(
      "NEGATIVE_VALUE",
      `${what} would be negative (${value})`,
    );
  }
}

export interface AssembledDeposit {
  readonly inputs: {
    compliancePk: Point<bigint>;
    note: ProverNoteInput;
    eph: DerivedEph;
  };
  readonly minted: MintedNote;
}

/** Deposit mints a self note for `value`; the pool pulls the ERC20 against the public inputs. */
export async function assembleDeposit(
  ctx: AssemblyContext,
  req: {
    readonly value: bigint;
    readonly assetId: Fr;
    readonly spendScalar: Fr;
    readonly eph: DerivedEph;
  },
): Promise<AssembledDeposit> {
  assertPositive(req.value, "deposit value");
  const minted = await mintSelfNote(
    req.eph,
    req.value,
    req.spendScalar,
    req.assetId,
    ctx.compliancePk,
  );
  return {
    inputs: { compliancePk: ctx.compliancePk, note: minted.note, eph: req.eph },
    minted,
  };
}

export interface AssembledWithdraw {
  readonly inputs: Record<string, unknown>;
  readonly change: MintedNote;
  readonly root: Fr;
}

/** withdraw: ONE note in, value out to `recipient`, remainder back as a self note. */
export async function assembleWithdraw(
  ctx: AssemblyContext,
  req: {
    readonly input: SpendableNote;
    readonly value: bigint;
    readonly recipient: Fr;
    /** Owns the CHANGE. Distinct from `input.spendScalar` whenever the input was received from someone else. */
    readonly selfSpendScalar: Fr;
    readonly changeEph: DerivedEph;
    readonly intentHash?: Fr;
  },
): Promise<AssembledWithdraw> {
  const spend = await openSpend(ctx, req.input);
  const changeValue = req.input.note.value.toBigInt() - req.value;
  assertPositive(changeValue, "withdraw change");

  const change = await mintSelfNote(
    req.changeEph,
    changeValue,
    req.selfSpendScalar,
    req.input.note.assetId,
    ctx.compliancePk,
    // Change is bound to the consumed note; the second slot is unused for a 1-in spend.
    packParents([{ leafIndex: spend.index }, { leafIndex: 0 }]),
  );

  return {
    inputs: {
      withdrawValue: toFr(req.value),
      recipient: req.recipient,
      intentHash: req.intentHash ?? toFr(0n),
      compliancePk: ctx.compliancePk,
      oldNote: req.input.note,
      spendScalar: req.input.spendScalar,
      oldNoteIndex: spend.index,
      oldNotePath: spend.path,
      changeNote: change.note,
      changeEph: req.changeEph,
    },
    change,
    root: spend.root,
  };
}

export interface AssembledTransfer {
  readonly inputs: Record<string, unknown>;
  readonly memo: MintedNote;
  readonly change: MintedNote;
  readonly root: Fr;
}

/**
 * transfer: ONE note in, a memo to the recipient plus change back.
 *
 * The memo's parents are forced to PARENTS_HIDDEN here. The circuit asserts it, and it is what hides the
 * sender's leaf index from the recipient; a caller must not be able to pass anything else.
 */
export async function assembleTransfer(
  ctx: AssemblyContext,
  req: {
    readonly input: SpendableNote;
    readonly value: bigint;
    readonly recipientInPub: Point<bigint>;
    readonly recipientInKey: Fr;
    /** Owns the CHANGE, never the input's key. Spending a received note is the case that separates them. */
    readonly selfSpendScalar: Fr;
    readonly memoEph: Fr;
    readonly changeEph: DerivedEph;
  },
): Promise<AssembledTransfer> {
  const spend = await openSpend(ctx, req.input);
  const changeValue = req.input.note.value.toBigInt() - req.value;
  assertPositive(changeValue, "transfer change");

  const memo = await mintIncomingNote(
    req.memoEph,
    req.value,
    req.recipientInPub,
    req.recipientInKey,
    req.input.note.assetId,
    ctx.compliancePk,
    PARENTS_HIDDEN,
  );
  const change = await mintSelfNote(
    req.changeEph,
    changeValue,
    req.selfSpendScalar,
    req.input.note.assetId,
    ctx.compliancePk,
    packParents([{ leafIndex: spend.index }, { leafIndex: 0 }]),
  );

  return {
    inputs: {
      compliancePk: ctx.compliancePk,
      recipientInPub: req.recipientInPub,
      oldNote: req.input.note,
      spendScalar: req.input.spendScalar,
      oldNoteIndex: spend.index,
      oldNotePath: spend.path,
      memoNote: memo.note,
      memoEph: req.memoEph,
      changeNote: change.note,
      changeEph: req.changeEph,
    },
    memo,
    change,
    root: spend.root,
  };
}

export interface AssembledSplit {
  readonly inputs: Record<string, unknown>;
  readonly out1: MintedNote;
  readonly out2: MintedNote;
  readonly root: Fr;
}

/** split: ONE note in, two self notes out. Both outputs carry the same asset; the circuit asserts it twice. */
export async function assembleSplit(
  ctx: AssemblyContext,
  req: {
    readonly input: SpendableNote;
    readonly value1: bigint;
    /** Owns BOTH outputs. */
    readonly selfSpendScalar: Fr;
    readonly eph1: DerivedEph;
    readonly eph2: DerivedEph;
  },
): Promise<AssembledSplit> {
  const spend = await openSpend(ctx, req.input);
  const value2 = req.input.note.value.toBigInt() - req.value1;
  assertPositive(req.value1, "split output 1");
  assertPositive(value2, "split output 2");
  if (req.eph1.equals(req.eph2)) {
    throw new AssemblyError(
      "EPHEMERAL_REUSE",
      "split outputs need distinct ephemerals; a shared one repeats the DEM keystream",
    );
  }

  const parents = packParents([{ leafIndex: spend.index }, { leafIndex: 0 }]);
  const out1 = await mintSelfNote(
    req.eph1,
    req.value1,
    req.selfSpendScalar,
    req.input.note.assetId,
    ctx.compliancePk,
    parents,
  );
  const out2 = await mintSelfNote(
    req.eph2,
    value2,
    req.selfSpendScalar,
    req.input.note.assetId,
    ctx.compliancePk,
    parents,
  );

  return {
    inputs: {
      compliancePk: ctx.compliancePk,
      noteIn: req.input.note,
      spendScalar: req.input.spendScalar,
      indexIn: spend.index,
      pathIn: spend.path,
      noteOut1: out1.note,
      eph1: req.eph1,
      noteOut2: out2.note,
      eph2: req.eph2,
    },
    out1,
    out2,
    root: spend.root,
  };
}

export interface AssembledJoin {
  readonly inputs: Record<string, unknown>;
  readonly out: MintedNote;
  readonly root: Fr;
}

/**
 * join: TWO notes in, one out. The pair is sorted here by leaf index, because the circuit asserts
 * `index_a < index_b` and `pack_parents` is positional, so a caller-supplied order is a footgun.
 */
export async function assembleJoin(
  ctx: AssemblyContext,
  req: {
    readonly inputA: SpendableNote;
    readonly inputB: SpendableNote;
    /** Owns the merged output. The two inputs may open with different keys; the output has one owner. */
    readonly selfSpendScalar: Fr;
    readonly ephOut: DerivedEph;
  },
): Promise<AssembledJoin> {
  if (req.inputA.leafIndex === req.inputB.leafIndex) {
    throw new AssemblyError(
      "JOIN_SELF",
      "cannot join a note with itself; the two inputs must be distinct leaves",
    );
  }
  const [lo, hi] =
    req.inputA.leafIndex < req.inputB.leafIndex
      ? ([req.inputA, req.inputB] as const)
      : ([req.inputB, req.inputA] as const);

  if (!lo.note.assetId.equals(hi.note.assetId)) {
    throw new AssemblyError(
      "JOIN_ASSET_MISMATCH",
      "join inputs carry different assets; the circuit requires one asset",
    );
  }

  const a = await openSpend(ctx, lo);
  const b = await openSpend(ctx, hi);
  if (!a.root.equals(b.root)) {
    throw new AssemblyError(
      "JOIN_ROOT_MISMATCH",
      "join inputs opened against different roots; both must prove against one root",
    );
  }

  const total = lo.note.value.toBigInt() + hi.note.value.toBigInt();
  const out = await mintSelfNote(
    req.ephOut,
    total,
    req.selfSpendScalar,
    lo.note.assetId,
    ctx.compliancePk,
    packParents([{ leafIndex: a.index }, { leafIndex: b.index }]),
  );

  return {
    inputs: {
      compliancePk: ctx.compliancePk,
      noteA: lo.note,
      spendScalarA: lo.spendScalar,
      indexA: a.index,
      pathA: a.path,
      noteB: hi.note,
      spendScalarB: hi.spendScalar,
      indexB: b.index,
      pathB: b.path,
      noteOut: out.note,
      ephOut: req.ephOut,
    },
    out,
    root: a.root,
  };
}
