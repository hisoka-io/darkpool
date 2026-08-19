/**
 * Transaction planning.
 *
 * This file is PURE on purpose: no chain reads, no Merkle paths, no proving, no storage, no clock. It is a
 * total function of an explicit snapshot, which is what lets it run unchanged in a browser, an MV3 service
 * worker, a mobile app and a relayer, and what lets the Rust client mirror it exactly.
 *
 * WHY A PLANNER AND NOT A SELECTOR. The circuits fix the arity: withdraw and transfer each consume ONE note,
 * split is 1-in-2-out, join is 2-in-1-out. So a target larger than the biggest single note cannot be met by
 * any choice of inputs; it requires consolidating on chain first. A function that returns "the notes to
 * spend" cannot express that, which is why the old helper simply threw `Insufficient funds`.
 */

/** A note as the planner sees it. Deliberately the minimum: no keys, no paths, no ciphertext. */
export interface PlannableNote {
  readonly leafIndex: number;
  readonly assetId: string;
  readonly value: bigint;
}

export type PlanOp = "JOIN" | "WITHDRAW" | "TRANSFER" | "SPLIT";

export interface PlanStep {
  readonly op: PlanOp;
  /** Leaf indexes consumed by this step, in the order the circuit requires (join is ascending). */
  readonly inputs: readonly number[];
  /** Value leaving the pool (WITHDRAW) or moving to the counterparty (TRANSFER). Zero for JOIN/SPLIT. */
  readonly outgoing: bigint;
  /** Value returning to the spender as change, including a JOIN's merged output. */
  readonly change: bigint;
}

export interface ActionPlan {
  readonly steps: readonly PlanStep[];
  /** Steps beyond the first are consolidation forced by arity, not by choice. */
  readonly joinsRequired: number;
  readonly totalSelected: bigint;
}

export interface PlanPolicy {
  /**
   * Change below this is not worth its own note: it costs a future join to ever spend, and a long tail of
   * tiny notes is itself a fingerprint. A candidate whose change would land in (0, dustFloor) loses to any
   * candidate that avoids it.
   */
  readonly dustFloor: bigint;
  /** Refuse to plan beyond this many on-chain steps rather than quietly proposing twenty transactions. */
  readonly maxSteps: number;
}

export const DEFAULT_PLAN_POLICY: PlanPolicy = {
  dustFloor: 0n,
  maxSteps: 8,
};

export type PlanFailureReason =
  | "NO_NOTES_FOR_ASSET"
  | "INSUFFICIENT_TOTAL"
  | "EXCEEDS_MAX_STEPS"
  | "NON_POSITIVE_TARGET";

export class PlanError extends Error {
  constructor(
    readonly reason: PlanFailureReason,
    message: string,
    readonly detail: Readonly<Record<string, string>> = {},
  ) {
    super(message);
    this.name = "PlanError";
  }
}

function forAsset(
  notes: readonly PlannableNote[],
  assetId: string,
): PlannableNote[] {
  return notes
    .filter((n) => n.assetId === assetId && n.value > 0n)
    .sort((a, b) =>
      a.value === b.value
        ? a.leafIndex - b.leafIndex
        : a.value < b.value
          ? -1
          : 1,
    );
}

/** Join consumes two notes and asserts ascending leaf index, so the pair order is not the caller's choice. */
function joinStep(a: PlannableNote, b: PlannableNote): PlanStep {
  const [lo, hi] =
    a.leafIndex < b.leafIndex ? ([a, b] as const) : ([b, a] as const);
  return {
    op: "JOIN",
    inputs: [lo.leafIndex, hi.leafIndex],
    outgoing: 0n,
    change: lo.value + hi.value,
  };
}

/**
 * Best fit with a dust guard: the SMALLEST note that covers the target, except that a note whose change
 * would be dust loses to any larger note that avoids dust. Largest-first is rejected because it shreds big
 * notes and leaks a coarse balance signal; first-fit is rejected because it is order-dependent.
 *
 * Deterministic by design. Randomising the pick would make two devices holding one seed disagree, and the
 * observable worth randomising is consolidation TIMING, not selection.
 */
function bestFit(
  sorted: readonly PlannableNote[],
  target: bigint,
  policy: PlanPolicy,
): PlannableNote | null {
  let dusty: PlannableNote | null = null;
  for (const n of sorted) {
    if (n.value < target) continue;
    const change = n.value - target;
    if (change > 0n && change < policy.dustFloor) {
      dusty ??= n;
      continue;
    }
    return n;
  }
  return dusty;
}

/**
 * Minimal covering subset, then the SMALLEST covering sum at that size.
 *
 * Taking the k largest tells us how few notes can possibly cover the target. Holding k fixed and minimising
 * the sum then leaves the big notes intact and keeps change small, which is both better for future
 * spendability and less informative to an observer than always consuming the largest holdings.
 */
function minimalCover(
  sorted: readonly PlannableNote[],
  target: bigint,
): PlannableNote[] | null {
  const desc = [...sorted].reverse();
  let k = 0;
  let sum = 0n;
  while (k < desc.length && sum < target) {
    sum += desc[k]!.value;
    k += 1;
  }
  if (sum < target) return null;

  // Smallest k-subset that still covers: walk the ascending list with a sliding window of size k.
  let best: PlannableNote[] | null = null;
  let bestSum: bigint | null = null;
  for (let start = 0; start + k <= sorted.length; start++) {
    const window = sorted.slice(start, start + k);
    const wsum = window.reduce((acc, n) => acc + n.value, 0n);
    if (wsum >= target && (bestSum === null || wsum < bestSum)) {
      best = window;
      bestSum = wsum;
    }
  }
  return best ?? desc.slice(0, k);
}

/**
 * Plan a spend of `target` of `assetId`, either out of the pool (WITHDRAW) or to a counterparty (TRANSFER).
 *
 * Returns the ordered steps. When one note suffices the plan is a single step; otherwise it is `k-1` joins
 * followed by the spend, because that is the only shape the circuits permit.
 */
export function planSpend(
  notes: readonly PlannableNote[],
  intent: {
    readonly op: "WITHDRAW" | "TRANSFER";
    readonly assetId: string;
    readonly target: bigint;
  },
  policy: PlanPolicy = DEFAULT_PLAN_POLICY,
): ActionPlan {
  if (intent.target <= 0n) {
    throw new PlanError(
      "NON_POSITIVE_TARGET",
      `cannot plan a spend of ${intent.target}; target must be positive`,
      { target: intent.target.toString() },
    );
  }

  const candidates = forAsset(notes, intent.assetId);
  if (candidates.length === 0) {
    throw new PlanError(
      "NO_NOTES_FOR_ASSET",
      `no spendable notes for asset ${intent.assetId}`,
      { assetId: intent.assetId },
    );
  }

  const single = bestFit(candidates, intent.target, policy);
  if (single !== null) {
    return {
      steps: [
        {
          op: intent.op,
          inputs: [single.leafIndex],
          outgoing: intent.target,
          change: single.value - intent.target,
        },
      ],
      joinsRequired: 0,
      totalSelected: single.value,
    };
  }

  const cover = minimalCover(candidates, intent.target);
  if (cover === null) {
    const total = candidates.reduce((a, n) => a + n.value, 0n);
    throw new PlanError(
      "INSUFFICIENT_TOTAL",
      `holding ${total} of asset ${intent.assetId}, need ${intent.target}`,
      { held: total.toString(), needed: intent.target.toString() },
    );
  }

  const joins = cover.length - 1;
  const steps: PlanStep[] = [];
  // Join ascending by leaf index so each merge is itself arity-legal, folding left into a running total.
  const ordered = [...cover].sort((a, b) => a.leafIndex - b.leafIndex);
  let merged = ordered[0]!;
  for (let i = 1; i < ordered.length; i++) {
    const step = joinStep(merged, ordered[i]!);
    steps.push(step);
    // The merged output is a NEW leaf whose index is not known until the join lands, so downstream steps
    // reference it positionally. `-1` marks "the output of the previous step", resolved at assembly time.
    merged = { leafIndex: -1, assetId: intent.assetId, value: step.change };
  }

  const totalSelected = cover.reduce((a, n) => a + n.value, 0n);
  steps.push({
    op: intent.op,
    inputs: [merged.leafIndex],
    outgoing: intent.target,
    change: totalSelected - intent.target,
  });

  if (steps.length > policy.maxSteps) {
    throw new PlanError(
      "EXCEEDS_MAX_STEPS",
      `plan needs ${steps.length} on-chain steps, above the ${policy.maxSteps} limit; consolidate first`,
      { steps: String(steps.length), limit: String(policy.maxSteps) },
    );
  }

  return { steps, joinsRequired: joins, totalSelected };
}

/**
 * What a user can actually spend, which is three different numbers.
 *
 * A wallet that shows only `total` and then fails at spend time is lying: arity means the largest single
 * note is the real one-transaction ceiling.
 */
export function spendableBalance(
  notes: readonly PlannableNote[],
  assetId: string,
  policy: PlanPolicy = DEFAULT_PLAN_POLICY,
): { total: bigint; inOneTx: bigint; withPlan: bigint } {
  const candidates = forAsset(notes, assetId);
  const total = candidates.reduce((a, n) => a + n.value, 0n);
  const inOneTx = candidates.reduce((a, n) => (n.value > a ? n.value : a), 0n);
  // Each join consumes two notes and yields one, so `maxSteps` steps can fold at most `maxSteps` notes.
  const foldable = [...candidates]
    .reverse()
    .slice(0, Math.max(1, policy.maxSteps))
    .reduce((a, n) => a + n.value, 0n);
  return { total, inOneTx, withPlan: foldable };
}
