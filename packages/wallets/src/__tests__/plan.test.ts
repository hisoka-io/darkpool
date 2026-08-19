import { describe, it, expect } from "vitest";
import {
  planSpend,
  spendableBalance,
  PlanError,
  DEFAULT_PLAN_POLICY,
  type PlannableNote,
} from "../tx/plan.js";

const A = "0xaaaa";
const B = "0xbbbb";
const note = (
  leafIndex: number,
  value: bigint,
  assetId = A,
): PlannableNote => ({
  leafIndex,
  assetId,
  value,
});

describe("planSpend", () => {
  it("uses one note when one suffices", () => {
    const plan = planSpend([note(1, 100n), note(2, 500n)], {
      op: "WITHDRAW",
      assetId: A,
      target: 80n,
    });
    expect(plan.joinsRequired).toBe(0);
    expect(plan.steps).toHaveLength(1);
    expect(plan.steps[0]!.inputs).toEqual([1]);
    expect(plan.steps[0]!.change).toBe(20n);
  });

  it("picks BEST fit, not first fit and not largest", () => {
    // 500 comes first in insertion order and 1000 is largest; 100 is the tightest cover.
    const plan = planSpend([note(1, 500n), note(2, 1000n), note(3, 100n)], {
      op: "WITHDRAW",
      assetId: A,
      target: 90n,
    });
    expect(plan.steps[0]!.inputs).toEqual([3]);
  });

  // The case the old TestWallet.pickNote could not express: it threw Insufficient funds while the wallet
  // demonstrably held enough. Arity, not balance, is what blocks the single transaction.
  it("plans joins when NO single note covers the target but the balance does", () => {
    const plan = planSpend([note(1, 40n), note(2, 40n), note(3, 40n)], {
      op: "WITHDRAW",
      assetId: A,
      target: 100n,
    });
    expect(plan.joinsRequired).toBe(2);
    expect(plan.steps.map((s) => s.op)).toEqual(["JOIN", "JOIN", "WITHDRAW"]);
    expect(plan.totalSelected).toBe(120n);
    expect(plan.steps.at(-1)!.change).toBe(20n);
  });

  it("orders every join pair ascending by leaf index, as the circuit asserts", () => {
    const plan = planSpend([note(9, 40n), note(2, 40n), note(5, 40n)], {
      op: "WITHDRAW",
      assetId: A,
      target: 100n,
    });
    for (const step of plan.steps) {
      if (step.op !== "JOIN") continue;
      const [a, b] = step.inputs;
      // -1 is the placeholder for the previous step's output, which has no index yet.
      if (a !== -1 && b !== -1) expect(a! < b!).toBe(true);
    }
  });

  it("avoids leaving dust when a non-dusty candidate exists", () => {
    const plan = planSpend(
      [note(1, 101n), note(2, 200n)],
      { op: "WITHDRAW", assetId: A, target: 100n },
      { ...DEFAULT_PLAN_POLICY, dustFloor: 10n },
    );
    // Best fit alone would take note 1 and strand 1 unit; the dust guard prefers note 2.
    expect(plan.steps[0]!.inputs).toEqual([2]);
    expect(plan.steps[0]!.change).toBe(100n);
  });

  it("still uses a dusty note when it is the only cover", () => {
    const plan = planSpend(
      [note(1, 101n)],
      { op: "WITHDRAW", assetId: A, target: 100n },
      { ...DEFAULT_PLAN_POLICY, dustFloor: 10n },
    );
    expect(plan.steps[0]!.inputs).toEqual([1]);
  });

  it("ignores notes of other assets", () => {
    expect(() =>
      planSpend([note(1, 1000n, B)], {
        op: "WITHDRAW",
        assetId: A,
        target: 10n,
      }),
    ).toThrow(PlanError);
  });

  it("fails CLOSED and names the shortfall", () => {
    try {
      planSpend([note(1, 10n), note(2, 20n)], {
        op: "WITHDRAW",
        assetId: A,
        target: 100n,
      });
      expect.unreachable("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(PlanError);
      const err = e as PlanError;
      expect(err.reason).toBe("INSUFFICIENT_TOTAL");
      expect(err.detail["held"]).toBe("30");
      expect(err.detail["needed"]).toBe("100");
    }
  });

  it("refuses to propose a plan longer than the step budget", () => {
    const many = Array.from({ length: 20 }, (_, i) => note(i + 1, 10n));
    try {
      planSpend(
        many,
        { op: "WITHDRAW", assetId: A, target: 195n },
        { dustFloor: 0n, maxSteps: 3 },
      );
      expect.unreachable("should have thrown");
    } catch (e) {
      expect((e as PlanError).reason).toBe("EXCEEDS_MAX_STEPS");
    }
  });

  it("rejects a non-positive target", () => {
    expect(() =>
      planSpend([note(1, 10n)], { op: "WITHDRAW", assetId: A, target: 0n }),
    ).toThrow(PlanError);
  });

  it("is deterministic: the same snapshot plans identically every time", () => {
    const notes = [note(3, 70n), note(1, 40n), note(2, 55n)];
    const a = planSpend(notes, { op: "TRANSFER", assetId: A, target: 90n });
    const b = planSpend([...notes].reverse(), {
      op: "TRANSFER",
      assetId: A,
      target: 90n,
    });
    expect(
      JSON.stringify(a, (_k, v) => (typeof v === "bigint" ? v.toString() : v)),
    ).toBe(
      JSON.stringify(b, (_k, v) => (typeof v === "bigint" ? v.toString() : v)),
    );
  });
});

describe("spendableBalance", () => {
  it("separates total from what one transaction can actually move", () => {
    const bal = spendableBalance([note(1, 40n), note(2, 40n), note(3, 40n)], A);
    expect(bal.total).toBe(120n);
    // Arity caps a single transaction at the largest single note, which is the number a naive wallet hides.
    expect(bal.inOneTx).toBe(40n);
    expect(bal.withPlan).toBe(120n);
  });

  it("reports zero for an asset it does not hold", () => {
    const bal = spendableBalance([note(1, 40n)], B);
    expect(bal.total).toBe(0n);
    expect(bal.inOneTx).toBe(0n);
  });
});
