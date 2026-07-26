import { describe, it, expect } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import { marshalU128 } from "../marshal.js";
import { ProofInputError } from "../errors.js";

const U128_MAX = (1n << 128n) - 1n;

describe("marshalU128", () => {
  it("accepts the u128 boundary", () => {
    expect(marshalU128("withdraw", "withdraw_value", new Fr(U128_MAX))).toBe(
      new Fr(U128_MAX).toString(),
    );
    expect(marshalU128("withdraw", "withdraw_value", new Fr(0n))).toBe(
      new Fr(0n).toString(),
    );
  });

  it("rejects one past the u128 boundary with a named, actionable error", () => {
    expect(() =>
      marshalU128("swap_intent", "from_amount", new Fr(U128_MAX + 1n)),
    ).toThrow(ProofInputError);
    expect(() =>
      marshalU128("swap_intent", "from_amount", new Fr(U128_MAX + 1n)),
    ).toThrow(/swap_intent.*from_amount exceeds u128 range/);
  });
});
