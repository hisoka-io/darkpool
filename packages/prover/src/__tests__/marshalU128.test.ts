import { describe, it, expect } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import { marshalU128 } from "../marshal.js";
import { ProofInputError } from "../errors.js";

const U128_MAX = (1n << 128n) - 1n;

// withdraw_value and from_amount are u128 in-circuit but were marshaled with a bare .toString(), so an
// out-of-range value surfaced as an opaque witness-generation abort instead of a named input error. The
// circuit is what enforces the bound; this is the boundary that says which field was wrong.
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
