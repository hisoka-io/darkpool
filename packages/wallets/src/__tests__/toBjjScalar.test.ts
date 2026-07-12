import { describe, it, expect } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import { subOrder } from "@zk-kit/baby-jubjub";
import { toBjjScalar } from "../crypto/index.js";

// The circuit's assert_subgroup_scalar REJECTS any scalar >= the BabyJubJub subgroup order, so every scalar
// that feeds an in-circuit / ECDH mul MUST be reduced mod subOrder on the TS side first. toBjjScalar is that
// reduction; a drift here yields a scalar the circuit rejects (unspendable note) or an aliased key/tag.
describe("toBjjScalar (BabyJubJub subgroup reduction)", () => {
  it("reduces an over-suborder scalar mod the subgroup order", () => {
    const reduced = toBjjScalar(new Fr(subOrder + 12345n));
    expect(reduced.toBigInt()).toBe(12345n);
    expect(reduced.toBigInt() < subOrder).toBe(true);
  });

  it("leaves an in-range scalar unchanged", () => {
    expect(toBjjScalar(new Fr(789n)).toBigInt()).toBe(789n);
    expect(toBjjScalar(new Fr(subOrder - 1n)).toBigInt()).toBe(subOrder - 1n);
  });

  it("maps the subgroup order itself to zero", () => {
    // subOrder % subOrder == 0; the circuit separately rejects a zero scalar via assert_subgroup_scalar.
    expect(toBjjScalar(new Fr(subOrder)).toBigInt()).toBe(0n);
  });
});
