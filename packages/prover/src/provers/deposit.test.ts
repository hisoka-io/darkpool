import { describe, it, expect } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import { Point } from "@zk-kit/baby-jubjub";
import { proveDeposit } from "./deposit.js";
import { DepositInputs } from "../types.js";

// Fixture from the wallets parity vectors; proving against the DepositVerifier VK exercises circuit -> verifier -> prover end to end.
const COMPLIANCE_PK: Point<bigint> = [
  0x085ed469c9a9f102b6d4f6f909b8ceaf6ca49b39759ac2e0feb7e0aada8b7111n,
  0x245e25ab2bd42f0280a5ade750828dd6868f5225ae798d6b51c676f519c8f4e8n,
];

const EXPECTED_LEAF =
  0x09b087f618ba26b56f02ad1438a08cf9681445de37e85771c2e77f3058e0a551n;

describe("proveDeposit (v2 note format, round-trip)", () => {
  const inputs: DepositInputs = {
    compliancePk: COMPLIANCE_PK,
    note: {
      noteVersion: new Fr(1n),
      assetId: new Fr(0x1234567890123456789012345678901234567890n),
      noteType: new Fr(0n),
      conditionsHash: new Fr(0n),
      value: new Fr(100n),
      owner: new Fr(
        0x2874ae964d8b283e2f521a7f14125fc92747bb9770139b8d4b70ee09e2d83785n,
      ),
      psi: new Fr(
        0x0981a88f9e119b057498a4ab99ed5379a1ea91c642454fc0c07aacc1f5cd5731n,
      ),
      parents: new Fr(0n),
    },
    eph: new Fr(5n),
  };

  it("proves and self-verifies, exposing the leaf/value/asset at the layout indices", async () => {
    const { verified, publicInputs } = await proveDeposit(inputs);
    expect(verified).toBe(true);
    // Layout: [0,1] compliance, [2] leaf, [3,4] eph_pub, [5] value, [6] asset, [7..13] ciphertext.
    expect(BigInt(publicInputs[2])).toBe(EXPECTED_LEAF);
    expect(BigInt(publicInputs[5])).toBe(100n);
    expect(BigInt(publicInputs[6])).toBe(
      0x1234567890123456789012345678901234567890n,
    );
  }, 180000);
});
