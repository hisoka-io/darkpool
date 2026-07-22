import { describe, it, expect } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import { calculatePublicMemoId } from "../crypto/index";

// TS leg of the memo-id parity triangle (Noir public_claim test_public_claim_kat + evm poseidon-parity.test.ts). Unpinned, an SDK consumer computes the wrong id and cannot find its own memo.
const VAL = new Fr(100n);
const ASSET = new Fr(0x1234567890123456789012345678901234567890n);
const TIMELOCK = new Fr(0n);
const OWNER_X = new Fr(
  0x2a39f6a9afe8c569977ec299af985e30142d18ee451008ffd13fc0a2a36cf54en,
);
const OWNER_Y = new Fr(
  0x1d5a43dc73fe0493cce521cc92a4d34d4837214ce47871c587c567d2d0c72c8fn,
);
const SALT = new Fr(
  0x004996117eaf098d97b6a42a8ec9c27b5ec30cdca90ffbdb6792eb4733c982d4n,
);
const GOLDEN = new Fr(
  0x0731300919ae74d1507ab3b22cac576da8c86deb8ddc11f24317b861f17f6f93n,
);

describe("public memo id parity (TS leg)", () => {
  it("matches the public_claim golden shared with Noir and Solidity", async () => {
    const memoId = await calculatePublicMemoId(
      VAL,
      ASSET,
      TIMELOCK,
      OWNER_X,
      OWNER_Y,
      SALT,
    );
    expect(memoId.equals(GOLDEN)).toBe(true);
  });

  // Field order is the failure mode a golden on one fixture can miss: swapping two equal-arity fields still
  // hashes six inputs. ownerX and ownerY are the pair most likely to be transposed.
  it("is sensitive to field order", async () => {
    const transposed = await calculatePublicMemoId(
      VAL,
      ASSET,
      TIMELOCK,
      OWNER_Y,
      OWNER_X,
      SALT,
    );
    expect(transposed.equals(GOLDEN)).toBe(false);
  });

  it("binds every field", async () => {
    const base = [VAL, ASSET, TIMELOCK, OWNER_X, OWNER_Y, SALT] as const;
    for (let i = 0; i < base.length; i++) {
      const mutated = base.map((f, j) =>
        j === i ? new Fr(f.toBigInt() + 1n) : f,
      );
      const id = await calculatePublicMemoId(
        mutated[0]!,
        mutated[1]!,
        mutated[2]!,
        mutated[3]!,
        mutated[4]!,
        mutated[5]!,
      );
      expect(id.equals(GOLDEN), `field ${i} is not bound`).toBe(false);
    }
  });
});
