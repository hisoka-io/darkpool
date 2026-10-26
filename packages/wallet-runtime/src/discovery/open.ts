import type { Fr } from "@aztec/foundation/fields";
import { WalletRuntimeError } from "../errors.js";
import type { VerifiedLeafSource } from "./ports.js";

export type LeafVerification = "verified" | "unverified";

/**
 * Compares an opened note with the verified tree leaf at its position before it may count toward a balance.
 * A prefix match and a clean decrypt do not prove the row is real: a phantom cell can carry both. Only the
 * leaf the tree was verified with does. `"unverified"` notes stay out of every spendable balance and out of
 * PSS until the spend path checks them against the on-chain root.
 */
export async function verifyAgainstTree(
  leaves: VerifiedLeafSource,
  leafIndex: number,
  commitment: Fr,
): Promise<LeafVerification> {
  const leaf = await leaves.leafAt(leafIndex);
  if (leaf === "unheld") return "unverified";
  if (!leaf.equals(commitment)) {
    throw new WalletRuntimeError(
      "LEAF_MISMATCH",
      `opened note commitment ${commitment.toString()} is not the verified tree leaf ${leaf.toString()} at index ${leafIndex}; the row is a phantom and is dropped`,
      {
        leafIndex: String(leafIndex),
        expected: leaf.toString(),
        actual: commitment.toString(),
      },
    );
  }
  return "verified";
}
