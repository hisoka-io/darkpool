import { describe, expect, it } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import {
  commitmentPrefixMatches,
  COMMITMENT_PREFIX_BYTES,
  HOWL_NOTE_LAYOUT_VERSION,
  leaf,
  RECORD_KIND_INCOMING,
  type HowlNoteRecord,
} from "@hisoka/wallets";
import { verifyAgainstTree } from "../discovery/open.js";
import type { VerifiedLeafSource } from "../discovery/ports.js";
import { WalletRuntimeError } from "../errors.js";
import { note } from "./fixtures/tree.js";

const LEAF_INDEX = 7;

function recordFor(commitment: Fr): HowlNoteRecord {
  return {
    layoutVersion: HOWL_NOTE_LAYOUT_VERSION,
    recordKind: RECORD_KIND_INCOMING,
    leafIndex: LEAF_INDEX,
    commitmentPrefix: commitment
      .toBuffer()
      .subarray(0, COMMITMENT_PREFIX_BYTES),
    ephemeralPkX: new Fr(0n),
    cekWrap: new Fr(0n),
    ciphertextKept: [],
  };
}

/** A different field element with the same 16-byte prefix: what a phantom cell can present. */
function samePrefixOther(commitment: Fr): Fr {
  return new Fr(commitment.toBigInt() ^ 1n);
}

function leavesWith(at: Fr | "unheld"): VerifiedLeafSource {
  return { leafAt: async (i) => (i === LEAF_INDEX ? at : "unheld") };
}

describe("leaf-vs-verified-tree check", () => {
  it("rejects a phantom cell whose prefix and opening pass but whose tree leaf differs", async () => {
    const opened = await leaf(note(1n));
    const treeLeaf = samePrefixOther(opened);
    expect(commitmentPrefixMatches(recordFor(opened), opened)).toBe(true);
    expect(commitmentPrefixMatches(recordFor(opened), treeLeaf)).toBe(true);

    const err = await verifyAgainstTree(
      leavesWith(treeLeaf),
      LEAF_INDEX,
      opened,
    ).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(WalletRuntimeError);
    expect((err as WalletRuntimeError).code).toBe("LEAF_MISMATCH");
    expect((err as WalletRuntimeError).context.leafIndex).toBe(
      String(LEAF_INDEX),
    );
  });

  it("verifies a note equal to the tree leaf", async () => {
    const opened = await leaf(note(2n));
    expect(
      await verifyAgainstTree(leavesWith(opened), LEAF_INDEX, opened),
    ).toBe("verified");
  });

  it("marks a note unverified when the adapter does not hold the leaf", async () => {
    const opened = await leaf(note(3n));
    expect(
      await verifyAgainstTree(leavesWith("unheld"), LEAF_INDEX, opened),
    ).toBe("unverified");
  });
});
