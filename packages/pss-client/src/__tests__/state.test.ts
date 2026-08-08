import { describe, expect, it } from "vitest";
import { nobleBackend } from "../crypto/index.js";
import { PSS_SCHEMA_VERSION } from "../wire/constants.js";
import { ParsedStatePayload, PssStatePayload } from "../wire/payload.js";
import {
  InstallGuard,
  MergeInput,
  PssRollbackError,
  PssSchemaError,
  PssStateError,
  VersionFloor,
  decodeStatePayload,
  emptyStatePayload,
  floorKey,
  mergeStatePayloads,
  newInstallId,
  parseStatePayload,
  serializeStatePayload,
} from "../state/index.js";
import { MemoryPssStore } from "./memoryStore.js";

const ACCOUNT =
  "8cfa343c716638269401b19220ec6ff3607ac1ed9e11f0b29d125bee39bb6188";
const INSTALL_A = "0x11111111111111111111111111111111";
const INSTALL_B = "0x22222222222222222222222222222222";
const INSTALL_C = "0x33333333333333333333333333333333";

function note(
  leafIndex: number,
  amount = "1000",
): PssStatePayload["unspentNotes"][number] {
  return {
    leafIndex,
    assetId: "0x1234567890123456789012345678901234567890",
    amount,
    nullifier: `0x${leafIndex.toString(16).padStart(64, "0")}`,
  };
}

function payload(
  overrides: Partial<PssStatePayload> = {},
  extra: Record<string, unknown> = {},
): ParsedStatePayload {
  return {
    known: {
      schema: PSS_SCHEMA_VERSION,
      installId: INSTALL_A,
      platform: "extension/chrome",
      updatedAt: 1_785_900_000,
      selfEphHighwater: 0,
      incomingIssueHighwater: 0,
      issuedAddresses: [],
      unspentNotes: [],
      syncCursor: { block: 0, logIndex: 0 },
      nullifierCheckedAt: { block: 0 },
      ...overrides,
    },
    extra,
  };
}

const complete = (p: ParsedStatePayload): MergeInput => ({
  payload: p,
  noteListComplete: true,
});

describe("payload serde", () => {
  it("round trips through JSON", () => {
    const original = payload({
      selfEphHighwater: 412,
      incomingIssueHighwater: 37,
      issuedAddresses: [{ index: 7 }],
      unspentNotes: [note(918_273)],
      syncCursor: { block: 21_830_001, logIndex: 4 },
      nullifierCheckedAt: { block: 21_830_001 },
    });
    expect(decodeStatePayload(serializeStatePayload(original))).toEqual(
      original,
    );
  });

  it("preserves unknown fields verbatim through a round trip", () => {
    const forward = { futureFlag: true, futureList: [1, 2, { deep: "value" }] };
    const parsed = decodeStatePayload(
      serializeStatePayload(payload({}, forward)),
    );
    expect(parsed.extra).toEqual(forward);
  });

  it("refuses a payload from a newer schema instead of dropping its fields", () => {
    expect(() =>
      parseStatePayload({
        ...payload().known,
        schema: PSS_SCHEMA_VERSION + 1,
      }),
    ).toThrow(PssSchemaError);
  });

  it("rejects an assetId that is a number rather than a 20 byte address", () => {
    expect(() =>
      parseStatePayload({
        ...payload().known,
        unspentNotes: [{ ...note(1), assetId: 1 }],
      }),
    ).toThrow(PssStateError);
    expect(() =>
      parseStatePayload({
        ...payload().known,
        unspentNotes: [{ ...note(1), assetId: "0x1234" }],
      }),
    ).toThrow(PssStateError);
  });

  it("requires a nullifier on every unspent note", () => {
    const withoutNullifier = { ...note(1) } as Record<string, unknown>;
    delete withoutNullifier.nullifier;
    expect(() =>
      parseStatePayload({
        ...payload().known,
        unspentNotes: [withoutNullifier],
      }),
    ).toThrow(PssStateError);
  });

  it("rejects an amount wider than a note can hold", () => {
    expect(() =>
      parseStatePayload({
        ...payload().known,
        unspentNotes: [note(1, (2n ** 128n).toString())],
      }),
    ).toThrow(PssStateError);
    expect(() =>
      parseStatePayload({
        ...payload().known,
        unspentNotes: [note(1, (2n ** 128n - 1n).toString())],
      }),
    ).not.toThrow();
  });

  it("rejects malformed JSON and non-objects", () => {
    expect(() => decodeStatePayload("{oops")).toThrow(PssStateError);
    expect(() => parseStatePayload([])).toThrow(PssStateError);
    expect(() => parseStatePayload(null)).toThrow(PssStateError);
  });

  it("builds an empty payload at the current schema", () => {
    const empty = emptyStatePayload(INSTALL_A, "web", 1);
    expect(empty.known.schema).toBe(PSS_SCHEMA_VERSION);
    expect(empty.known.unspentNotes).toEqual([]);
    expect(decodeStatePayload(serializeStatePayload(empty))).toEqual(empty);
  });
});

describe("merge table (R4)", () => {
  it("takes the max of both highwaters", () => {
    const merged = mergeStatePayloads([
      complete(payload({ selfEphHighwater: 412, incomingIssueHighwater: 3 })),
      complete(payload({ selfEphHighwater: 99, incomingIssueHighwater: 37 })),
    ]);
    expect(merged.known.selfEphHighwater).toBe(412);
    expect(merged.known.incomingIssueHighwater).toBe(37);
  });

  it("unions issued addresses by index and sorts them", () => {
    const merged = mergeStatePayloads([
      complete(payload({ issuedAddresses: [{ index: 7 }, { index: 1 }] })),
      complete(payload({ issuedAddresses: [{ index: 3 }, { index: 7 }] })),
    ]);
    expect(merged.known.issuedAddresses).toEqual([
      { index: 1 },
      { index: 3 },
      { index: 7 },
    ]);
  });

  it("unions unspent notes by leafIndex", () => {
    const merged = mergeStatePayloads([
      complete(payload({ unspentNotes: [note(5), note(9)] })),
      complete(payload({ unspentNotes: [note(9), note(1)] })),
    ]);
    expect(merged.known.unspentNotes.map((n) => n.leafIndex)).toEqual([
      1, 5, 9,
    ]);
  });

  it("refuses to merge two payloads that disagree about one leaf", () => {
    expect(() =>
      mergeStatePayloads([
        complete(payload({ unspentNotes: [note(5, "1000")] })),
        complete(payload({ unspentNotes: [note(5, "2000")] })),
      ]),
    ).toThrow(PssStateError);
  });

  it("takes the max cursor by block then logIndex", () => {
    const merged = mergeStatePayloads([
      complete(payload({ syncCursor: { block: 100, logIndex: 9 } })),
      complete(payload({ syncCursor: { block: 100, logIndex: 4 } })),
      complete(payload({ syncCursor: { block: 99, logIndex: 99 } })),
    ]);
    expect(merged.known.syncCursor).toEqual({ block: 100, logIndex: 9 });
  });

  it("ignores the cursor of a payload whose note list is not complete", () => {
    const merged = mergeStatePayloads([
      complete(
        payload({
          syncCursor: { block: 90, logIndex: 0 },
          nullifierCheckedAt: { block: 90 },
          unspentNotes: [note(1)],
        }),
      ),
      {
        payload: payload({
          syncCursor: { block: 100, logIndex: 0 },
          nullifierCheckedAt: { block: 100 },
          unspentNotes: [],
        }),
        noteListComplete: false,
      },
    ]);
    expect(merged.known.syncCursor).toEqual({ block: 90, logIndex: 0 });
    expect(merged.known.nullifierCheckedAt).toEqual({ block: 90 });
    // The notes themselves still merge; only the claim of having scanned that far is dropped.
    expect(merged.known.unspentNotes.map((n) => n.leafIndex)).toEqual([1]);
  });

  it("never lets a nullifier checkpoint advance past a checked range", () => {
    const merged = mergeStatePayloads([
      complete(payload({ nullifierCheckedAt: { block: 50 } })),
      complete(payload({ nullifierCheckedAt: { block: 70 } })),
    ]);
    expect(merged.known.nullifierCheckedAt).toEqual({ block: 70 });
  });

  it("keeps installId and platform from the newest writer", () => {
    const merged = mergeStatePayloads([
      complete(
        payload({
          installId: INSTALL_A,
          platform: "extension/chrome",
          updatedAt: 10,
        }),
      ),
      complete(
        payload({
          installId: INSTALL_B,
          platform: "mobile/ios",
          updatedAt: 20,
        }),
      ),
    ]);
    expect(merged.known.installId).toBe(INSTALL_B);
    expect(merged.known.platform).toBe("mobile/ios");
    expect(merged.known.updatedAt).toBe(20);
  });

  it("preserves unknown fields from every input, newest winning a collision", () => {
    const merged = mergeStatePayloads([
      complete(payload({ updatedAt: 10 }, { onlyOld: 1, shared: "old" })),
      complete(payload({ updatedAt: 20 }, { onlyNew: 2, shared: "new" })),
    ]);
    expect(merged.extra).toEqual({
      onlyOld: 1,
      onlyNew: 2,
      shared: "new",
    });
  });

  it("survives a merge of a single payload and refuses an empty list", () => {
    expect(mergeStatePayloads([complete(payload())]).known.schema).toBe(
      PSS_SCHEMA_VERSION,
    );
    expect(() => mergeStatePayloads([])).toThrow(PssStateError);
  });
});

describe("version floor (R3)", () => {
  it("accepts a rising version and refuses a lower one", async () => {
    const floor = new VersionFloor(new MemoryPssStore(), ACCOUNT);
    await floor.accept("state", 5);
    await floor.accept("state", 6);
    await expect(floor.accept("state", 5)).rejects.toThrow(PssRollbackError);
    expect(await floor.current("state")).toBe(6);
  });

  it("keeps the two collections independent", async () => {
    const floor = new VersionFloor(new MemoryPssStore(), ACCOUNT);
    await floor.accept("state", 9);
    expect(await floor.current("labels")).toBe(0);
    await expect(floor.accept("labels", 0)).resolves.toBe(0);
  });

  it("persists under the account and collection key", async () => {
    const store = new MemoryPssStore();
    await new VersionFloor(store, ACCOUNT).accept("state", 4);
    expect(store.snapshot()[floorKey(ACCOUNT, "state")]).toBe("4");
  });

  it("stays atomic when two writers interleave across the store await", async () => {
    // Both writers read the same floor before either writes, which is exactly the check-then-act the
    // async store creates. Without the lock the lower version would win the last write.
    const floor = new VersionFloor(new MemoryPssStore(2), ACCOUNT);
    await floor.accept("state", 1);
    const results = await Promise.allSettled([
      floor.accept("state", 9),
      floor.accept("state", 2),
      floor.accept("state", 7),
    ]);
    expect(await floor.current("state")).toBe(9);
    // The lock serialises them in call order, so 9 lands and the two lower offers are refused as
    // rollbacks. Without the lock all three would read floor 1, all three would pass the check, and
    // the last write to land would decide the floor.
    expect(results.map((r) => r.status)).toEqual([
      "fulfilled",
      "rejected",
      "rejected",
    ]);
    for (const result of results.slice(1)) {
      expect(result.status === "rejected" && result.reason).toBeInstanceOf(
        PssRollbackError,
      );
    }
  });

  it("never regresses under many interleaved writers", async () => {
    const floor = new VersionFloor(new MemoryPssStore(1), ACCOUNT);
    const versions = [3, 1, 8, 2, 12, 4, 11, 6];
    await Promise.allSettled(versions.map((v) => floor.accept("state", v)));
    expect(await floor.current("state")).toBe(12);
  });

  // Number() would read every one of these as a plausible floor: "0x10" is 16, "1e3" is 1000, "" and
  // "  " and "-0" are 0. Only the last spelling raises on its own.
  it.each([
    ["", 0],
    ["  ", 0],
    ["\t\n", 0],
    ["-0", -0],
    ["0x10", 16],
    ["0b11", 3],
    ["1e3", 1000],
    ["5.0", 5],
    [" 7 ", 7],
    ["not-a-number", Number.NaN],
  ])(
    "rejects the corrupt stored floor %j rather than reading it as %j",
    async (raw: string, wouldBe: number) => {
      expect(Number(raw)).toBe(wouldBe);
      const store = new MemoryPssStore();
      await store.set(floorKey(ACCOUNT, "state"), raw);
      await expect(
        new VersionFloor(store, ACCOUNT).current("state"),
      ).rejects.toThrow(PssStateError);
    },
  );

  it("rejects a stored floor beyond the safe integer range", async () => {
    const store = new MemoryPssStore();
    await store.set(floorKey(ACCOUNT, "state"), "9007199254740993");
    await expect(
      new VersionFloor(store, ACCOUNT).current("state"),
    ).rejects.toThrow(PssStateError);
  });

  it("bootstraps from the chain after a reinstall and never lowers (R3a)", async () => {
    const store = new MemoryPssStore();
    await new VersionFloor(store, ACCOUNT).accept("state", 12);

    // A reinstall loses local storage entirely.
    const reinstalled = new VersionFloor(new MemoryPssStore(), ACCOUNT);
    expect(await reinstalled.current("state")).toBe(0);
    await reinstalled.bootstrap("state", 10);
    await expect(reinstalled.accept("state", 4)).rejects.toThrow(
      PssRollbackError,
    );
    expect(await reinstalled.current("state")).toBe(10);

    // A lower chain floor must not pull an existing floor down.
    await reinstalled.accept("state", 15);
    await reinstalled.bootstrap("state", 11);
    expect(await reinstalled.current("state")).toBe(15);
  });
});

describe("takeover (R6)", () => {
  const identity = { installId: INSTALL_A, platform: "extension/chrome" };

  function guard(): InstallGuard {
    return new InstallGuard(
      identity,
      new VersionFloor(new MemoryPssStore(), ACCOUNT),
    );
  }

  it("mints a well shaped install id", () => {
    expect(newInstallId(nobleBackend)).toMatch(/^0x[0-9a-f]{32}$/);
    expect(newInstallId(nobleBackend)).not.toBe(newInstallId(nobleBackend));
  });

  it("writes when the blob is absent or already ours", () => {
    expect(guard().evaluate(null).mode).toBe("writer");
    expect(guard().evaluate(payload({ installId: INSTALL_A }).known).mode).toBe(
      "writer",
    );
  });

  it("demotes to read-only when another install holds the blob", () => {
    const decision = guard().evaluate(
      payload({ installId: INSTALL_B, platform: "mobile/ios" }).known,
    );
    expect(decision.mode).toBe("readonly");
    expect(decision.heldBy).toEqual({
      installId: INSTALL_B,
      platform: "mobile/ios",
    });
  });

  it("never takes over automatically", () => {
    const g = guard();
    const remote = payload({ installId: INSTALL_B }).known;
    for (let i = 0; i < 5; i++) {
      expect(g.evaluate(remote).mode).toBe("readonly");
    }
  });

  it("refuses to stamp a payload while read-only", () => {
    expect(() =>
      guard().stamp(payload(), payload({ installId: INSTALL_B }).known, 1),
    ).toThrow(PssStateError);
  });

  it("bootstraps the chain floor before it becomes the writer", async () => {
    const store = new MemoryPssStore();
    const floor = new VersionFloor(store, ACCOUNT);
    const g = new InstallGuard(identity, floor);
    const remote = payload({ installId: INSTALL_B }).known;

    expect(g.evaluate(remote).mode).toBe("readonly");
    await g.confirmTakeover(remote, { state: 20, labels: 5 });
    expect(g.evaluate(remote).mode).toBe("writer");
    expect(await floor.current("state")).toBe(20);
    expect(await floor.current("labels")).toBe(5);
    await expect(floor.accept("state", 19)).rejects.toThrow(PssRollbackError);
  });

  it("re-prompts when a different install takes the account over", async () => {
    const g = guard();
    const fromB = payload({ installId: INSTALL_B }).known;
    const fromC = payload({
      installId: INSTALL_C,
      platform: "mobile/ios",
    }).known;

    await g.confirmTakeover(fromB, { state: 0, labels: 0 });
    expect(g.evaluate(fromB).mode).toBe("writer");

    const decision = g.evaluate(fromC);
    expect(decision.mode).toBe("readonly");
    expect(decision.heldBy).toEqual({
      installId: INSTALL_C,
      platform: "mobile/ios",
    });
    expect(() => g.stamp(payload(), fromC, 1)).toThrow(PssStateError);
  });

  it("does not let the device it took over from take the account back silently", async () => {
    const g = guard();
    const fromB = payload({ installId: INSTALL_B }).known;

    await g.confirmTakeover(fromB, { state: 0, labels: 0 });
    // The handover completes the moment our own id is in the blob, which spends the grant.
    expect(g.evaluate(payload({ installId: INSTALL_A }).known).mode).toBe(
      "writer",
    );
    expect(g.evaluate(fromB).mode).toBe("readonly");
    expect(() => g.stamp(payload(), fromB, 1)).toThrow(PssStateError);
  });

  it("stamps its own identity onto the payload after takeover", async () => {
    const g = guard();
    const remote = payload({ installId: INSTALL_B }).known;
    await g.confirmTakeover(remote, { state: 0, labels: 0 });
    const stamped = g.stamp(
      payload({ installId: INSTALL_B, platform: "mobile/ios" }),
      remote,
      99,
    );
    expect(stamped.known.installId).toBe(INSTALL_A);
    expect(stamped.known.platform).toBe("extension/chrome");
    expect(stamped.known.updatedAt).toBe(99);
  });

  it("keeps unknown fields when stamping", () => {
    const stamped = guard().stamp(payload({}, { future: 1 }), null, 5);
    expect(stamped.extra).toEqual({ future: 1 });
  });
});

describe("identity validation", () => {
  it("refuses an install id that its own parser would reject", () => {
    const floor = new VersionFloor(new MemoryPssStore(), ACCOUNT);
    for (const bad of [
      "",
      "0x1234",
      INSTALL_A.toUpperCase(),
      "11111111111111111111111111111111",
    ]) {
      expect(
        () => new InstallGuard({ installId: bad, platform: "web" }, floor),
      ).toThrow(PssStateError);
    }
    expect(() => emptyStatePayload("nope", "web", 1)).toThrow(PssStateError);
  });

  it("keeps stamp and emptyStatePayload round-trippable through the parser", () => {
    const empty = emptyStatePayload(INSTALL_A, "extension/chrome", 5);
    expect(decodeStatePayload(serializeStatePayload(empty))).toEqual(empty);
    const guard = new InstallGuard(
      { installId: INSTALL_B, platform: "mobile/ios" },
      new VersionFloor(new MemoryPssStore(), ACCOUNT),
    );
    const stamped = guard.stamp(empty, null, 6);
    expect(decodeStatePayload(serializeStatePayload(stamped))).toEqual(stamped);
  });
});
