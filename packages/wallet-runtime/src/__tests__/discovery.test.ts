import { beforeAll, describe, expect, it } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import {
  completeComplianceHistory,
  isEvenY,
  publicKey,
  pubkeyOwner,
  type CompleteComplianceHistory,
  type DarkAccount,
  type HowlNoteRecord,
} from "@hisoka/wallets";
import { RavenDiscovery, type RavenHowlClient } from "../adapters/raven.js";
import { SelfIndexDiscovery } from "../adapters/selfIndex/selfIndex.js";
import { RpcChainReader } from "../chain/chainReader.js";
import { RpcLogSource } from "../chain/logs.js";
import { discoverySourceOver } from "../discovery/feedSource.js";
import { openRecord, type OpenCandidate } from "../discovery/open.js";
import type { DiscoveryPort, TagMatches } from "../discovery/ports.js";
import {
  checkMatches,
  discoverNotes,
  discoverWallet,
  walletCandidates,
} from "../discovery/sync.js";
import { WalletRuntimeError } from "../errors.js";
import {
  evenIncomingIndex,
  evenSelfIndex,
  memoTo,
  selfNote,
} from "./fixtures/mint.js";
import { accounts, COMPLIANCE_PK, SimPool } from "./fixtures/pool.js";
import { MemoryStore } from "./fixtures/store.js";

let alice: DarkAccount;
let bob: DarkAccount;
let s0: number;
let s1: number;
let in0: number;
let v1: CompleteComplianceHistory;
let v123: CompleteComplianceHistory;

const rotation = (v: number, block: number) => ({
  oldVersion: v - 1,
  newVersion: v,
  newX: COMPLIANCE_PK[v - 1]![0],
  newY: COMPLIANCE_PK[v - 1]![1],
  blockNumber: block,
});

beforeAll(async () => {
  ({ alice, bob } = await accounts());
  s0 = await evenSelfIndex(alice, 0);
  s1 = await evenSelfIndex(alice, s0 + 1);
  in0 = await evenIncomingIndex(bob, 0);
  v1 = completeComplianceHistory({
    genesisPk: COMPLIANCE_PK[0]!,
    rotations: [],
    currentPk: COMPLIANCE_PK[0]!,
    currentVersion: 1,
  });
  v123 = completeComplianceHistory({
    genesisPk: COMPLIANCE_PK[0]!,
    rotations: [rotation(2, 20), rotation(3, 30)],
    currentPk: COMPLIANCE_PK[2]!,
    currentVersion: 3,
  });
});

async function selfCandidate(index: number): Promise<OpenCandidate> {
  return {
    kind: "self",
    eph: await alice.getSelfEphemeral(BigInt(index)),
    index,
    ownerCommitment: await pubkeyOwner(await alice.getSelfSpendPub()),
  };
}

async function indexed(pool: SimPool): Promise<SelfIndexDiscovery> {
  const index = await SelfIndexDiscovery.open({
    config: pool.config,
    chain: RpcChainReader.over(pool.chain.rpc, pool.config),
    logs: RpcLogSource.over(pool.chain.rpc, pool.config),
    store: new MemoryStore(),
  });
  await index.sync();
  return index;
}

async function recordAt(index: SelfIndexDiscovery, tag: Fr, position = 0) {
  const [m] = await index.match([tag]);
  const record = m!.records[position];
  if (record === undefined) throw new Error("no record");
  return record;
}

describe("opening notes", () => {
  it("opens a self note under its epoch, and an incoming note with its address key", async () => {
    const pool = await SimPool.create();
    const self = await selfNote(alice, s0, 10n, COMPLIANCE_PK[0]!);
    const memo = await memoTo(bob, in0, 30n, COMPLIANCE_PK[0]!, 3n);
    await pool.insertSelf(10, self);
    await pool.insertMemo(11, memo);
    const index = await indexed(pool);

    const opened = await openRecord(
      await recordAt(index, self.tag),
      await selfCandidate(s0),
      v1,
      { commitment: self.commitment },
    );
    expect(opened.kind).toBe("opened");
    if (opened.kind !== "opened") return;
    expect(opened.note.commitment.equals(self.commitment)).toBe(true);
    expect(opened.note.note.value).toBe(10n);
    expect(opened.note.complianceVersion).toBe(1);
    expect(opened.note.origin).toBe("self");

    const inKey = await bob.getIncomingKey(BigInt(in0));
    const incoming = await openRecord(
      await recordAt(index, memo.tag),
      {
        kind: "incoming",
        inKey,
        index: in0,
        ownerCommitment: await pubkeyOwner(memo.inPub),
      },
      v1,
    );
    expect(incoming.kind).toBe("opened");
    if (incoming.kind !== "opened") return;
    expect(incoming.note.note.value).toBe(30n);
    expect(incoming.note.complianceVersion).toBeNull();
    expect(incoming.note.nullifier.isZero()).toBe(false);
  });

  it("opens a note minted under v1 with a v1 -> v2 -> v3 history, trying the covering epoch first", async () => {
    const pool = await SimPool.create();
    const old = await selfNote(alice, s0, 5n, COMPLIANCE_PK[0]!);
    await pool.insertSelf(10, old);
    const index = await indexed(pool);
    const record = await recordAt(index, old.tag);
    const late = await openRecord(record, await selfCandidate(s0), v123, {
      block: 35,
    });
    expect(late).toMatchObject({ kind: "opened" });
    if (late.kind === "opened") expect(late.note.complianceVersion).toBe(1);
    // The wrong epochs (3, then 2) fail inside the leaf check; that is "try the next one".
    const single = completeComplianceHistory({
      genesisPk: COMPLIANCE_PK[2]!,
      rotations: [],
      currentPk: COMPLIANCE_PK[2]!,
      currentVersion: 1,
    });
    expect(await openRecord(record, await selfCandidate(s0), single)).toEqual({
      kind: "unopenable",
      versionsTried: [1],
    });
  });

  it("does not accept a row on decryption alone: a wrong candidate or another wallet is a miss", async () => {
    const pool = await SimPool.create();
    const self = await selfNote(alice, s0, 10n, COMPLIANCE_PK[0]!);
    await pool.insertSelf(10, self);
    const index = await indexed(pool);
    const record = await recordAt(index, self.tag);
    expect(await openRecord(record, await selfCandidate(s1), v1)).toEqual({
      kind: "unopenable",
      versionsTried: [1],
    });
    const bobOwner = await pubkeyOwner(await bob.getSelfSpendPub());
    expect(
      await openRecord(
        record,
        { ...(await selfCandidate(s0)), ownerCommitment: bobOwner },
        v1,
      ),
    ).toMatchObject({ kind: "unopenable" });
    expect(
      await openRecord(
        record,
        {
          kind: "incoming",
          inKey: await bob.getIncomingKey(BigInt(in0)),
          index: in0,
          ownerCommitment: bobOwner,
        },
        v1,
      ),
    ).toEqual({ kind: "miss" });
  });
});

describe("discovery sync", () => {
  it("finds every note under every matched position, verifies it against the tree, and reports unopenable self rows", async () => {
    const pool = await SimPool.create();
    const pk = COMPLIANCE_PK[0]!;
    const a = await selfNote(alice, s0, 10n, pk);
    const b = await selfNote(alice, s0, 11n, pk);
    await pool.insertSelf(10, a);
    await pool.insertSelf(11, b);
    // A self row under alice's tag that no epoch opens: bob minted it with alice's tag.
    const foreign = await selfNote(bob, s0, 99n, pk);
    await pool.insertSelf(12, { ...foreign, tag: a.tag, ephPub: a.ephPub });
    const index = await indexed(pool);
    const head = await index.sync();
    const found = await discoverNotes(
      index,
      head,
      [{ tag: a.tag, candidate: await selfCandidate(s0) }],
      v1,
      100,
    );
    expect(
      found.notes.map((n) => [n.leafIndex, n.note.value, n.verification]),
    ).toEqual([
      [1, 10n, "verified"],
      [2, 11n, "verified"],
    ]);
    expect(found.notes[0]!.block.number).toBe(10);
    expect(found.unopenable.map((u) => u.leafIndex)).toEqual([3]);
  });

  it("drops a phantom whose opening passes but whose tree leaf differs, and never counts it", async () => {
    const pool = await SimPool.create();
    const a = await selfNote(alice, s0, 10n, COMPLIANCE_PK[0]!);
    await pool.insertSelf(10, a);
    const index = await indexed(pool);
    const head = await index.sync();
    const lying: DiscoveryPort = {
      sync: () => index.sync(),
      match: (t) => index.match(t),
      leafAt: async () => new Fr(0xbadn),
    };
    const found = await discoverNotes(
      lying,
      head,
      [{ tag: a.tag, candidate: await selfCandidate(s0) }],
      v1,
      100,
    );
    expect(found.notes).toEqual([]);
    expect(found.phantoms).toEqual([1]);
  });

  it("finds a note past the first window by extending the gap limit at every match", async () => {
    const pool = await SimPool.create();
    const pk = COMPLIANCE_PK[0]!;
    const near = await evenSelfIndex(alice, 15);
    const far = await evenSelfIndex(alice, near + 12);
    await pool.insertSelf(10, await selfNote(alice, near, 1n, pk));
    await pool.insertSelf(11, await selfNote(alice, far, 2n, pk));
    const memoIdx = await evenIncomingIndex(alice, 3);
    const memo = await memoTo(alice, memoIdx, 3n, pk, 5n);
    await pool.insertMemo(12, memo);
    const index = await indexed(pool);
    const head = await index.sync();
    const found = await discoverWallet(
      index,
      head,
      alice,
      v1,
      { self: 0, incoming: 0 },
      100,
    );
    expect(
      found.notes.map((n) => [n.origin, n.derivationIndex]).sort(),
    ).toEqual(
      [
        ["incoming", memoIdx],
        ["self", far],
        ["self", near],
      ].sort(),
    );
  });

  it("builds a candidate for every even-y index in the window and for no odd-y one", async () => {
    for (const family of ["self", "incoming"] as const) {
      const built = await walletCandidates(alice, family, 0, 20);
      const indices = built.map((c) => c.candidate.index);
      for (let i = 0; i < 20; i++) {
        const key =
          family === "self"
            ? await alice.getSelfEphemeral(BigInt(i))
            : await alice.getIncomingKey(BigInt(i));
        const pub = publicKey(key);
        expect(indices.includes(i)).toBe(isEvenY(pub));
        const c = built.find((x) => x.candidate.index === i);
        if (c !== undefined) expect(c.tag.toBigInt()).toBe(pub[0]);
      }
    }
  });
});

/** A Raven client over a self-index, standing in for the real client's answers. */
function recordedRaven(index: SelfIndexDiscovery): RavenHowlClient {
  return {
    async sync() {
      const head = await index.sync();
      return { leafCount: head.leafCount, root: head.root, block: head.block };
    },
    async probeFirst(tags) {
      return (await index.match(tags)).map((m) => ({
        tag: m.tag,
        positions: m.positions,
        records: m.records,
      }));
    },
    async confirmNote(leafIndex) {
      const leaf = await index.leafAt(leafIndex);
      return leaf === "unheld"
        ? { status: "unconfirmed" }
        : { status: "confirmed", leaf };
    },
    merkleWitness: (i, n) => index.witness(i, n),
  };
}

describe("DiscoveryPort contract", () => {
  async function fixture(): Promise<{ pool: SimPool; tags: Fr[] }> {
    const pool = await SimPool.create();
    const pk = COMPLIANCE_PK[0]!;
    const a = await selfNote(alice, s0, 10n, pk);
    await pool.insertSelf(10, a);
    await pool.insertSelf(11, await selfNote(alice, s1, 12n, pk));
    await pool.insertSelf(12, await selfNote(alice, s0, 13n, pk));
    return { pool, tags: [a.tag, new Fr(424242n)] };
  }

  const adapters: [
    string,
    (i: SelfIndexDiscovery, p: SimPool) => DiscoveryPort,
  ][] = [
    ["self-index", (i) => i],
    ["Raven adapter", (i, p) => new RavenDiscovery(recordedRaven(i), p.config)],
  ];

  it.each(adapters)(
    "%s answers one entry per tag in order, with every position, never 0, records aligned",
    async (
      _name: string,
      make: (i: SelfIndexDiscovery, p: SimPool) => DiscoveryPort,
    ) => {
      const { pool, tags } = await fixture();
      const port = make(await indexed(pool), pool);
      await port.sync();
      const matches = await port.match(tags);
      expect(() => checkMatches(tags, matches, 100)).not.toThrow();
      expect(matches.map((m) => m.positions)).toEqual([[1, 3], []]);
      expect(await port.leafAt(1)).not.toBe("unheld");
    },
  );

  it("refuses an adapter that breaks the contract or exceeds the occurrence cap", () => {
    const tag = new Fr(5n);
    const record = { leafIndex: 2 } as HowlNoteRecord;
    const ok: TagMatches = {
      tag,
      positions: [2],
      records: [record],
      blocks: [null],
    };
    const code = (fn: () => void): string => {
      try {
        fn();
      } catch (e) {
        return (e as WalletRuntimeError).code;
      }
      return "none";
    };
    expect(code(() => checkMatches([tag], [ok], 1))).toBe("none");
    expect(code(() => checkMatches([tag], [], 1))).toBe("DISCOVERY_PROTOCOL");
    expect(code(() => checkMatches([new Fr(6n)], [ok], 1))).toBe(
      "DISCOVERY_PROTOCOL",
    );
    expect(
      code(() =>
        checkMatches(
          [tag],
          [
            {
              ...ok,
              positions: [0],
              records: [{ leafIndex: 0 } as HowlNoteRecord],
            },
          ],
          1,
        ),
      ),
    ).toBe("DISCOVERY_PROTOCOL");
    expect(code(() => checkMatches([tag], [{ ...ok, records: [] }], 1))).toBe(
      "DISCOVERY_PROTOCOL",
    );
    expect(
      code(() =>
        checkMatches(
          [tag],
          [{ ...ok, records: [{ leafIndex: 3 } as HowlNoteRecord] }],
          1,
        ),
      ),
    ).toBe("DISCOVERY_PROTOCOL");
    expect(
      code(() =>
        checkMatches(
          [tag],
          [
            {
              ...ok,
              positions: [2, 2],
              records: [record, record],
              blocks: [null, null],
            },
          ],
          5,
        ),
      ),
    ).toBe("DISCOVERY_PROTOCOL");
    expect(
      code(() =>
        checkMatches(
          [tag],
          [
            {
              tag,
              positions: [2, 3],
              records: [record, { leafIndex: 3 } as HowlNoteRecord],
              blocks: [null, null],
            },
          ],
          1,
        ),
      ),
    ).toBe("DISCOVERY_OCCURRENCE_CAP");
  });

  it("maps Raven's answers: unconfirmed leaf is unheld, a phantom is LEAF_MISMATCH, a foreign pool is refused", async () => {
    const { pool } = await fixture();
    const index = await indexed(pool);
    const client = recordedRaven(index);
    const raven = new RavenDiscovery(
      {
        ...client,
        confirmNote: async (i) =>
          i === 1 ? { status: "unconfirmed" } : { status: "phantom" },
      },
      pool.config,
    );
    expect(await raven.leafAt(1)).toBe("unheld");
    const err = await raven.leafAt(2).catch((e: unknown) => e);
    expect((err as WalletRuntimeError).code).toBe("LEAF_MISMATCH");
    const foreign = new RavenDiscovery(
      {
        ...client,
        deployment: async () => ({
          chainId: 31337n,
          pool: `0x${"12".repeat(20)}`,
        }),
      },
      pool.config,
    );
    const mismatch = await foreign.sync().catch((e: unknown) => e);
    expect((mismatch as WalletRuntimeError).code).toBe("DEPLOYMENT_MISMATCH");
    const same = new RavenDiscovery(
      {
        ...client,
        deployment: async () => ({
          chainId: 31337n,
          pool: pool.config.deployment.dark_pool
            .toUpperCase()
            .replace("0X", "0x"),
        }),
      },
      pool.config,
    );
    expect((await same.sync()).leafCount).toBe(4);
  });
});

describe("preflight view", () => {
  it("syncs before each probe and reports the full matched count with the first record", async () => {
    const pool = await SimPool.create();
    const pk = COMPLIANCE_PK[0]!;
    const a = await selfNote(alice, s0, 10n, pk);
    await pool.insertSelf(10, a);
    const index = await indexed(pool);
    const source = discoverySourceOver(index, 100);
    // A second occurrence lands after the adapter's last sync: the probe must see it.
    await pool.insertSelf(61, await selfNote(alice, s0, 11n, pk));
    pool.chain.mine(2);
    const [hit, miss] = await source.probeFirst([a.tag, new Fr(77n)]);
    expect(hit!.occurrenceCount).toBe(2);
    expect(hit!.record?.leafIndex).toBe(1);
    expect(miss!.occurrenceCount).toBe(0);
    expect(miss!.record?.leafIndex).toBe(0);
    const [second] = await source.fetchOccurrences([
      { tag: a.tag, occurrence: 1 },
    ]);
    expect(second?.leafIndex).toBe(2);
    const err = await source.fetchLeafBlock(0).catch((e: unknown) => e);
    expect((err as WalletRuntimeError).code).toBe("DISCOVERY_UNAVAILABLE");
  });
});
