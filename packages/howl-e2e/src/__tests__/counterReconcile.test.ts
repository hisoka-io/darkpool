import { describe, expect, it } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import {
  DarkAccount,
  deriveCek,
  demEncrypt,
  discoveryTag,
  leaf as computeLeaf,
  NOTE_VERSION,
  publicKey,
  pubkeyOwner,
  computePsi,
  InMemoryEphemeralCounterStore,
  reconcileCounterWithChain,
  ratchetCounter,
  MAX_OCCURRENCES_PER_TAG,
  type DiscoverySource,
  type IndexedTag,
} from "@hisoka/wallets";
import { KeyRepository } from "@hisoka/wallets/reference";
import { MockRaven } from "../mockRaven.js";
import { indexEvents, type ChainNoteEvent } from "../indexer.js";
import { syncViaDiscovery } from "../discoveryClient.js";

const MNEMONIC = "test test test test test test test test test test test junk";
const ZERO = new Fr(0n);
const ASSET = new Fr(0xaaaan);
const COMPLIANCE_PK = publicKey(new Fr(0x1f3n));
const SELF_SCOPE = "self";

async function mintSelf(
  eph: Fr,
  owner: Fr,
  value: bigint,
  leafIndex: number,
): Promise<ChainNoteEvent> {
  const cek = deriveCek(eph, COMPLIANCE_PK);
  const psi = await computePsi(cek);
  const note = {
    noteVersion: NOTE_VERSION,
    assetId: ASSET,
    noteType: ZERO,
    conditionsHash: ZERO,
    value,
    owner,
    psi,
    parents: ZERO,
  };
  const ct = await demEncrypt(cek, [
    NOTE_VERSION,
    ASSET,
    ZERO,
    ZERO,
    new Fr(value),
    owner,
    ZERO,
  ]);
  return {
    kind: "NEW_NOTE",
    leafIndex,
    commitment: await computeLeaf(note),
    ephemeralX: new Fr(publicKey(eph)[0]),
    packedCiphertext: ct,
  };
}

/** The candidate window a restoring wallet probes: every derived self index it could have minted under. */
async function candidateWindow(
  account: DarkAccount,
  through: number,
): Promise<IndexedTag[]> {
  const out: IndexedTag[] = [];
  for (let i = 0; i <= through; i++) {
    const eph = await account.getSelfEphemeral(BigInt(i));
    const pub = publicKey(eph);
    if (pub[1] % 2n !== 0n) continue; // odd-y indices are abandoned, never minted under
    out.push({ index: i, tag: discoveryTag(pub) });
  }
  return out;
}

describe("scenario B: the counter must learn what the chain already knows", () => {
  it("without reconciliation, a wallet that DISCOVERS its notes still reuses their indices", async () => {
    const account = await DarkAccount.fromMnemonic(MNEMONIC);
    const owner = await pubkeyOwner(await account.getSelfSpendPub());

    // Device A mints three notes while its PSS push never lands.
    const deviceA = new KeyRepository(
      account,
      new InMemoryEphemeralCounterStore(),
    );
    const raven = new MockRaven();
    const events: ChainNoteEvent[] = [];
    const mintedIndices: number[] = [];
    for (let i = 0; i < 3; i++) {
      const { eph, index } = await deviceA.nextSelfEphemeral();
      mintedIndices.push(index);
      events.push(await mintSelf(eph, owner, 100n, i));
    }
    indexEvents(raven, events);

    // Device B restores from a STALE blob: counter at zero.
    const staleStore = new InMemoryEphemeralCounterStore();
    const deviceB = new KeyRepository(account, staleStore);

    // It discovers all three notes. The balance is right and the restore looks successful.
    const window = await candidateWindow(
      account,
      Math.max(...mintedIndices) + 10,
    );
    const found = await syncViaDiscovery(
      raven,
      window.map(({ index, tag }) => ({
        tag,
        ownerCommitment: owner,
        cekFor: async () =>
          deriveCek(
            await account.getSelfEphemeral(BigInt(index)),
            COMPLIANCE_PK,
          ),
      })),
    );
    expect(found.notes).toHaveLength(3);

    // And the very next mint hands back an index the chain has already consumed.
    const next = await deviceB.nextSelfEphemeral();
    expect(mintedIndices).toContain(next.index);
    expect(await staleStore.highWater(SELF_SCOPE)).toBeLessThanOrEqual(
      Math.max(...mintedIndices),
    );
  });

  it("with reconciliation, the next index is strictly past every index on chain", async () => {
    const account = await DarkAccount.fromMnemonic(MNEMONIC);
    const owner = await pubkeyOwner(await account.getSelfSpendPub());

    const deviceA = new KeyRepository(
      account,
      new InMemoryEphemeralCounterStore(),
    );
    const raven = new MockRaven();
    const events: ChainNoteEvent[] = [];
    const mintedIndices: number[] = [];
    for (let i = 0; i < 3; i++) {
      const { eph, index } = await deviceA.nextSelfEphemeral();
      mintedIndices.push(index);
      events.push(await mintSelf(eph, owner, 100n, i));
    }
    indexEvents(raven, events);

    const staleStore = new InMemoryEphemeralCounterStore();
    const deviceB = new KeyRepository(account, staleStore);

    const window = await candidateWindow(
      account,
      Math.max(...mintedIndices) + 10,
    );
    const { highWater, occupied } = await reconcileCounterWithChain(
      raven,
      staleStore,
      SELF_SCOPE,
      window,
    );

    expect([...occupied].sort((a, b) => a - b)).toEqual(
      [...mintedIndices].sort((a, b) => a - b),
    );
    expect(highWater).toBe(Math.max(...mintedIndices) + 1);

    const next = await deviceB.nextSelfEphemeral();
    for (const used of mintedIndices) expect(next.index).toBeGreaterThan(used);
  });

  it("never lowers the counter, because a discovery miss carries no information", async () => {
    const store = new InMemoryEphemeralCounterStore();
    await store.reserve(SELF_SCOPE, 50);
    expect(await store.highWater(SELF_SCOPE)).toBe(50);

    // An empty table. Raven lags the chain and is untrusted, so "nothing found" must not rewind anything.
    const empty = new MockRaven();
    const account = await DarkAccount.fromMnemonic(MNEMONIC);
    const { highWater } = await reconcileCounterWithChain(
      empty,
      store,
      SELF_SCOPE,
      await candidateWindow(account, 10),
    );
    expect(highWater).toBe(50);
    expect(await store.highWater(SELF_SCOPE)).toBe(50);

    await ratchetCounter(store, SELF_SCOPE, 5);
    expect(await store.highWater(SELF_SCOPE)).toBe(50);
  });
});

describe("multi-realm collision: two stores, one account", () => {
  it("two realms hydrated from one snapshot allocate the SAME index without reconciliation", async () => {
    const account = await DarkAccount.fromMnemonic(MNEMONIC);
    const snapshot = { [SELF_SCOPE]: 4 };

    // Two browser tabs, or a phone restored from a cloned device backup: one snapshot, two live stores.
    const tabA = new KeyRepository(
      account,
      new InMemoryEphemeralCounterStore({ ...snapshot }),
    );
    const tabB = new KeyRepository(
      account,
      new InMemoryEphemeralCounterStore({ ...snapshot }),
    );

    const a = await tabA.nextSelfEphemeral();
    const b = await tabB.nextSelfEphemeral();
    expect(a.index).toBe(b.index);
    // Same index means the same ephemeral, so the same tag lands in two events for anyone to cluster.
    expect(discoveryTag(publicKey(a.eph)).toString()).toBe(
      discoveryTag(publicKey(b.eph)).toString(),
    );
  });

  it("the collision is observable with the query an outside analyst already gets for free", async () => {
    const account = await DarkAccount.fromMnemonic(MNEMONIC);
    const owner = await pubkeyOwner(await account.getSelfSpendPub());
    const snapshot = { [SELF_SCOPE]: 4 };

    const tabA = new KeyRepository(
      account,
      new InMemoryEphemeralCounterStore({ ...snapshot }),
    );
    const tabB = new KeyRepository(
      account,
      new InMemoryEphemeralCounterStore({ ...snapshot }),
    );
    const a = await tabA.nextSelfEphemeral();
    const b = await tabB.nextSelfEphemeral();

    const raven = new MockRaven();
    indexEvents(raven, [
      await mintSelf(a.eph, owner, 100n, 0),
      await mintSelf(b.eph, owner, 250n, 1),
    ]);

    // The regression anchor: no self tag of mine may ever hold more than one note.
    const [entry] = await raven.probeFirst([discoveryTag(publicKey(a.eph))]);
    expect(entry.occurrenceCount).toBe(2);

    // Reconciliation between the two mints is what prevents it.
    const guarded = new InMemoryEphemeralCounterStore({ ...snapshot });
    const raven2 = new MockRaven();
    indexEvents(raven2, [await mintSelf(a.eph, owner, 100n, 0)]);
    const window: IndexedTag[] = [];
    for (let i = 0; i <= a.index + 5; i++) {
      const eph = await account.getSelfEphemeral(BigInt(i));
      const pub = publicKey(eph);
      if (pub[1] % 2n === 0n) window.push({ index: i, tag: discoveryTag(pub) });
    }
    await reconcileCounterWithChain(raven2, guarded, SELF_SCOPE, window);
    const guardedNext = await new KeyRepository(
      account,
      guarded,
    ).nextSelfEphemeral();
    expect(guardedNext.index).toBeGreaterThan(a.index);
  });
});

describe("a hostile occurrence count cannot wedge the device", () => {
  it("bounds the round-2 batch and reports which tags were truncated", async () => {
    const account = await DarkAccount.fromMnemonic(MNEMONIC);
    const owner = await pubkeyOwner(await account.getSelfSpendPub());
    const eph = await account.getSelfEphemeral(0n);
    const tag = discoveryTag(publicKey(eph));

    const raven = new MockRaven();
    indexEvents(raven, [await mintSelf(eph, owner, 100n, 0)]);

    // A server that claims a quarter of a million rows under one tag, delegating everything else honestly.
    const hostile: DiscoverySource = {
      probeFirst: async (tags) =>
        (await raven.probeFirst(tags)).map((r) => ({
          ...r,
          occurrenceCount: 250_000,
        })),
      fetchOccurrences: (requests) => raven.fetchOccurrences(requests),
      fetchLeafBlock: (block) => raven.fetchLeafBlock(block),
    };

    const result = await syncViaDiscovery(hostile, [
      {
        tag,
        ownerCommitment: owner,
        cekFor: async () => deriveCek(eph, COMPLIANCE_PK),
      },
    ]);

    expect(result.truncatedTags).toContain(tag.toString());
    // Bounded, not unbounded: the request never grows past the cap no matter what the server claims.
    expect(raven.queryLog.rowsRequested).toBeLessThanOrEqual(
      MAX_OCCURRENCES_PER_TAG + 1,
    );
    expect(result.notes).toHaveLength(1);
  });
});
