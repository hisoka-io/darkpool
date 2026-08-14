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
  type CounterSnapshot,
  type DerivedEph,
} from "@hisoka/wallets";
// KeyRepository is the reference state layer, deliberately off the production barrel.
import { KeyRepository } from "@hisoka/wallets/reference";
import {
  decodeStatePayload,
  emptyStatePayload,
  serializeStatePayload,
} from "@hisoka/pss-client";
import { MockRaven } from "../mockRaven.js";
import { indexEvents, type ChainNoteEvent } from "../indexer.js";
import { syncViaDiscovery, type TagCandidate } from "../discoveryClient.js";

const MNEMONIC = "test test test test test test test test test test test junk";
const ZERO = new Fr(0n);
const ASSET = new Fr(0xaaaan);
const COMPLIANCE_PK = publicKey(new Fr(0x1f3n));

/** Everything a phone still has after the app is deleted: the seed, and whatever PSS held. */
interface ColdStart {
  mnemonic: string;
  pssBlob: string;
}

async function mintSelfEvent(
  eph: DerivedEph | Fr,
  ownerCommitment: Fr,
  value: bigint,
  leafIndex: number,
): Promise<ChainNoteEvent> {
  const cek = deriveCek(eph, COMPLIANCE_PK);
  const psi = await computePsi(cek);
  const commitment = await computeLeaf({
    noteVersion: NOTE_VERSION,
    assetId: ASSET,
    noteType: ZERO,
    conditionsHash: ZERO,
    value,
    owner: ownerCommitment,
    psi,
    parents: ZERO,
  });
  const ct = await demEncrypt(cek, [
    NOTE_VERSION,
    ASSET,
    ZERO,
    ZERO,
    new Fr(value),
    ownerCommitment,
    ZERO,
  ]);
  return {
    kind: "NEW_NOTE",
    leafIndex,
    commitment,
    ephemeralX: new Fr(publicKey(eph)[0]),
    packedCiphertext: ct,
  };
}

/** What a restored wallet can address: every derived self tag it could have minted under. */
async function derivedSelfTags(
  account: DarkAccount,
  through: number,
): Promise<{ tag: Fr; eph: DerivedEph }[]> {
  const out: { tag: Fr; eph: DerivedEph }[] = [];
  for (let i = 0; i <= through; i++) {
    const eph = await account.getSelfEphemeral(BigInt(i));
    const pub = publicKey(eph);
    if (pub[1] % 2n !== 0n) continue; // odd-y indices are burned, never minted under
    out.push({ tag: discoveryTag(pub), eph });
  }
  return out;
}

async function discover(
  raven: MockRaven,
  tags: { tag: Fr; eph: DerivedEph }[],
  ownerCommitment: Fr,
) {
  const candidates: TagCandidate[] = tags.map(({ tag, eph }) => ({
    tag,
    ownerCommitment,
    cekFor: async () => deriveCek(eph, COMPLIANCE_PK),
  }));
  return syncViaDiscovery(raven, candidates);
}

describe("mobile lifecycle: destroy everything, restore from seed plus PSS plus discovery", () => {
  it("recovers every self note and its balance from a cold start", async () => {
    // ---------- device 1: mint ----------
    const account = await DarkAccount.fromMnemonic(MNEMONIC);
    const counter = new InMemoryEphemeralCounterStore();
    const repo = new KeyRepository(account, counter);
    const owner = await pubkeyOwner(await account.getSelfSpendPub());

    const raven = new MockRaven();
    const events: ChainNoteEvent[] = [];
    const values = [100n, 250n, 40n, 7n];
    for (const [i, value] of values.entries()) {
      const { eph } = await repo.nextSelfEphemeral();
      events.push(await mintSelfEvent(eph, owner, value, i));
    }
    indexEvents(raven, events);

    // ---------- persist to PSS, exactly as the wallet would ----------
    const snapshot: CounterSnapshot = counter.snapshot();
    const parsed = emptyStatePayload(
      "0x00000000000000000000000000000000",
      "test",
      1_700_000_000,
    );
    const blob = serializeStatePayload({
      ...parsed,
      known: {
        ...parsed.known,
        ephemeralCounters: snapshot,
        selfEphHighwater: repo.getState().selfMintCounter,
      },
    });
    const cold: ColdStart = { mnemonic: MNEMONIC, pssBlob: blob };

    // ---------- device 2: nothing but the seed and the blob ----------
    const restoredAccount = await DarkAccount.fromMnemonic(cold.mnemonic);
    const restoredPayload = decodeStatePayload(cold.pssBlob);
    const restoredCounter = new InMemoryEphemeralCounterStore(
      restoredPayload.known.ephemeralCounters,
    );
    const restoredRepo = new KeyRepository(restoredAccount, restoredCounter);
    await restoredRepo.restore({
      selfMintCounter: restoredPayload.known.selfEphHighwater,
      selfScanIndex: 0,
      incomingIssueCounter: 0,
      incomingScanIndex: 0,
      highestMatchedSelf: 0,
      highestMatchedIncoming: 0,
    });

    const restoredOwner = await pubkeyOwner(
      await restoredAccount.getSelfSpendPub(),
    );
    expect(restoredOwner.toString()).toBe(owner.toString());

    raven.resetQueryLog();
    const highwater = restoredPayload.known.selfEphHighwater;
    const tags = await derivedSelfTags(restoredAccount, highwater + 20);
    const result = await discover(raven, tags, restoredOwner);

    const recovered = result.notes
      .map((n) => n.plaintext[4].toBigInt())
      .sort((a, b) => Number(a - b));
    expect(recovered).toEqual([...values].sort((a, b) => Number(a - b)));
    expect(recovered.reduce((a, b) => a + b, 0n)).toBe(
      values.reduce((a, b) => a + b, 0n),
    );

    // Two round trips, from a cold device, regardless of how many notes there were.
    expect(raven.queryLog.roundTrips).toBeLessThanOrEqual(2);
  });

  it("CANNOT recover a note minted from a sampled ephemeral, which is the defect class this guards", async () => {
    const account = await DarkAccount.fromMnemonic(MNEMONIC);
    const counter = new InMemoryEphemeralCounterStore();
    const repo = new KeyRepository(account, counter);
    const owner = await pubkeyOwner(await account.getSelfSpendPub());
    const raven = new MockRaven();

    // One honest note through the derived path.
    const { eph } = await repo.nextSelfEphemeral();
    const good = await mintSelfEvent(eph, owner, 100n, 0);

    // One note minted from a scalar that is NOT in the wallet's derivation family. The tag it lands
    // under is that scalar's own public x, which no derived enumeration will ever produce.
    let sampled = new Fr(0xfeedfacecafebeefn);
    while (publicKey(sampled)[1] % 2n !== 0n) {
      sampled = new Fr(sampled.toBigInt() + 1n);
    }
    const orphan = await mintSelfEvent(sampled, owner, 999n, 1);

    indexEvents(raven, [good, orphan]);

    const tags = await derivedSelfTags(
      account,
      repo.getState().selfMintCounter + 50,
    );
    const result = await discover(raven, tags, owner);

    const values = result.notes.map((n) => n.plaintext[4].toBigInt());
    expect(values).toEqual([100n]);
    // The orphan is sitting in the table, owned by this wallet, and is unreachable. Silently.
    expect(values).not.toContain(999n);
    expect(raven.noteCount).toBe(2);
  });
});
