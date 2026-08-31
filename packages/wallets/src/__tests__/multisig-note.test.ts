import { describe, it, expect, vi } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import {
  multisigAddress,
  multisigIncomingKeyAt,
  buildIncomingMultisigNote,
  memberReadIncoming,
  deriveSelfEph,
  canonicalMultisigSelfTag,
  buildSelfNote,
  memberReadSelf,
  multisigOwner,
  NOTE_TYPE_MULTISIG,
  MultisigScanner,
  MultisigNoteView,
  selfNoteEvent,
  incomingNoteEvent,
  type MultisigSelfMint,
} from "../frost/index.js";
import { Point, scalarBaseMul, randScalar } from "../tss/bjj.js";
import {
  assertSelfNoteDiscoverable,
  multisigDepositEph as deriveMultisigDepositEph,
} from "../frost/index.js";
import {
  InMemoryEphemeralCounterStore,
  SealedEphemeralCounterStore,
  type EphemeralCounterStore,
} from "../state/EphemeralCounterStore.js";
import { isEvenY } from "../note/keys.js";
import { Poseidon } from "../crypto/Poseidon.js";
import { deriveCek } from "../crypto/kem.js";
import { demEncrypt } from "../crypto/dem.js";
import { leaf as computeLeaf, Note } from "../note/note.js";
import { computePsi, computeNullifier } from "../note/nullifier.js";
import { completeComplianceHistory } from "../note/complianceKeys.js";
import { SelfMintPreflight } from "../discovery/preflight.js";
import type { SelfMintAuthorization } from "../discovery/preflight.js";
import {
  CIPHERTEXT_KEPT_INDICES,
  COMMITMENT_PREFIX_BYTES,
  HOWL_NOTE_LAYOUT_VERSION,
  RECORD_KIND_INCOMING,
  type HowlNoteRecord,
} from "../discovery/types.js";

const DOMAIN = {
  chainId: 31337n,
  poolAddress: "0x0000000000000000000000000000000000000001",
  deploymentAnchor: 1n,
};
const MISS_RECORD: HowlNoteRecord = {
  layoutVersion: HOWL_NOTE_LAYOUT_VERSION,
  recordKind: RECORD_KIND_INCOMING,
  leafIndex: 0,
  commitmentPrefix: new Uint8Array(COMMITMENT_PREFIX_BYTES),
  ephemeralPkX: Fr.ZERO,
  cekWrap: Fr.ZERO,
  ciphertextKept: CIPHERTEXT_KEPT_INDICES.map(() => Fr.ZERO),
};
const TEST_GPK = scalarBaseMul(0x12345n);

function multisigDepositEph(
  v: Fr,
  memberId: bigint,
  counters: EphemeralCounterStore,
  gpk: Point = TEST_GPK,
) {
  return deriveMultisigDepositEph(v, memberId, counters, gpk);
}

function historyFor(compliancePk: Point) {
  return completeComplianceHistory({
    genesisPk: compliancePk,
    rotations: [],
    currentPk: compliancePk,
    currentVersion: 1,
  });
}

function evenYViewKey(): Fr {
  for (let i = 0; i < 256; i++) {
    const v = new Fr(randScalar());
    if (isEvenY(scalarBaseMul(v.toBigInt()))) return v;
  }
  throw new Error("no even-y view key sampled");
}

async function preflighted(
  mint: MultisigSelfMint,
  compliancePk: Point,
  gpk: Point,
) {
  const preflight = new SelfMintPreflight({
    allocator: { next: () => Promise.resolve(mint) },
    discovery: {
      probeFirst: (tags) =>
        Promise.resolve(
          tags.map((tag) => ({ tag, record: MISS_RECORD, occurrenceCount: 0 })),
        ),
      fetchOccurrences: () => Promise.resolve([]),
      fetchLeafBlock: () => Promise.resolve([]),
    },
    history: historyFor(compliancePk),
    ownerCommitment: new Fr(await multisigOwner(gpk)),
    domain: DOMAIN,
  });
  return (await preflight.take(1))[0];
}

function buildCheckedSelfNote(
  authorization: SelfMintAuthorization,
  compliancePk: Point,
  gpk: Point,
) {
  return buildSelfNote(
    authorization,
    compliancePk,
    1,
    historyFor(compliancePk),
    DOMAIN,
    gpk,
  );
}

async function encryptNote(
  cek: Fr,
  owner: Fr,
  value: bigint,
  asset: Fr,
): Promise<{ note: Note; commitment: Fr; ciphertext: Fr[] }> {
  const psi = await computePsi(cek);
  const note: Note = {
    noteVersion: new Fr(1n),
    assetId: asset,
    noteType: new Fr(NOTE_TYPE_MULTISIG),
    conditionsHash: new Fr(0n),
    value,
    owner,
    psi,
    parents: new Fr(0n),
  };
  const commitment = await computeLeaf(note);
  const ciphertext = await demEncrypt(cek, [
    note.noteVersion,
    note.assetId,
    note.noteType,
    note.conditionsHash,
    new Fr(value),
    note.owner,
    note.parents,
  ]);
  return { note, commitment, ciphertext };
}

describe("multisig note VIEW layer (FROST accounts, decoupled owner/view, member-partitioned self)", () => {
  const gpk: Point = scalarBaseMul(randScalar());
  const compliancePk: Point = scalarBaseMul(randScalar());
  const v = evenYViewKey();

  // An odd-y v is no longer rejected: the index rolls until V lands even-y, matching the standard path.
  it("address: owner = Poseidon2(gpk), V even-y, and any v yields a usable address", async () => {
    const { ownerCommitment, viewPub } = await multisigAddress(gpk, v);
    expect(ownerCommitment.toBigInt()).toBe(await multisigOwner(gpk));
    expect(isEvenY(viewPub)).toBe(true);

    let oddV = new Fr(randScalar());
    while (isEvenY(scalarBaseMul(oddV.toBigInt()))) oddV = new Fr(randScalar());
    const rolled = await multisigAddress(gpk, oddV);
    expect(isEvenY(rolled.viewPub)).toBe(true);
  });

  // The treasury-clustering fix: distinct indices must yield distinct on-chain tags, or one log filter
  // recovers a group's entire inbound history.
  it("address: rotating the index yields a different tag under the same group", async () => {
    const a = await multisigAddress(gpk, v, 0n);
    const b = await multisigAddress(gpk, v, a.index + 1n);
    expect(b.index).toBeGreaterThan(a.index);
    expect(b.viewPub[0]).not.toBe(a.viewPub[0]);
    // The group identity is unchanged; only the receiving address rotated.
    expect(b.ownerCommitment.toBigInt()).toBe(a.ownerCommitment.toBigInt());
  });

  it("address: derivation is deterministic across members holding the same v", async () => {
    const first = await multisigAddress(gpk, v, 7n);
    const second = await multisigAddress(gpk, v, 7n);
    expect(second.index).toBe(first.index);
    expect(second.viewPub[0]).toBe(first.viewPub[0]);
  });

  it("incoming: owner decoupled to gpk, member recovers the SAME cek via the rotated key, tag = V.x", async () => {
    const { index, viewKey, viewPub } = await multisigIncomingKeyAt(v, 0n);
    const { ownerCommitment } = await multisigAddress(gpk, v, index);
    const eph = new Fr(randScalar());
    const built = await buildIncomingMultisigNote(
      eph,
      compliancePk,
      gpk,
      viewPub,
    );

    expect(built.owner.toBigInt()).toBe(ownerCommitment.toBigInt());
    expect(built.tag.equals(new Fr(viewPub[0]))).toBe(true);

    // The wrap targets the rotated point, so only the rotated secret opens it.
    const recovered = await memberReadIncoming(
      built.cekWrap,
      viewKey,
      built.ephPub,
    );
    expect(recovered.equals(built.cek)).toBe(true);
  });

  it("self/change: member-partitioned eph, member re-derives the same cek; tag = eph_pub.x", async () => {
    const memberId = 2n;
    const j = 7n;
    const selfTag = await canonicalMultisigSelfTag(v, memberId, j);
    const self = {
      cek: deriveCek(selfTag.eph, compliancePk),
      tag: selfTag.tag,
      ephPub: selfTag.ephPub,
    };
    const recovered = await memberReadSelf(
      v,
      memberId,
      selfTag.j,
      compliancePk,
    );

    expect(recovered.equals(self.cek)).toBe(true);
    expect(self.tag.equals(new Fr(self.ephPub[0]))).toBe(true);
  });

  it("member partitioning: disjoint sub-sequences (member_id or j change -> distinct eph)", async () => {
    const a = await deriveSelfEph(v, 1n, 0n);
    const b = await deriveSelfEph(v, 2n, 0n);
    const c = await deriveSelfEph(v, 1n, 1n);
    expect(a.ephPub[0]).not.toBe(b.ephPub[0]);
    expect(a.ephPub[0]).not.toBe(c.ephPub[0]);
  });

  it("two spends never collide even if two members reuse the same counter index", async () => {
    const m1 = await deriveSelfEph(v, 1n, 0n);
    const m3 = await deriveSelfEph(v, 3n, 0n);
    expect(m1.eph.equals(m3.eph)).toBe(false);
    expect(m1.ephPub[0]).not.toBe(m3.ephPub[0]);
  });

  it("canonicalMultisigSelfTag rolls j to an even-y eph_pub", async () => {
    const tag = await canonicalMultisigSelfTag(v, 4n, 0n);
    expect(isEvenY(tag.ephPub)).toBe(true);
    expect(tag.tag.equals(new Fr(tag.ephPub[0]))).toBe(true);
    const again = await deriveSelfEph(v, 4n, tag.j);
    expect(again.eph.equals(tag.eph)).toBe(true);
  });

  it("KAT: member-partitioned eph_pub.x is deterministic for fixed (v, member_id, j)", async () => {
    const vFixed = new Fr(1234567890123456789012345678901234567890n);
    const { eph, ephPub } = await deriveSelfEph(vFixed, 2n, 0n);
    const again = await deriveSelfEph(vFixed, 2n, 0n);
    expect(again.eph.equals(eph)).toBe(true);
    const hex = "0x" + ephPub[0].toString(16).padStart(64, "0");
    expect(hex).toBe(
      "0x00a937691bbf2bbc3e7e7da64f2dc273e991f408fa56a7460d73c6a9ab6c525c",
    );
  });
});

describe("multisig scan: read a MULTISIG note end to end (incoming + self)", () => {
  it("reads an incoming note (V.x tag) and a self note (member eph tag) into MultisigNoteView", async () => {
    const gpk: Point = scalarBaseMul(randScalar());
    const compliancePk: Point = scalarBaseMul(randScalar());
    const v = evenYViewKey();
    const asset = new Fr(0xabcdefn);
    const memberIds = [1n, 2n, 3n, 4n, 5n];
    const scanner = await MultisigScanner.create({
      v,
      gpk,
      compliancePk,
      memberIds,
      selfWindow: 16,
    });
    const { viewPub, ownerCommitment } = await multisigAddress(gpk, v);

    let eph = new Fr(randScalar());
    while (!isEvenY(scalarBaseMul(eph.toBigInt()))) eph = new Fr(randScalar());
    const inc = await buildIncomingMultisigNote(
      eph,
      compliancePk,
      gpk,
      viewPub,
    );
    const incEnc = await encryptNote(inc.cek, inc.owner, 100n, asset);
    const incView = await scanner.readNote(
      incomingNoteEvent({
        leafIndex: 3n,
        commitment: incEnc.commitment,
        ephPub: inc.ephPub,
        tag: inc.tag,
        cekWrap: inc.cekWrap,
        packedCiphertext: incEnc.ciphertext,
      }),
    );
    expect(incView).not.toBeNull();
    expect(incView!.isIncoming).toBe(true);
    expect(incView!.note.value).toBe(100n);
    expect(incView!.note.owner.equals(ownerCommitment)).toBe(true);
    expect(incView!.note.noteType.toBigInt()).toBe(NOTE_TYPE_MULTISIG);
    const expectedPsi = await computePsi(inc.cek);
    expect(
      incView!.nullifier.equals(
        await computeNullifier(expectedPsi, new Fr(3n)),
      ),
    ).toBe(true);

    const selfTag = await canonicalMultisigSelfTag(v, 2n, 0n);
    const self = {
      cek: deriveCek(selfTag.eph, compliancePk),
      ephPub: selfTag.ephPub,
    };
    const selfEnc = await encryptNote(self.cek, ownerCommitment, 50n, asset);
    const selfView = await scanner.readNote(
      selfNoteEvent({
        leafIndex: 4n,
        note: selfEnc.note,
        commitment: selfEnc.commitment,
        ephPub: self.ephPub,
        packedCiphertext: selfEnc.ciphertext,
      }),
    );
    expect(selfView).not.toBeNull();
    expect(selfView!.isIncoming).toBe(false);
    expect(selfView!.memberId).toBe(2n);
    expect(selfView!.note.value).toBe(50n);
    expect(selfView!.note.owner.equals(ownerCommitment)).toBe(true);
  });

  it("ignores a note that is not this account's (foreign tag)", async () => {
    const gpk: Point = scalarBaseMul(randScalar());
    const compliancePk: Point = scalarBaseMul(randScalar());
    const v = evenYViewKey();
    const scanner = await MultisigScanner.create({
      v,
      gpk,
      compliancePk,
      memberIds: [1n, 2n, 3n],
      selfWindow: 16,
    });
    const otherV = evenYViewKey();
    const otherTag = await canonicalMultisigSelfTag(otherV, 1n, 0n);
    const otherSelf = {
      cek: deriveCek(otherTag.eph, compliancePk),
      ephPub: otherTag.ephPub,
    };
    const enc = await encryptNote(
      otherSelf.cek,
      new Fr(await multisigOwner(gpk)),
      1n,
      new Fr(0x1n),
    );
    const view = await scanner.readNote(
      selfNoteEvent({
        leafIndex: 0n,
        note: enc.note,
        commitment: enc.commitment,
        ephPub: otherSelf.ephPub,
        packedCiphertext: enc.ciphertext,
      }),
    );
    expect(view).toBeNull();
  });

  it("skips a poisoned event (malformed ciphertext) and still resolves the good notes", async () => {
    const gpk: Point = scalarBaseMul(randScalar());
    const compliancePk: Point = scalarBaseMul(randScalar());
    const v = evenYViewKey();
    const asset = new Fr(0xfeedn);
    const scanner = await MultisigScanner.create({
      v,
      gpk,
      compliancePk,
      memberIds: [1n, 2n, 3n],
      selfWindow: 16,
    });
    const { viewPub, ownerCommitment } = await multisigAddress(gpk, v);

    let eph = new Fr(randScalar());
    while (!isEvenY(scalarBaseMul(eph.toBigInt()))) eph = new Fr(randScalar());
    const inc = await buildIncomingMultisigNote(
      eph,
      compliancePk,
      gpk,
      viewPub,
    );
    const incEnc = await encryptNote(inc.cek, inc.owner, 100n, asset);
    const goodIncoming = incomingNoteEvent({
      leafIndex: 1n,
      commitment: incEnc.commitment,
      ephPub: inc.ephPub,
      tag: inc.tag,
      cekWrap: inc.cekWrap,
      packedCiphertext: incEnc.ciphertext,
    });

    const selfTag = await canonicalMultisigSelfTag(v, 2n, 0n);
    const self = {
      cek: deriveCek(selfTag.eph, compliancePk),
      ephPub: selfTag.ephPub,
    };
    const selfEnc = await encryptNote(self.cek, ownerCommitment, 50n, asset);
    const goodSelf = selfNoteEvent({
      leafIndex: 3n,
      note: selfEnc.note,
      commitment: selfEnc.commitment,
      ephPub: self.ephPub,
      packedCiphertext: selfEnc.ciphertext,
    });

    const poisoned = incomingNoteEvent({
      leafIndex: 2n,
      commitment: incEnc.commitment,
      ephPub: inc.ephPub,
      tag: inc.tag,
      cekWrap: inc.cekWrap,
      packedCiphertext: incEnc.ciphertext,
    });
    poisoned.args.packedCiphertext = [
      "0x1",
      "not-a-field-element",
      "0x3",
      "0x4",
      "0x5",
      "0x6",
      "0x7",
    ];

    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const views: MultisigNoteView[] = [];
    for (const ev of [goodIncoming, poisoned, goodSelf]) {
      const view = await scanner.readNote(ev);
      if (view) views.push(view);
    }

    expect(warnSpy).toHaveBeenCalledTimes(1);
    const logged = String(warnSpy.mock.calls[0][0]);
    expect(logged).toContain("leaf=2");
    warnSpy.mockRestore();

    expect(views.length).toBe(2);
    expect(views.some((x) => x.isIncoming && x.note.value === 100n)).toBe(true);
    expect(views.some((x) => !x.isIncoming && x.note.value === 50n)).toBe(true);
  });
});

describe("multisig deposit ephemerals are derived, not sampled", () => {
  async function group(): Promise<{
    v: Fr;
    gpk: Point;
    compliancePk: Point;
    ownerCommitment: Fr;
    asset: Fr;
  }> {
    const gpk: Point = scalarBaseMul(randScalar());
    const compliancePk: Point = scalarBaseMul(randScalar());
    const v = evenYViewKey();
    const ownerCommitment = new Fr(await multisigOwner(gpk));
    return { v, gpk, compliancePk, ownerCommitment, asset: new Fr(7n) };
  }

  // A valid derived deposit must be discoverable by a scanner holding only v.
  it("a deposit is discoverable by a v-only scanner with no prior state", async () => {
    const { v, gpk, compliancePk, ownerCommitment, asset } = await group();
    const counters = new InMemoryEphemeralCounterStore();
    const mint = await multisigDepositEph(v, 3n, counters, gpk);
    const self = await buildCheckedSelfNote(
      await preflighted(mint, compliancePk, gpk),
      compliancePk,
      gpk,
    );
    const enc = await encryptNote(self.cek, ownerCommitment, 250n, asset);

    const scanner = await MultisigScanner.create({
      v,
      gpk,
      compliancePk,
      memberIds: [3n],
    });
    const view = await scanner.readNote(
      selfNoteEvent({
        leafIndex: 9n,
        note: enc.note,
        commitment: enc.commitment,
        ephPub: mint.ephPub,
        packedCiphertext: enc.ciphertext,
      }),
    );
    expect(view).not.toBeNull();
    expect(view!.isIncoming).toBe(false);
    expect(view!.memberId).toBe(3n);
    expect(view!.note.value).toBe(250n);
  });

  it("binds one-shot authorization to the multisig group", async () => {
    const { v, gpk, compliancePk } = await group();
    const mint = await multisigDepositEph(
      v,
      4n,
      new InMemoryEphemeralCounterStore(),
      gpk,
    );
    const authorization = await preflighted(mint, compliancePk, gpk);
    const wrongGroup = scalarBaseMul(randScalar());

    const mutableMint = await multisigDepositEph(
      v,
      5n,
      new InMemoryEphemeralCounterStore(),
      gpk,
    );
    const sampledEph = evenYViewKey();
    const sampledPub = scalarBaseMul(sampledEph.toBigInt());
    Reflect.set(mutableMint, "eph", sampledEph);
    Reflect.set(mutableMint, "ephPub", sampledPub);
    Reflect.set(mutableMint, "tag", new Fr(sampledPub[0]));
    await expect(
      preflighted(mutableMint, compliancePk, gpk),
    ).rejects.toMatchObject({ reason: "CANDIDATE_PROVENANCE_MISMATCH" });

    await expect(
      preflighted(mint, compliancePk, wrongGroup),
    ).rejects.toMatchObject({ reason: "CANDIDATE_OWNER_MISMATCH" });

    await expect(
      buildCheckedSelfNote(authorization, compliancePk, wrongGroup),
    ).rejects.toThrow(/context/);
    await expect(
      buildCheckedSelfNote(authorization, compliancePk, gpk),
    ).resolves.toBeDefined();
    await expect(
      buildCheckedSelfNote(authorization, compliancePk, gpk),
    ).rejects.toThrow(/consumed/);
  });

  it("consecutive deposits take different indices, so no ephemeral is reused", async () => {
    const { v } = await group();
    const counters = new InMemoryEphemeralCounterStore();
    const a = await multisigDepositEph(v, 1n, counters);
    const b = await multisigDepositEph(v, 1n, counters);
    expect(a.j).not.toBe(b.j);
    expect(a.eph.equals(b.eph)).toBe(false);
    expect(a.tag.equals(b.tag)).toBe(false);
  });

  it("refuses to mint without a durable counter", async () => {
    const { v } = await group();
    await expect(
      multisigDepositEph(v, 1n, new SealedEphemeralCounterStore()),
    ).rejects.toThrow(/durable ephemeral counter/);
  });

  it("hands out no index when the durable write fails", async () => {
    const { v } = await group();
    const counters = new InMemoryEphemeralCounterStore();
    const scope = `msSelf:${(await Poseidon.hash([v])).toString()}:2`;
    const first = await multisigDepositEph(v, 2n, counters);
    const highWater = await counters.highWater(scope);

    // reserve() throws BEFORE advancing the high-water, so the failure must consume nothing.
    counters.failNextWrite();
    await expect(multisigDepositEph(v, 2n, counters)).rejects.toThrow(
      /durable write failed/,
    );
    expect(await counters.highWater(scope)).toBe(highWater);

    const after = await multisigDepositEph(v, 2n, counters);
    expect(after.j).not.toBe(first.j);
    expect(after.eph.equals(first.eph)).toBe(false);
  });

  // Odd-y indices are burned because derivation is deterministic in (v, memberId, j).
  it("burns an odd-y index so a retry never re-derives it", async () => {
    const { v } = await group();
    const counters = new InMemoryEphemeralCounterStore();
    const scope = `msSelf:${(await Poseidon.hash([v])).toString()}:9`;

    const mints = [];
    for (let i = 0; i < 8; i++) {
      mints.push(await multisigDepositEph(v, 9n, counters));
    }
    // Every index strictly advances, and the counter never revisits one.
    const seen = mints.map((m) => m.j);
    expect(new Set(seen.map(String)).size).toBe(seen.length);
    for (let i = 1; i < seen.length; i++) {
      expect(seen[i] > seen[i - 1]).toBe(true);
    }
    // The high-water is past the last index used, including any odd-y indices burned along the way.
    expect(BigInt(await counters.highWater(scope))).toBeGreaterThan(
      seen[seen.length - 1],
    );
  });

  it("keeps each group and member on its own counter scope", async () => {
    const one = await group();
    const two = await group();
    const counters = new InMemoryEphemeralCounterStore();
    await multisigDepositEph(one.v, 1n, counters);
    const otherGroup = await multisigDepositEph(two.v, 1n, counters);
    const otherMember = await multisigDepositEph(one.v, 2n, counters);
    // Asserted on the scope keys themselves. Comparing indices is vacuous: a fully shared scope still
    // produces small indices, so it passes either way.
    const scopes = Object.keys(counters.snapshot()).sort();
    expect(scopes).toHaveLength(3);
    // Keyed on a commitment to v, so two groups and two members each get their own line, and rotating
    // gpk while v survives does NOT reset the counter.
    const oneKey = (await Poseidon.hash([one.v])).toString();
    const twoKey = (await Poseidon.hash([two.v])).toString();
    expect(scopes).toContain(`msSelf:${oneKey}:1`);
    expect(scopes).toContain(`msSelf:${oneKey}:2`);
    expect(scopes).toContain(`msSelf:${twoKey}:1`);
    expect(otherGroup.j).toBeDefined();
    expect(otherMember.j).toBeDefined();
  });

  it("the pre-flight refuses a note the scanner cannot open", async () => {
    const { v, gpk, compliancePk, ownerCommitment, asset } = await group();
    const scanner = await MultisigScanner.create({
      v,
      gpk,
      compliancePk,
      memberIds: [1n],
    });

    // A sampled self ephemeral has no seed-derived scanner tag.
    const strayEph = new Fr(randScalar());
    const strayPub = scalarBaseMul(strayEph.toBigInt());
    const cek = await memberReadSelf(v, 1n, 0n, compliancePk);
    const enc = await encryptNote(cek, ownerCommitment, 10n, asset);

    await expect(
      assertSelfNoteDiscoverable(scanner, {
        leafIndex: 1n,
        note: enc.note,
        commitment: enc.commitment,
        ephPub: strayPub,
        packedCiphertext: enc.ciphertext,
      }),
    ).rejects.toThrow(/not discoverable/);
  });

  it("finds a note minted beyond the initial scan window after a lookahead", async () => {
    const { v, gpk, compliancePk, ownerCommitment, asset } = await group();
    const scanner = await MultisigScanner.create({
      v,
      gpk,
      compliancePk,
      memberIds: [4n],
      selfWindow: 16,
    });

    // Far past the two indices the scanner registered at construction.
    const far = await canonicalMultisigSelfTag(v, 4n, 40n);
    const self = { cek: deriveCek(far.eph, compliancePk), ephPub: far.ephPub };
    const enc = await encryptNote(self.cek, ownerCommitment, 5n, asset);
    const event = selfNoteEvent({
      leafIndex: 2n,
      note: enc.note,
      commitment: enc.commitment,
      ephPub: far.ephPub,
      packedCiphertext: enc.ciphertext,
    });

    expect(await scanner.readNote(event)).toBeNull();
    expect(await scanner.ensureSelfLookahead(64)).toBe(true);
    expect(await scanner.readNote(event)).not.toBeNull();
  });

  // A crash after reserve burns one index; recovery must continue beyond it.
  it("burns one index on a crash, and the next note is still discoverable", async () => {
    const { v, gpk, compliancePk, ownerCommitment, asset } = await group();
    const counters = new InMemoryEphemeralCounterStore();
    const scope = `msSelf:${(await Poseidon.hash([v])).toString()}:5`;

    // Reserve and never commit or release: the crash.
    await counters.reserve(scope, 1);
    expect(await counters.highWater(scope)).toBe(1);

    const recovered = await multisigDepositEph(v, 5n, counters, gpk);
    const self = await buildCheckedSelfNote(
      await preflighted(recovered, compliancePk, gpk),
      compliancePk,
      gpk,
    );
    const enc = await encryptNote(self.cek, ownerCommitment, 1n, asset);

    const scanner = await MultisigScanner.create({
      v,
      gpk,
      compliancePk,
      memberIds: [5n],
    });
    const view = await scanner.readNote(
      selfNoteEvent({
        leafIndex: 3n,
        note: enc.note,
        commitment: enc.commitment,
        ephPub: recovered.ephPub,
        packedCiphertext: enc.ciphertext,
      }),
    );
    expect(view).not.toBeNull();
  });

  // A sampled self ephemeral produces a note the group's scanner cannot see.
  it("a sampled ephemeral yields a note the scanner cannot find", async () => {
    const { v, gpk, compliancePk, ownerCommitment, asset } = await group();
    const scanner = await MultisigScanner.create({
      v,
      gpk,
      compliancePk,
      memberIds: [1n],
    });
    const counters = new InMemoryEphemeralCounterStore();

    const derived = await multisigDepositEph(v, 1n, counters, gpk);
    const derivedEnc = await encryptNote(
      (
        await buildCheckedSelfNote(
          await preflighted(derived, compliancePk, gpk),
          compliancePk,
          gpk,
        )
      ).cek,
      ownerCommitment,
      10n,
      asset,
    );
    const found = await scanner.readNote(
      selfNoteEvent({
        leafIndex: 1n,
        note: derivedEnc.note,
        commitment: derivedEnc.commitment,
        ephPub: derived.ephPub,
        packedCiphertext: derivedEnc.ciphertext,
      }),
    );
    expect(found).not.toBeNull();

    // The same note shape, with a sampled scalar instead. Its tag is in no scanner map.
    const sampled = new Fr(randScalar());
    const sampledPub = scalarBaseMul(sampled.toBigInt());
    const sampledEnc = await encryptNote(
      await memberReadSelf(v, 1n, 0n, compliancePk),
      ownerCommitment,
      10n,
      asset,
    );
    const lost = await scanner.readNote(
      selfNoteEvent({
        leafIndex: 2n,
        note: sampledEnc.note,
        commitment: sampledEnc.commitment,
        ephPub: sampledPub,
        packedCiphertext: sampledEnc.ciphertext,
      }),
    );
    expect(lost).toBeNull();
  });

  // memberId participates in the salt, so member scopes must remain disjoint.
  it("never lets two members of one group collide on a tag", async () => {
    const { v } = await group();
    const counters = new InMemoryEphemeralCounterStore();
    const tags = new Set<string>();
    for (const memberId of [1n, 2n, 3n]) {
      for (let i = 0; i < 4; i++) {
        const mint = await multisigDepositEph(v, memberId, counters);
        tags.add(mint.tag.toString());
      }
    }
    expect(tags.size).toBe(12);
  });

  it("grows the incoming map only when it gains a key", async () => {
    const { v, gpk, compliancePk } = await group();
    const scanner = await MultisigScanner.create({
      v,
      gpk,
      compliancePk,
      memberIds: [1n],
      incomingWindow: 16,
    });
    // 64, not 8: multisigIncomingKeyAt rolls to even-y, so the scan index after a 2-address create is
    // unbounded above 2 and an unlucky view key can already sit past a small target. This was flaky at 8.
    expect(await scanner.ensureIncomingLookahead(64)).toBe(true);
    // Already covered, so nothing new is registered and it must say so.
    expect(await scanner.ensureIncomingLookahead(64)).toBe(false);
  });

  it("refuses a lookahead window below one", async () => {
    const { v, gpk, compliancePk } = await group();
    await expect(
      MultisigScanner.create({
        v,
        gpk,
        compliancePk,
        memberIds: [1n],
        selfWindow: 0,
      }),
    ).rejects.toThrow(/lookahead must be an integer of at least 16/);
  });

  // A positive case prevents an always-rejecting preflight from passing.
  it("the pre-flight accepts a note the scanner can open", async () => {
    const { v, gpk, compliancePk, ownerCommitment, asset } = await group();
    const scanner = await MultisigScanner.create({
      v,
      gpk,
      compliancePk,
      memberIds: [1n],
    });
    const counters = new InMemoryEphemeralCounterStore();
    const mint = await multisigDepositEph(v, 1n, counters, gpk);
    const enc = await encryptNote(
      (
        await buildCheckedSelfNote(
          await preflighted(mint, compliancePk, gpk),
          compliancePk,
          gpk,
        )
      ).cek,
      ownerCommitment,
      42n,
      asset,
    );
    const view = await assertSelfNoteDiscoverable(scanner, {
      leafIndex: 6n,
      note: enc.note,
      commitment: enc.commitment,
      ephPub: mint.ephPub,
      packedCiphertext: enc.ciphertext,
    });
    expect(view.note.value).toBe(42n);
    expect(view.memberId).toBe(1n);
  });

  // This fixed v has six odd-y candidates before the first usable index.
  it("reserves one index per odd-y attempt across a known odd-y run", async () => {
    const v = new Fr(0x2f1c9a4bd77e3051n);
    const inner = new InMemoryEphemeralCounterStore();
    let reserves = 0;
    const counting = {
      reserve: (scope: string, span: number) => {
        reserves++;
        return inner.reserve(scope, span);
      },
      highWater: (scope: string) => inner.highWater(scope),
    };

    const mint = await multisigDepositEph(v, 1n, counting);
    const scope = `msSelf:${(await Poseidon.hash([v])).toString()}:1`;

    expect(mint.j).toBe(6n);
    expect(reserves).toBe(7);
    // Six burned plus the one committed.
    expect(await inner.highWater(scope)).toBe(7);
  });
});
