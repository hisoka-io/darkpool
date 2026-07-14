import { describe, it, expect, vi } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import {
  multisigAddress,
  buildIncomingMultisigNote,
  memberReadIncoming,
  deriveSelfEph,
  canonicalMultisigSelfTag,
  buildSelfNote,
  memberReadSelf,
  freshMultisigDepositEph,
  multisigOwner,
  NOTE_TYPE_MULTISIG,
  MultisigScanner,
  MultisigNoteView,
  selfNoteEvent,
  incomingNoteEvent,
} from "../frost/index.js";
import { Point, scalarBaseMul, randScalar } from "../tss/bjj.js";
import { isEvenY } from "../note/keys.js";
import { demEncrypt } from "../crypto/dem.js";
import { leaf as computeLeaf, Note } from "../note/note.js";
import { computePsi, computeNullifier } from "../note/nullifier.js";

function evenYViewKey(): Fr {
  for (let i = 0; i < 256; i++) {
    const v = new Fr(randScalar());
    if (isEvenY(scalarBaseMul(v.toBigInt()))) return v;
  }
  throw new Error("no even-y view key sampled");
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

  it("address: owner = Poseidon2(gpk), V = v*Base8 even-y; rejects an odd-y V", async () => {
    const { ownerCommitment, viewPub } = await multisigAddress(gpk, v);
    expect(ownerCommitment.toBigInt()).toBe(await multisigOwner(gpk));
    expect(isEvenY(viewPub)).toBe(true);

    let oddV = new Fr(randScalar());
    while (isEvenY(scalarBaseMul(oddV.toBigInt()))) oddV = new Fr(randScalar());
    await expect(multisigAddress(gpk, oddV)).rejects.toThrow(/odd y/i);
  });

  it("incoming: owner decoupled to gpk, member recovers the SAME cek via v, tag = V.x", async () => {
    const { viewPub, ownerCommitment } = await multisigAddress(gpk, v);
    const eph = new Fr(randScalar());
    const built = await buildIncomingMultisigNote(
      eph,
      compliancePk,
      gpk,
      viewPub,
    );

    expect(built.owner.toBigInt()).toBe(ownerCommitment.toBigInt());
    expect(built.tag.equals(new Fr(viewPub[0]))).toBe(true);

    const recovered = await memberReadIncoming(built.cekWrap, v, built.ephPub);
    expect(recovered.equals(built.cek)).toBe(true);
  });

  it("self/change: member-partitioned eph, member re-derives the same cek; tag = eph_pub.x", async () => {
    const memberId = 2n;
    const j = 7n;
    const { eph } = await deriveSelfEph(v, memberId, j);
    const self = buildSelfNote(eph, compliancePk);
    const recovered = await memberReadSelf(v, memberId, j, compliancePk);

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
    // Two members colliding on j=0 still yield distinct eph (no two-time-pad).
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

  it("self-funding deposit draws a fresh even-y eph, distinct each call", async () => {
    const d1 = await freshMultisigDepositEph();
    const d2 = await freshMultisigDepositEph();
    expect(isEvenY(d1.ephPub)).toBe(true);
    expect(isEvenY(d2.ephPub)).toBe(true);
    expect(d1.eph.equals(d2.eph)).toBe(false);
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
      selfWindow: 8,
    });
    const { viewPub, ownerCommitment } = await multisigAddress(gpk, v);

    // The emitted memo eph must be even-y so the member recovers it from x on-chain.
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
    const self = buildSelfNote(selfTag.eph, compliancePk);
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
      selfWindow: 4,
    });
    const otherV = evenYViewKey();
    const otherTag = await canonicalMultisigSelfTag(otherV, 1n, 0n);
    const otherSelf = buildSelfNote(otherTag.eph, compliancePk);
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
      selfWindow: 8,
    });
    const { viewPub, ownerCommitment } = await multisigAddress(gpk, v);

    // The emitted memo eph must be even-y so the member recovers it from x on-chain.
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
    const self = buildSelfNote(selfTag.eph, compliancePk);
    const selfEnc = await encryptNote(self.cek, ownerCommitment, 50n, asset);
    const goodSelf = selfNoteEvent({
      leafIndex: 3n,
      note: selfEnc.note,
      commitment: selfEnc.commitment,
      ephPub: self.ephPub,
      packedCiphertext: selfEnc.ciphertext,
    });

    // One ciphertext word is not a field element: the decode throws, and isolation MUST turn it into a skip.
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
