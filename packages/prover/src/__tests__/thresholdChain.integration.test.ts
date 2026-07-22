import { describe, it, expect } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import { Point, subOrder } from "@zk-kit/baby-jubjub";
import {
  leaf,
  computePsi,
  computeNullifier,
  deriveCek,
  demDecrypt,
  DEM_FIELDS,
  isEvenY,
  publicKey,
  pubkeyOwner,
  packParents,
  unpackParents,
  PARENTS_HIDDEN,
  recoverEvenY,
  LeanIMT,
  Note,
} from "@hisoka/wallets";
import * as frost from "@hisoka/wallets/frost";
import {
  partialDecrypt,
  combine,
  thresholdCek,
  forwardTrace,
  backwardTrace,
  Partial,
  ChainState,
  LeafData,
  DecryptNote,
} from "@hisoka/wallets/threshold";
import { runDkg, frostAccountDkg } from "@hisoka/wallets/unsafe-sim";
import { proveDeposit } from "../provers/standard/deposit.js";
import { proveTransfer } from "../provers/standard/transfer.js";
import { proveTransferMultisig } from "../provers/multisig/transferMultisig.js";
import { proveWithdrawMultisig } from "../provers/multisig/withdrawMultisig.js";
import { proveSplitMultisig } from "../provers/multisig/splitMultisig.js";
import { proveJoinMultisig } from "../provers/multisig/joinMultisig.js";
import { NoteInput } from "../types.js";

// Full-chain threshold-compliance over REAL proofs: a (t,n) committee (never reconstructs c) reproduces every
// nullifier from on-chain eph_pub+leaf_index and cross-checks it against each proof, so a circuit<->wallet
// divergence (KEM/psi/nullifier/parents) fails here. Spans standard+multisig and a multisig->standard convert.

const ASSET_ID = new Fr(0x1234567890123456789012345678901234567890n);
const NOTE_VERSION = new Fr(1n);
const NOTE_TYPE_STANDARD = new Fr(0n);
const NOTE_TYPE_MULTISIG = new Fr(1n);
const ZERO = new Fr(0n);
const TREE_DEPTH = 32;

const COMMITTEE_N = 5;
const COMMITTEE_T = 3;
const COMMITTEE_QUORUM = [1n, 2n, 3n];
const COMMITTEE_CTX = 0x484f574cn;

const ACCOUNT_N = 5;
const ACCOUNT_T = 3;
const ACCOUNT_CTX = 0x4d554c5449n;

/** A uniform BabyJubJub subgroup scalar (test randomness for ephemerals). */
function randSubgroupScalar(): bigint {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  let acc = 0n;
  for (const b of bytes) acc = (acc << 8n) | BigInt(b);
  const s = acc % subOrder;
  return s === 0n ? 1n : s;
}

/** A subgroup ephemeral whose public point is even-y (required as a self/deposit discovery tag). */
async function evenYEph(): Promise<Fr> {
  for (let i = 0; i < 256; i++) {
    const eph = new Fr(randSubgroupScalar());
    if (isEvenY(publicKey(eph))) return eph;
  }
  throw new Error("no even-y ephemeral sampled");
}

/** A subgroup keypair whose public point is even-y (a valid incoming view key). */
function evenYKeypair(): { scalar: Fr; pub: Point<bigint> } {
  for (let i = 0; i < 256; i++) {
    const scalar = new Fr(randSubgroupScalar());
    const pub = publicKey(scalar);
    if (isEvenY(pub)) return { scalar, pub };
  }
  throw new Error("no even-y keypair sampled");
}

/** Run a full FROST 2-round session: `signerIds` (a t-of-n quorum) jointly sign `m` under `gpk`. */
async function frostSign(
  gpk: Point,
  shares: Map<bigint, bigint>,
  signerIds: bigint[],
  m: bigint,
): Promise<{ R: Point; z: bigint }> {
  const cs = frost.bjjCiphersuite;
  const msg = frost.encodeMessage(m);

  type Round1 = Awaited<ReturnType<typeof frost.commit<Point>>>;
  const nonceById = new Map<bigint, Round1["nonces"]>();
  const commitments: Round1["commitment"][] = [];
  for (const id of signerIds) {
    const secret = shares.get(id);
    if (secret === undefined) throw new Error(`missing share for signer ${id}`);
    const hidingRandom = crypto.getRandomValues(new Uint8Array(32));
    const bindingRandom = crypto.getRandomValues(new Uint8Array(32));
    const { nonces, commitment } = await frost.commit(
      cs,
      id,
      secret,
      hidingRandom,
      bindingRandom,
    );
    nonceById.set(id, nonces);
    commitments.push(commitment);
  }

  const rhos = await frost.bindingFactors(cs, gpk, msg, commitments);
  const R = frost.groupCommitment(cs, commitments, rhos);

  const zShares: bigint[] = [];
  for (const id of signerIds) {
    const nonces = nonceById.get(id)!;
    const secret = shares.get(id)!;
    zShares.push(
      await frost.signShare(cs, id, nonces, secret, gpk, msg, commitments),
    );
  }

  const sig = frost.aggregate(cs, R, zShares);
  const ok = await frost.verify(cs, gpk, msg, sig);
  expect(ok).toBe(true);
  return { R: sig.R, z: sig.z };
}

function mkNote(
  noteType: Fr,
  value: bigint,
  owner: Fr,
  psi: Fr,
  parents: Fr,
): NoteInput {
  return {
    noteVersion: NOTE_VERSION,
    assetId: ASSET_ID,
    noteType,
    conditionsHash: ZERO,
    value: new Fr(value),
    owner,
    psi,
    parents,
  };
}

function toNote(n: NoteInput): Note {
  return {
    noteVersion: n.noteVersion,
    assetId: n.assetId,
    noteType: n.noteType,
    conditionsHash: n.conditionsHash,
    value: n.value.toBigInt(),
    owner: n.owner,
    psi: n.psi,
    parents: n.parents,
  };
}

function noteLeaf(n: NoteInput): Promise<Fr> {
  return leaf(toNote(n));
}

// An emitted output note read from a proof at its layout indices, plus its tree index.
interface Landed {
  index: number;
  ephPub: Point<bigint>;
  leaf: Fr;
  ciphertext: Fr[];
}

describe("thresholdChain: committee reproduces the spend graph over real proofs", () => {
  it("recovers every nullifier + the full lineage across a standard<->multisig chain", async () => {
    // Compliance committee: C = c*Base8 with (5,3) shares; c is never assembled.
    const committee = await runDkg(COMMITTEE_N, COMMITTEE_T, COMMITTEE_CTX);
    const C = committee.C;
    const cShares = committee.shares;
    const cV = committee.V;

    // FROST multisig account M: gpk (t-of-n spend), shared viewing key v (1-of-n view).
    const account = await frostAccountDkg(ACCOUNT_N, ACCOUNT_T, ACCOUNT_CTX);
    const gpk = account.gpk;
    const ownerM = account.owner;
    const vScalar = new Fr(account.viewKey);
    const accountQuorum = account.qual.slice(0, ACCOUNT_T);
    const selfMember = account.qual[0];

    // Two standard actors, each with an even-y view key so both can receive incoming memos: Bob (who receives
    // the converted note and re-spends it) and Alice (a downstream memo recipient).
    const alice = evenYKeypair();
    const ownerA = await pubkeyOwner(alice.pub);
    const bob = evenYKeypair();
    const ownerB = await pubkeyOwner(bob.pub);

    const psiFor = async (eph: Fr): Promise<Fr> =>
      computePsi(deriveCek(eph, C));

    async function committeeCek(ephPub: Point<bigint>): Promise<Fr> {
      const partials: Partial[] = await Promise.all(
        COMMITTEE_QUORUM.map((id) =>
          partialDecrypt(id, cShares.get(id)!, ephPub),
        ),
      );
      return thresholdCek(ephPub, partials, cV, COMMITTEE_T);
    }

    // The committee's nullifier for a note, from ONLY its on-chain eph_pub and leaf index (no plaintext).
    async function committeeNullifier(
      ephPub: Point<bigint>,
      leafIndex: number,
    ): Promise<Fr> {
      const cek = await committeeCek(ephPub);
      const psi = await computePsi(cek);
      return computeNullifier(psi, new Fr(BigInt(leafIndex)));
    }

    const committeeDecrypt: DecryptNote = async (ephPub, ciphertext) => {
      const cek = await committeeCek(ephPub);
      const fields = await demDecrypt(cek, ciphertext);
      return { fields, cek };
    };

    const tree = new LeanIMT(TREE_DEPTH);
    const leaves = new Map<number, LeafData>();
    const spent = new Map<string, number[]>();
    const markSpent = (nf: Fr, children: number[]): void => {
      spent.set(nf.toString(), children);
    };
    const chainState: ChainState = {
      getLeaf: (i) => leaves.get(i),
      nextLeafIndex: () => tree.nextLeafIndex,
      isNullifierSpent: (nf) => spent.has(nf.toString()),
      childrenOfSpend: (nf) => spent.get(nf.toString()) ?? [],
    };

    // Read an emitted output note from a proof at its layout indices and append it to the tree.
    async function land(
      outs: bigint[],
      leafIdx: number,
      epkIdx: number,
      ctBase: number,
    ): Promise<Landed> {
      const l = new Fr(outs[leafIdx]);
      // The output carries only eph_pub.x; recover the even-y point off-chain before ECDH.
      const ephPub: Point<bigint> = recoverEvenY(outs[epkIdx]);
      const ciphertext = outs
        .slice(ctBase, ctBase + DEM_FIELDS)
        .map((v) => new Fr(v));
      const index = tree.nextLeafIndex;
      await tree.insert(l);
      leaves.set(index, { ephPub, ciphertext, leaf: l });
      return { index, ephPub, leaf: l, ciphertext };
    }

    // Reserve leaf 0 with a genesis leaf so the real chain starts at index 1: a lone leaf-0 single-input
    // spend packs parents == 0, which the backward tracer reads as a deposit root (leaf-0 aliasing).
    const genesisNote = mkNote(
      NOTE_TYPE_STANDARD,
      1n,
      ownerA,
      await psiFor(await evenYEph()),
      ZERO,
    );
    await tree.insert(await noteLeaf(genesisNote));
    expect(tree.nextLeafIndex).toBe(1);

    // deposit (MULTISIG): account M is funded by a public self-deposit of 1000. A private transfer to a
    // multisig account is deferred, so the account receives value via deposit.
    const dmTag = await frost.canonicalMultisigSelfTag(vScalar, selfMember, 0n);
    const dmNote = mkNote(
      NOTE_TYPE_MULTISIG,
      1000n,
      ownerM,
      await psiFor(dmTag.eph),
      ZERO,
    );
    const dmLeafExpected = await noteLeaf(dmNote);
    const dep = await proveDeposit({
      compliancePk: C,
      note: dmNote,
      eph: dmTag.eph,
    });
    expect(dep.verified).toBe(true);
    const depOut = dep.publicInputs.map((p) => BigInt(p));
    expect(depOut[2]).toBe(dmLeafExpected.toBigInt());
    const dm = await land(depOut, 2, 3, 6);
    expect(dm.index).toBe(1);

    // transfer_multisig (MULTISIG -> STANDARD conversion): the account spends its deposit into a STANDARD
    // memo MB to Bob (400) plus a MULTISIG change TM (600) back to the account. Paying a standard recipient
    // binds owner == view == tag to the single address in_pub_j.
    const oldPath1 = tree.getMerklePath(dm.index);
    const root1 = tree.getRoot();
    const mbEph = await evenYEph();
    const tmTag = await frost.canonicalMultisigSelfTag(
      vScalar,
      selfMember,
      dmTag.j + 1n,
    );
    const parents1 = packParents([{ leafIndex: dm.index }, { leafIndex: 0 }]);
    const mbNote = mkNote(
      NOTE_TYPE_STANDARD,
      400n,
      ownerB,
      await psiFor(mbEph),
      PARENTS_HIDDEN,
    );
    const tmNote = mkNote(
      NOTE_TYPE_MULTISIG,
      600n,
      ownerM,
      await psiFor(tmTag.eph),
      parents1,
    );
    const mbLeafExpected = await noteLeaf(mbNote);
    const tmLeafExpected = await noteLeaf(tmNote);
    const nfDM = await computeNullifier(dmNote.psi, new Fr(BigInt(dm.index)));
    const mT = await frost.msgTransfer({
      root: root1.toBigInt(),
      nullifier: nfDM.toBigInt(),
      memoLeaf: mbLeafExpected.toBigInt(),
      changeLeaf: tmLeafExpected.toBigInt(),
      asset: ASSET_ID.toBigInt(),
    });
    const sigT = await frostSign(gpk, account.shares, accountQuorum, mT);
    const tmv = await proveTransferMultisig({
      compliancePk: C,
      gpk,
      frostR: sigT.R,
      frostZ: new Fr(sigT.z),
      recipientInPub: bob.pub,
      oldNote: dmNote,
      oldNoteIndex: dm.index,
      oldNotePath: oldPath1,
      memoNote: mbNote,
      memoEph: mbEph,
      changeNote: tmNote,
      changeEph: tmTag.eph,
    });
    expect(tmv.verified).toBe(true);
    const tmvOut = tmv.publicInputs.map((p) => BigInt(p));
    expect(tmvOut[4]).toBe(mbLeafExpected.toBigInt());
    expect(tmvOut[15]).toBe(tmLeafExpected.toBigInt());
    // The memo tag is Bob's static view tag (owner == view == in_pub_j for a standard recipient).
    expect(tmvOut[6]).toBe(bob.pub[0]);
    // FORWARD cross-check: the committee reproduces DM's spend nullifier from the deposit's on-chain eph_pub.
    expect((await committeeNullifier(dm.ephPub, dm.index)).toBigInt()).toBe(
      tmvOut[2],
    );
    const mb = await land(tmvOut, 4, 5, 8);
    const tm = await land(tmvOut, 15, 16, 17);
    markSpent(new Fr(tmvOut[2]), [mb.index, tm.index]);

    // transfer (standard): Bob spends the converted note MB into a STANDARD memo to Alice (150) plus a
    // STANDARD change back to Bob (250). The standard lineage descends from the conversion.
    const oldPath2 = tree.getMerklePath(mb.index);
    const maEph = await evenYEph();
    const chBobEph = await evenYEph();
    const parents2 = packParents([{ leafIndex: mb.index }, { leafIndex: 0 }]);
    const maNote = mkNote(
      NOTE_TYPE_STANDARD,
      150n,
      ownerA,
      await psiFor(maEph),
      PARENTS_HIDDEN,
    );
    const chBobNote = mkNote(
      NOTE_TYPE_STANDARD,
      250n,
      ownerB,
      await psiFor(chBobEph),
      parents2,
    );
    const ts = await proveTransfer({
      compliancePk: C,
      recipientInPub: alice.pub,
      oldNote: mbNote,
      spendScalar: bob.scalar,
      oldNoteIndex: mb.index,
      oldNotePath: oldPath2,
      memoNote: maNote,
      memoEph: maEph,
      changeNote: chBobNote,
      changeEph: chBobEph,
    });
    expect(ts.verified).toBe(true);
    const tsOut = ts.publicInputs.map((p) => BigInt(p));
    expect(tsOut[4]).toBe((await noteLeaf(maNote)).toBigInt());
    expect(tsOut[15]).toBe((await noteLeaf(chBobNote)).toBigInt());
    // FORWARD cross-check on MB (a standard INCOMING note spent here).
    expect((await committeeNullifier(mb.ephPub, mb.index)).toBigInt()).toBe(
      tsOut[2],
    );
    const ma = await land(tsOut, 4, 5, 8);
    const chBob = await land(tsOut, 15, 16, 17);
    markSpent(new Fr(tsOut[2]), [ma.index, chBob.index]);

    // withdraw_multisig: the account spends TM, pays 100 to a public recipient, mints MULTISIG change
    // Ch_M (500) back to the account (member-partitioned even-y self ephemeral).
    const oldPath3 = tree.getMerklePath(tm.index);
    const root3 = tree.getRoot();
    const chMTag = await frost.canonicalMultisigSelfTag(
      vScalar,
      selfMember,
      tmTag.j + 1n,
    );
    const withdrawValue = 100n;
    const parents3 = packParents([{ leafIndex: tm.index }, { leafIndex: 0 }]);
    const chMNote = mkNote(
      NOTE_TYPE_MULTISIG,
      600n - withdrawValue,
      ownerM,
      await psiFor(chMTag.eph),
      parents3,
    );
    const chMLeafExpected = await noteLeaf(chMNote);
    const nfTM = await computeNullifier(tmNote.psi, new Fr(BigInt(tm.index)));
    const recipient = new Fr(0x00c0ffee00c0ffee00c0ffee00c0ffee00c0ffeen);
    const mW = await frost.msgWithdraw({
      root: root3.toBigInt(),
      nullifier: nfTM.toBigInt(),
      changeLeaf: chMLeafExpected.toBigInt(),
      publicOut: withdrawValue,
      asset: ASSET_ID.toBigInt(),
      recipient: recipient.toBigInt(),
      intentHash: 0n,
    });
    const sigW = await frostSign(gpk, account.shares, accountQuorum, mW);
    const w = await proveWithdrawMultisig({
      withdrawValue: new Fr(withdrawValue),
      recipient,
      intentHash: ZERO,
      compliancePk: C,
      gpk,
      frostR: sigW.R,
      frostZ: new Fr(sigW.z),
      oldNote: tmNote,
      oldNoteIndex: tm.index,
      oldNotePath: oldPath3,
      changeNote: chMNote,
      changeEph: chMTag.eph,
    });
    expect(w.verified).toBe(true);
    const wOut = w.publicInputs.map((p) => BigInt(p));
    expect(wOut[8]).toBe(chMLeafExpected.toBigInt());
    // FORWARD cross-check on TM (multisig SELF note spent here).
    expect((await committeeNullifier(tm.ephPub, tm.index)).toBigInt()).toBe(
      wOut[5],
    );
    const chM = await land(wOut, 8, 9, 10);
    markSpent(new Fr(wOut[5]), [chM.index]);

    // Member + committee read of the MULTISIG SELF note Ch_M: the member re-derives its content via the
    // shared viewing key, and the member nullifier matches the committee's from on-chain data only.
    const scanner = await frost.MultisigScanner.create({
      v: vScalar,
      gpk,
      compliancePk: C,
      memberIds: account.qual,
    });
    const chMEvent = frost.selfNoteEvent({
      leafIndex: BigInt(chM.index),
      note: toNote(chMNote),
      commitment: chM.leaf,
      ephPub: chM.ephPub,
      packedCiphertext: chM.ciphertext,
    });
    const chMView = await scanner.readNote(chMEvent);
    expect(chMView).not.toBeNull();
    expect(chMView!.isIncoming).toBe(false);
    expect(chMView!.memberId).toBe(selfMember);
    expect(chMView!.note.value).toBe(500n);
    expect(chMView!.nullifier.toBigInt()).toBe(
      (await committeeNullifier(chM.ephPub, chM.index)).toBigInt(),
    );
    const chMFields = await demDecrypt(
      await committeeCek(chM.ephPub),
      chM.ciphertext,
    );
    expect(chMFields[4].toBigInt()).toBe(chMView!.note.value);
    expect(chMFields[5].equals(chMView!.note.owner)).toBe(true);

    // split_multisig: the account spends Ch_M into two MULTISIG self notes S1 (300) + S2 (200).
    const oldPath4 = tree.getMerklePath(chM.index);
    const root4 = tree.getRoot();
    const s1Tag = await frost.canonicalMultisigSelfTag(
      vScalar,
      selfMember,
      chMTag.j + 1n,
    );
    const s2Tag = await frost.canonicalMultisigSelfTag(
      vScalar,
      selfMember,
      s1Tag.j + 1n,
    );
    const parents4 = packParents([{ leafIndex: chM.index }, { leafIndex: 0 }]);
    const s1Note = mkNote(
      NOTE_TYPE_MULTISIG,
      300n,
      ownerM,
      await psiFor(s1Tag.eph),
      parents4,
    );
    const s2Note = mkNote(
      NOTE_TYPE_MULTISIG,
      200n,
      ownerM,
      await psiFor(s2Tag.eph),
      parents4,
    );
    const s1LeafExpected = await noteLeaf(s1Note);
    const s2LeafExpected = await noteLeaf(s2Note);
    const nfChM = await computeNullifier(
      chMNote.psi,
      new Fr(BigInt(chM.index)),
    );
    const mS = await frost.msgSplit({
      root: root4.toBigInt(),
      nullifier: nfChM.toBigInt(),
      out1Leaf: s1LeafExpected.toBigInt(),
      out2Leaf: s2LeafExpected.toBigInt(),
      asset: ASSET_ID.toBigInt(),
    });
    const sigS = await frostSign(gpk, account.shares, accountQuorum, mS);
    const sp = await proveSplitMultisig({
      compliancePk: C,
      gpk,
      frostR: sigS.R,
      frostZ: new Fr(sigS.z),
      noteIn: chMNote,
      indexIn: chM.index,
      pathIn: oldPath4,
      noteOut1: s1Note,
      eph1: s1Tag.eph,
      noteOut2: s2Note,
      eph2: s2Tag.eph,
    });
    expect(sp.verified).toBe(true);
    const spOut = sp.publicInputs.map((p) => BigInt(p));
    expect(spOut[4]).toBe(s1LeafExpected.toBigInt());
    expect(spOut[13]).toBe(s2LeafExpected.toBigInt());
    // FORWARD cross-check on Ch_M (multisig SELF note spent here).
    expect((await committeeNullifier(chM.ephPub, chM.index)).toBigInt()).toBe(
      spOut[2],
    );
    const s1 = await land(spOut, 4, 5, 6);
    const s2 = await land(spOut, 13, 14, 15);
    markSpent(new Fr(spOut[2]), [s1.index, s2.index]);

    // join_multisig: the account joins S1 + S2 into one MULTISIG self note J (500). Each input's quorum
    // signs the same message under gpk (two independent FROST sessions).
    const pathA = tree.getMerklePath(s1.index);
    const pathB = tree.getMerklePath(s2.index);
    const rootJ = tree.getRoot();
    const jTag = await frost.canonicalMultisigSelfTag(
      vScalar,
      selfMember,
      s2Tag.j + 1n,
    );
    const parentsJ = packParents([
      { leafIndex: s1.index },
      { leafIndex: s2.index },
    ]);
    const jNote = mkNote(
      NOTE_TYPE_MULTISIG,
      500n,
      ownerM,
      await psiFor(jTag.eph),
      parentsJ,
    );
    const jLeafExpected = await noteLeaf(jNote);
    const nfS1 = await computeNullifier(s1Note.psi, new Fr(BigInt(s1.index)));
    const nfS2 = await computeNullifier(s2Note.psi, new Fr(BigInt(s2.index)));
    const mJ = await frost.msgJoin({
      root: rootJ.toBigInt(),
      nullifierA: nfS1.toBigInt(),
      nullifierB: nfS2.toBigInt(),
      outLeaf: jLeafExpected.toBigInt(),
      asset: ASSET_ID.toBigInt(),
    });
    const sigJA = await frostSign(gpk, account.shares, accountQuorum, mJ);
    const sigJB = await frostSign(gpk, account.shares, accountQuorum, mJ);
    const jn = await proveJoinMultisig({
      compliancePk: C,
      gpkA: gpk,
      frostRA: sigJA.R,
      frostZA: new Fr(sigJA.z),
      noteA: s1Note,
      indexA: s1.index,
      pathA,
      gpkB: gpk,
      frostRB: sigJB.R,
      frostZB: new Fr(sigJB.z),
      noteB: s2Note,
      indexB: s2.index,
      pathB,
      noteOut: jNote,
      ephOut: jTag.eph,
    });
    expect(jn.verified).toBe(true);
    const jnOut = jn.publicInputs.map((p) => BigInt(p));
    expect(jnOut[5]).toBe(jLeafExpected.toBigInt());
    // FORWARD cross-check on BOTH joined self notes.
    expect((await committeeNullifier(s1.ephPub, s1.index)).toBigInt()).toBe(
      jnOut[2],
    );
    expect((await committeeNullifier(s2.ephPub, s2.index)).toBigInt()).toBe(
      jnOut[3],
    );
    const j = await land(jnOut, 5, 6, 7);
    markSpent(new Fr(jnOut[2]), [j.index]);
    markSpent(new Fr(jnOut[3]), [j.index]);

    // BACKWARD: the committee-decrypted `parents` field packs the real consumed leaf indices.
    const jParents = unpackParents(
      (await committeeDecrypt(j.ephPub, j.ciphertext)).fields[DEM_FIELDS - 1],
    );
    expect(jParents[0].leafIndex).toBe(s1.index);
    expect(jParents[1].leafIndex).toBe(s2.index);
    const chMParents = unpackParents(
      (await committeeDecrypt(chM.ephPub, chM.ciphertext)).fields[
        DEM_FIELDS - 1
      ],
    );
    expect(chMParents[0].leafIndex).toBe(tm.index);
    expect(chMParents[1].leafIndex).toBe(0);

    // MB hides parents (PARENTS_HIDDEN) so the recipient can't see the sender's leaf, yet compliance recovers
    // MB's source via its co-output TM (same spend nfDM), whose parents point to dm. Backward from MB terminates.
    const mbParentsField = (await committeeDecrypt(mb.ephPub, mb.ciphertext))
      .fields[DEM_FIELDS - 1];
    expect(mbParentsField.toBigInt()).toBe(PARENTS_HIDDEN.toBigInt());
    const mbBack = await backwardTrace(mb.index, chainState, committeeDecrypt);
    expect(mbBack.edges).toEqual([]);
    const tmSource = unpackParents(
      (await committeeDecrypt(tm.ephPub, tm.ciphertext)).fields[DEM_FIELDS - 1],
    );
    expect(tmSource[0].leafIndex).toBe(dm.index);

    // Compose the exact spend graph forward from the deposit and backward from the join output.
    const allNodes = [
      dm.index,
      mb.index,
      tm.index,
      ma.index,
      chBob.index,
      chM.index,
      s1.index,
      s2.index,
      j.index,
    ].sort((a, b) => a - b);
    const forwardEdges = (
      [
        [dm.index, mb.index],
        [dm.index, tm.index],
        [mb.index, ma.index],
        [mb.index, chBob.index],
        [tm.index, chM.index],
        [chM.index, s1.index],
        [chM.index, s2.index],
        [s1.index, j.index],
        [s2.index, j.index],
      ] as [number, number][]
    ).sort((a, b) => a[0] - b[0] || a[1] - b[1]);
    const forward = await forwardTrace(dm.index, chainState, committeeDecrypt);
    expect(forward.nodes).toEqual(allNodes);
    expect(forward.edges).toEqual(forwardEdges);

    // Lineage excludes the standard side branch (MB to Bob and its descendants Ma, Ch_Bob): siblings, not
    // ancestors, of J.
    const backNodes = [
      dm.index,
      tm.index,
      chM.index,
      s1.index,
      s2.index,
      j.index,
    ].sort((a, b) => a - b);
    const backEdges = (
      [
        [dm.index, tm.index],
        [tm.index, chM.index],
        [chM.index, s1.index],
        [chM.index, s2.index],
        [s1.index, j.index],
        [s2.index, j.index],
      ] as [number, number][]
    ).sort((a, b) => a[0] - b[0] || a[1] - b[1]);
    const backward = await backwardTrace(j.index, chainState, committeeDecrypt);
    expect(backward.nodes).toEqual(backNodes);
    expect(backward.edges).toEqual(backEdges);
  }, 1_800_000);

  it("a sub-threshold committee (t-1 valid partials) cannot recover the CEK", async () => {
    const committee = await runDkg(COMMITTEE_N, COMMITTEE_T, COMMITTEE_CTX);
    const ephPub = publicKey(new Fr(randSubgroupScalar()));
    const belowQuorum: Partial[] = await Promise.all(
      [1n, 2n].map((id) =>
        partialDecrypt(id, committee.shares.get(id)!, ephPub),
      ),
    );
    await expect(
      combine(ephPub, belowQuorum, committee.V, COMMITTEE_T),
    ).rejects.toThrow(/valid partials/i);
    await expect(
      thresholdCek(ephPub, belowQuorum, committee.V, COMMITTEE_T),
    ).rejects.toThrow(/valid partials/i);
  }, 60_000);
});
