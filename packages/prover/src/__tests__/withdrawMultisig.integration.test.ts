import { describe, it, expect } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import { Base8, mulPointEscalar, subOrder, Point } from "@zk-kit/baby-jubjub";
import {
  leaf,
  computePsi,
  computeNullifier,
  isEvenY,
  deriveCek,
} from "@hisoka/wallets";
import * as frost from "@hisoka/wallets/frost";
import { frostAccountDkg } from "@hisoka/wallets/unsafe-sim";
import { proveWithdrawMultisig } from "../provers/multisig/withdrawMultisig.js";
import { NoteInput } from "../types.js";

/** A uniform BabyJubJub subgroup scalar (test randomness for ephemerals and nonces). */
function randSubgroupScalar(): bigint {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  let acc = 0n;
  for (const b of bytes) acc = (acc << 8n) | BigInt(b);
  const s = acc % subOrder;
  return s === 0n ? 1n : s;
}

// Subgroup-valid compliance key (deposit parity fixture); circuit range-checks it in the prime-order subgroup.
const COMPLIANCE_PK: Point<bigint> = [
  0x085ed469c9a9f102b6d4f6f909b8ceaf6ca49b39759ac2e0feb7e0aada8b7111n,
  0x245e25ab2bd42f0280a5ade750828dd6868f5225ae798d6b51c676f519c8f4e8n,
];

const ASSET_ID = new Fr(0x1234567890123456789012345678901234567890n);
const NOTE_VERSION = new Fr(1n);
const NOTE_TYPE_MULTISIG = new Fr(1n);
const TREE_DEPTH = 32;

/** A subgroup ephemeral whose public point is even-y, required for a self/change note's discovery tag. */
function evenYEph(): Fr {
  for (let i = 0; i < 256; i++) {
    const eph = new Fr(randSubgroupScalar());
    if (isEvenY(mulPointEscalar(Base8, eph.toBigInt()))) return eph;
  }
  throw new Error("no even-y ephemeral sampled");
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

describe("proveWithdrawMultisig (FROST sign -> witness -> proof -> verify)", () => {
  it("a 3-of-5 quorum authorizes a multisig withdraw and the proof verifies", async () => {
    const account = await frostAccountDkg(5, 3, 0x484f574cn);
    const gpk = account.gpk;
    const owner = account.owner;
    const quorum = account.qual.slice(0, 3);

    // (b) MULTISIG old note owned by the account, in a single-leaf tree (index 0, root == leaf).
    const oldValue = 1000n;
    const withdrawValue = 300n;
    const changeValue = oldValue - withdrawValue;

    const oldPsi = await computePsi(
      deriveCek(new Fr(randSubgroupScalar()), COMPLIANCE_PK),
    );
    const oldNote: NoteInput = {
      noteVersion: NOTE_VERSION,
      assetId: ASSET_ID,
      noteType: NOTE_TYPE_MULTISIG,
      conditionsHash: new Fr(0n),
      value: new Fr(oldValue),
      owner,
      psi: oldPsi,
      parents: new Fr(0n),
    };
    const oldNoteIndex = 0;
    const oldNotePath = Array.from({ length: TREE_DEPTH }, () => new Fr(0n));

    const oldLeaf = await leaf({
      noteVersion: oldNote.noteVersion,
      assetId: oldNote.assetId,
      noteType: oldNote.noteType,
      conditionsHash: oldNote.conditionsHash,
      value: oldValue,
      owner: oldNote.owner,
      psi: oldNote.psi,
      parents: oldNote.parents,
    });
    // Single-leaf LeanIMT: every sibling is zero, so the root is the leaf itself.
    const root = oldLeaf;
    const nullifier = await computeNullifier(
      oldPsi,
      new Fr(BigInt(oldNoteIndex)),
    );

    // (b) MULTISIG change note back to the account; eph rolled even-y for the self discovery tag.
    const changeEph = evenYEph();
    const changeCek = deriveCek(changeEph, COMPLIANCE_PK);
    const changePsi = await computePsi(changeCek);
    const changeNote: NoteInput = {
      noteVersion: NOTE_VERSION,
      assetId: ASSET_ID,
      noteType: NOTE_TYPE_MULTISIG,
      conditionsHash: new Fr(0n),
      value: new Fr(changeValue),
      owner,
      psi: changePsi,
      parents: new Fr(0n), // pack(oldNoteIndex=0, 0) == 0
    };
    const changeLeaf = await leaf({
      noteVersion: changeNote.noteVersion,
      assetId: changeNote.assetId,
      noteType: changeNote.noteType,
      conditionsHash: changeNote.conditionsHash,
      value: changeValue,
      owner: changeNote.owner,
      psi: changeNote.psi,
      parents: changeNote.parents,
    });

    const recipient = new Fr(0x00c0ffee00c0ffee00c0ffee00c0ffee00c0ffeen);
    const intentHash = new Fr(0n);

    // (c) The spend message m, recomputed in-circuit from the constrained public IO.
    const m = await frost.msgWithdraw({
      root: root.toBigInt(),
      nullifier: nullifier.toBigInt(),
      changeLeaf: changeLeaf.toBigInt(),
      publicOut: withdrawValue,
      asset: ASSET_ID.toBigInt(),
      recipient: recipient.toBigInt(),
      intentHash: intentHash.toBigInt(),
    });

    const { R, z } = await frostSign(gpk, account.shares, quorum, m);

    const { verified, publicInputs } = await proveWithdrawMultisig({
      withdrawValue: new Fr(withdrawValue),
      recipient,
      intentHash,
      compliancePk: COMPLIANCE_PK,
      gpk,
      frostR: R,
      frostZ: new Fr(z),
      oldNote,
      oldNoteIndex,
      oldNotePath,
      changeNote,
      changeEph,
    });

    expect(verified).toBe(true);
    // Outputs: nullifier, root, asset, change_leaf, ... after the pub inputs.
    const outs = publicInputs.map((p) => BigInt(p));
    expect(outs).toContain(nullifier.toBigInt());
    expect(outs).toContain(root.toBigInt());
    expect(outs).toContain(changeLeaf.toBigInt());
  }, 300000);
});
