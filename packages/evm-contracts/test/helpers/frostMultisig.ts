import { expect } from "chai";
import {
  Fr,
  toFr,
  deriveCek,
  computePsi,
  leaf,
  packParents,
} from "@hisoka/wallets";
import * as frost from "@hisoka/wallets/frost";
import { NoteInput, proveDeposit } from "@hisoka/prover";
import { Point } from "@zk-kit/baby-jubjub";
import { DarkPool, MockERC20 } from "../../typechain-types";
import { ContractRunner } from "ethers";
import { COMPLIANCE_PK, evenYEphemeral } from "./fixtures";

/** A MULTISIG note (note_type == 1) owned by a FROST account (owner == Poseidon2(gpk)), ECDH-encrypted to the
 *  compliance key. Returns the leaf commitment, the prover NoteInput view, and psi (for the nullifier). */
export async function buildMultisigNote(
  eph: Fr,
  value: bigint,
  owner: Fr,
  assetFr: Fr,
  parents: Fr,
): Promise<{ commitment: Fr; noteInput: NoteInput; psi: Fr }> {
  const cek = deriveCek(eph, COMPLIANCE_PK);
  const psi = await computePsi(cek);
  const commitment = await leaf({
    noteVersion: toFr(1n),
    assetId: assetFr,
    noteType: toFr(1n),
    conditionsHash: toFr(0n),
    value,
    owner,
    psi,
    parents,
  });
  const noteInput: NoteInput = {
    noteVersion: toFr(1n),
    assetId: assetFr,
    noteType: toFr(1n),
    conditionsHash: toFr(0n),
    value: toFr(value),
    owner,
    psi,
    parents,
  };
  return { commitment, noteInput, psi };
}

/** Run a full FROST 2-round session: `signerIds` (a t-of-n quorum) jointly sign `m` under `gpk`. */
export async function frostSign(
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
    const { nonces, commitment } = await frost.commit(
      cs,
      id,
      secret,
      crypto.getRandomValues(new Uint8Array(32)),
      crypto.getRandomValues(new Uint8Array(32)),
    );
    nonceById.set(id, nonces);
    commitments.push(commitment);
  }

  const rhos = await frost.bindingFactors(cs, gpk, msg, commitments);
  const R = frost.groupCommitment(cs, commitments, rhos);

  const zShares: bigint[] = [];
  for (const id of signerIds) {
    const nonces = nonceById.get(id);
    const secret = shares.get(id);
    if (nonces === undefined || secret === undefined)
      throw new Error(`missing nonce/share for signer ${id}`);
    zShares.push(
      await frost.signShare(cs, id, nonces, secret, gpk, msg, commitments),
    );
  }

  const sig = frost.aggregate(cs, R, zShares);
  expect(await frost.verify(cs, gpk, msg, sig)).to.equal(true);
  return { R: sig.R, z: sig.z };
}

/** Deposit a MULTISIG note (owner == Poseidon2(gpk)) so the account holds a spendable note at the next index.
 *  The deposit circuit asserts an even-y discovery tag, so the ephemeral is derived from `ephSeed`. */
export async function depositMultisig(
  darkPool: DarkPool,
  token: MockERC20,
  user: ContractRunner & { address: string },
  value: bigint,
  owner: Fr,
  assetFr: Fr,
  ephSeed: bigint,
): Promise<{ commitment: Fr; noteInput: NoteInput; psi: Fr }> {
  const eph = evenYEphemeral(ephSeed);
  const ms = await buildMultisigNote(eph, value, owner, assetFr, toFr(0n));
  const proof = await proveDeposit({
    compliancePk: COMPLIANCE_PK,
    note: ms.noteInput,
    eph,
  });
  await token.connect(user).approve(await darkPool.getAddress(), value);
  await darkPool.connect(user).deposit(proof.proof, proof.publicInputs);
  return ms;
}

export { packParents };
