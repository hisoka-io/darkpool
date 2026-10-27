import { Fr } from "@aztec/foundation/fields";
import type { Point } from "@zk-kit/baby-jubjub";
import type { ProofEnvelope } from "@hisoka/howl-protocol";
import type {
  NoteWitnessDto,
  StandardCircuitId,
  StandardWitnessByCircuit,
} from "@hisoka/howl-protocol/proving";
import {
  computeNullifier,
  demEncrypt,
  deriveCek,
  leaf,
  publicKey,
  wrapCek,
} from "@hisoka/wallets";
import { foldPath } from "@hisoka/wallets/tx";
import type { ProverPort } from "../../spend/pipeline.js";

const fr = (hex: string): Fr => new Fr(BigInt(hex));

function noteOf(n: NoteWitnessDto) {
  return {
    noteVersion: fr(n.note_version),
    assetId: fr(n.asset_id),
    noteType: fr(n.note_type),
    conditionsHash: fr(n.conditions_hash),
    value: BigInt(n.value),
    owner: fr(n.owner),
    psi: fr(n.psi),
    parents: fr(n.parents),
  };
}

/** leaf, eph.x, then the seven ciphertext words: the block every minted output occupies. */
async function output(
  n: NoteWitnessDto,
  eph: Fr,
  pk: Point<bigint>,
): Promise<Fr[]> {
  const note = noteOf(n);
  const ct = await demEncrypt(deriveCek(eph, pk), [
    note.noteVersion,
    note.assetId,
    note.noteType,
    note.conditionsHash,
    new Fr(note.value),
    note.owner,
    note.parents,
  ]);
  return [await leaf(note), new Fr(publicKey(eph)[0]), ...ct];
}

async function spent(
  n: NoteWitnessDto,
  index: string,
  path: readonly string[],
) {
  const note = noteOf(n);
  const commitment = await leaf(note);
  return {
    nullifier: await computeNullifier(note.psi, new Fr(BigInt(index))),
    root: await foldPath(commitment, Number(index), path.map(fr)),
  };
}

/**
 * The public outputs each standard circuit exposes, derived from the witness the way the circuit computes
 * them (nullifier from psi and index, root by folding the path, outputs by minting), independently of the
 * runtime's own binding table. Stands in for a real prover in unit tests; real proofs run in the hardhat
 * integration suite.
 */
export async function publicOutputs<C extends StandardCircuitId>(
  circuit: C,
  witness: StandardWitnessByCircuit[C],
): Promise<Fr[]> {
  switch (circuit) {
    case "deposit": {
      const w = witness as StandardWitnessByCircuit["deposit"];
      const pk: Point<bigint> = [
        BigInt(w.compliance_pubkey_x),
        BigInt(w.compliance_pubkey_y),
      ];
      const [l, e, ...ct] = await output(w.note, fr(w.eph), pk);
      const note = noteOf(w.note);
      return [
        fr(w.compliance_pubkey_x),
        fr(w.compliance_pubkey_y),
        l!,
        e!,
        new Fr(note.value),
        note.assetId,
        ...ct,
      ];
    }
    case "withdraw": {
      const w = witness as StandardWitnessByCircuit["withdraw"];
      const pk: Point<bigint> = [
        BigInt(w.compliance_pubkey_x),
        BigInt(w.compliance_pubkey_y),
      ];
      const s = await spent(w.old_note, w.old_note_index, w.old_note_path);
      return [
        new Fr(BigInt(w.withdraw_value)),
        fr(w._recipient),
        fr(w._intent_hash),
        fr(w.compliance_pubkey_x),
        fr(w.compliance_pubkey_y),
        s.nullifier,
        s.root,
        fr(w.old_note.asset_id),
        ...(await output(w.change_note, fr(w.change_eph), pk)),
      ];
    }
    case "transfer": {
      const w = witness as StandardWitnessByCircuit["transfer"];
      const pk: Point<bigint> = [
        BigInt(w.compliance_pubkey_x),
        BigInt(w.compliance_pubkey_y),
      ];
      const s = await spent(w.old_note, w.old_note_index, w.old_note_path);
      const memoEph = fr(w.memo_eph);
      const view: Point<bigint> = [
        BigInt(w.recipient_view_pub.x),
        BigInt(w.recipient_view_pub.y),
      ];
      const [ml, me, ...mct] = await output(w.memo_note, memoEph, pk);
      return [
        fr(w.compliance_pubkey_x),
        fr(w.compliance_pubkey_y),
        s.nullifier,
        s.root,
        ml!,
        me!,
        new Fr(view[0]),
        await wrapCek(deriveCek(memoEph, pk), memoEph, view),
        ...mct,
        ...(await output(w.change_note, fr(w.change_eph), pk)),
      ];
    }
    case "split": {
      const w = witness as StandardWitnessByCircuit["split"];
      const pk: Point<bigint> = [
        BigInt(w.compliance_pubkey_x),
        BigInt(w.compliance_pubkey_y),
      ];
      const s = await spent(w.note_in, w.index_in, w.path_in);
      return [
        fr(w.compliance_pubkey_x),
        fr(w.compliance_pubkey_y),
        s.nullifier,
        s.root,
        ...(await output(w.note_out_1, fr(w.eph_1), pk)),
        ...(await output(w.note_out_2, fr(w.eph_2), pk)),
      ];
    }
    case "join": {
      const w = witness as StandardWitnessByCircuit["join"];
      const pk: Point<bigint> = [
        BigInt(w.compliance_pubkey_x),
        BigInt(w.compliance_pubkey_y),
      ];
      const a = await spent(w.note_a, w.index_a, w.path_a);
      const b = await spent(w.note_b, w.index_b, w.path_b);
      return [
        fr(w.compliance_pubkey_x),
        fr(w.compliance_pubkey_y),
        a.nullifier,
        b.nullifier,
        a.root,
        ...(await output(w.note_out, fr(w.eph_out), pk)),
      ];
    }
    case "public_claim": {
      const w = witness as StandardWitnessByCircuit["public_claim"];
      const pk: Point<bigint> = [
        BigInt(w.compliance_pubkey_x),
        BigInt(w.compliance_pubkey_y),
      ];
      return [
        fr(w.memo_id),
        fr(w.compliance_pubkey_x),
        fr(w.compliance_pubkey_y),
        new Fr(BigInt(w.current_timestamp)),
        ...(await output(w.note_out, fr(w.eph), pk)),
      ];
    }
    default:
      throw new Error(`no reference outputs for ${String(circuit)}`);
  }
}

const hex32 = (f: Fr): string =>
  `0x${f.toBigInt().toString(16).padStart(64, "0")}`;

/** A prover that records its calls and lets a test corrupt one output word or the verdict. */
export class ReferenceProver implements ProverPort {
  readonly calls: string[] = [];
  /** Replaces the public input at this index with this value. */
  corrupt: { readonly index: number; readonly value: Fr } | null = null;
  /** Drops the last public input. */
  truncate = false;
  verdict = true;
  failProve: Error | null = null;
  onProve: (() => Promise<void>) | null = null;

  async prove<C extends StandardCircuitId>(
    circuit: C,
    witness: StandardWitnessByCircuit[C],
  ): Promise<ProofEnvelope<C>> {
    this.calls.push(`prove:${circuit}`);
    if (this.failProve !== null) throw this.failProve;
    await this.onProve?.();
    const outputs = await publicOutputs(circuit, witness);
    if (this.corrupt !== null) outputs[this.corrupt.index] = this.corrupt.value;
    if (this.truncate) outputs.pop();
    return {
      circuit_id: circuit,
      proof: "0x00" as ProofEnvelope<C>["proof"],
      public_inputs: outputs.map(
        hex32,
      ) as unknown as ProofEnvelope<C>["public_inputs"],
    };
  }

  async verify<C extends StandardCircuitId>(
    envelope: ProofEnvelope<C>,
  ): Promise<boolean> {
    this.calls.push(`verify:${envelope.circuit_id}`);
    return this.verdict;
  }
}
