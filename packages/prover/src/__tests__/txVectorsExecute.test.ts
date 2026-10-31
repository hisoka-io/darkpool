/**
 * Every golden transaction witness must satisfy its compiled circuit. Byte-identity alone pins a witness the
 * circuit could still reject; executing it (witness generation only, no proof) closes that gap.
 *
 * The circuit's public outputs must also equal what the TypeScript SDK derives from the same witness, and the
 * frozen `derived` values. Without that, a TS drift regenerated into the vectors stays green: the circuit
 * recomputes leaf, root and ciphertext from the witness and never compares them with the SDK.
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join as joinPath, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { Fr } from "@aztec/foundation/fields";
import type { Point } from "@zk-kit/baby-jubjub";
import { Noir, type CompiledCircuit, type InputMap } from "@noir-lang/noir_js";
import {
  computeNullifier,
  computePsi,
  demEncrypt,
  deriveCek,
  isEvenY,
  leaf,
  publicKey,
  toFr,
  wrapCek,
  type Note,
} from "@hisoka/wallets";
import { foldPath } from "@hisoka/wallets/tx";
import { circuit as deposit } from "../generated/deposit_circuit.js";
import { circuit as withdraw } from "../generated/withdraw_circuit.js";
import { circuit as transfer } from "../generated/transfer_circuit.js";
import { circuit as split } from "../generated/split_circuit.js";
import { circuit as join } from "../generated/join_circuit.js";
import { circuit as public_claim } from "../generated/public_claim_circuit.js";

const VECTORS = joinPath(
  dirname(fileURLToPath(import.meta.url)),
  "../../tx-vectors.json",
);

const CIRCUITS = {
  deposit,
  withdraw,
  transfer,
  split,
  join,
  public_claim,
} as const;

type CircuitName = keyof typeof CIRCUITS;

const frozen = JSON.parse(readFileSync(VECTORS, "utf8")) as Record<
  CircuitName,
  { witness: InputMap; derived: Record<string, string | null> }
>;

function execute(name: CircuitName, witness: InputMap) {
  return new Noir(CIRCUITS[name] as CompiledCircuit).execute(witness);
}

type Witness = Record<string, unknown>;

function scalar(v: unknown, label: string): Fr {
  if (typeof v !== "string" && typeof v !== "number") {
    throw new Error(`witness field ${label} is not a scalar`);
  }
  return toFr(BigInt(v));
}

function field(w: Witness, key: string): Fr {
  return scalar(w[key], key);
}

function sub(w: Witness, key: string): Witness {
  const v = w[key];
  if (typeof v !== "object" || v === null || Array.isArray(v)) {
    throw new Error(`witness field ${key} is not a struct`);
  }
  return v as Witness;
}

function fields(w: Witness, key: string): Fr[] {
  const v = w[key];
  if (!Array.isArray(v))
    throw new Error(`witness field ${key} is not an array`);
  return v.map((x: unknown, i) => scalar(x, `${key}[${i}]`));
}

function point(w: Witness, key: string): Point<bigint> {
  const p = sub(w, key);
  return [field(p, "x").toBigInt(), field(p, "y").toBigInt()];
}

function note(w: Witness, key: string): Note {
  const n = sub(w, key);
  return {
    noteVersion: field(n, "note_version"),
    assetId: field(n, "asset_id"),
    noteType: field(n, "note_type"),
    conditionsHash: field(n, "conditions_hash"),
    value: field(n, "value").toBigInt(),
    owner: field(n, "owner"),
    psi: field(n, "psi"),
    parents: field(n, "parents"),
  };
}

const compliance = (w: Witness): Point<bigint> => [
  field(w, "compliance_pubkey_x").toBigInt(),
  field(w, "compliance_pubkey_y").toBigInt(),
];

/** leaf, eph.x and the DEM ciphertext, as `mint_common` returns them; `cek` feeds the memo wrap. */
async function minted(n: Note, eph: Fr, c: Point<bigint>) {
  const cek = deriveCek(eph, c);
  const ciphertext = await demEncrypt(cek, [
    n.noteVersion,
    n.assetId,
    n.noteType,
    n.conditionsHash,
    toFr(n.value),
    n.owner,
    n.parents,
  ]);
  return {
    leaf: await leaf(n),
    ephX: toFr(publicKey(eph)[0]),
    cek,
    ciphertext,
  };
}

async function spent(
  w: Witness,
  noteKey: string,
  indexKey: string,
  pathKey: string,
) {
  const n = note(w, noteKey);
  const index = field(w, indexKey);
  return {
    nullifier: await computeNullifier(n.psi, index),
    root: await foldPath(
      await leaf(n),
      Number(index.toBigInt()),
      fields(w, pathKey),
    ),
  };
}

/** Each circuit's flattened return tuple, derived by the SDK from the witness alone. */
async function sdkOutputs(name: CircuitName, w: Witness): Promise<Fr[]> {
  const c = compliance(w);
  switch (name) {
    case "deposit": {
      const n = note(w, "note");
      const m = await minted(n, field(w, "eph"), c);
      return [m.leaf, m.ephX, toFr(n.value), n.assetId, ...m.ciphertext];
    }
    case "withdraw": {
      const s = await spent(w, "old_note", "old_note_index", "old_note_path");
      const m = await minted(note(w, "change_note"), field(w, "change_eph"), c);
      return [
        s.nullifier,
        s.root,
        note(w, "old_note").assetId,
        m.leaf,
        m.ephX,
        ...m.ciphertext,
      ];
    }
    case "transfer": {
      const s = await spent(w, "old_note", "old_note_index", "old_note_path");
      const memoEph = field(w, "memo_eph");
      const viewPub = point(w, "recipient_view_pub");
      const memo = await minted(note(w, "memo_note"), memoEph, c);
      const change = await minted(
        note(w, "change_note"),
        field(w, "change_eph"),
        c,
      );
      return [
        s.nullifier,
        s.root,
        memo.leaf,
        memo.ephX,
        toFr(viewPub[0]),
        await wrapCek(memo.cek, memoEph, viewPub),
        ...memo.ciphertext,
        change.leaf,
        change.ephX,
        ...change.ciphertext,
      ];
    }
    case "split": {
      const s = await spent(w, "note_in", "index_in", "path_in");
      const o1 = await minted(note(w, "note_out_1"), field(w, "eph_1"), c);
      const o2 = await minted(note(w, "note_out_2"), field(w, "eph_2"), c);
      return [
        s.nullifier,
        s.root,
        o1.leaf,
        o1.ephX,
        ...o1.ciphertext,
        o2.leaf,
        o2.ephX,
        ...o2.ciphertext,
      ];
    }
    case "join": {
      const a = await spent(w, "note_a", "index_a", "path_a");
      const b = await spent(w, "note_b", "index_b", "path_b");
      expect(b.root.toBigInt()).toBe(a.root.toBigInt());
      const m = await minted(note(w, "note_out"), field(w, "eph_out"), c);
      return [
        a.nullifier,
        b.nullifier,
        a.root,
        m.leaf,
        m.ephX,
        ...m.ciphertext,
      ];
    }
    case "public_claim": {
      const m = await minted(note(w, "note_out"), field(w, "eph"), c);
      return [m.leaf, m.ephX, ...m.ciphertext];
    }
  }
}

// Position of each frozen `derived` value in the flattened return tuple. psi, the values and memoId are inputs.
const DERIVED_AT: Record<CircuitName, Record<string, number>> = {
  deposit: { commitment: 0, tag: 1 },
  withdraw: { root: 1, changeCommitment: 3 },
  transfer: {
    root: 1,
    memoCommitment: 2,
    memoTag: 4,
    memoCekWrap: 5,
    changeCommitment: 13,
  },
  split: { root: 1, out1: 2, out2: 11 },
  join: { root: 2, out: 3 },
  public_claim: { commitment: 0, tag: 1 },
};

function flatten(value: unknown): bigint[] {
  if (Array.isArray(value)) return value.flatMap(flatten);
  if (typeof value !== "string" && typeof value !== "number") {
    throw new Error(`unexpected circuit output ${JSON.stringify(value)}`);
  }
  return [BigInt(value)];
}

describe("transaction golden vectors execute against the compiled circuits", () => {
  it.each(Object.keys(CIRCUITS) as CircuitName[])(
    "%s witness satisfies every constraint and returns the SDK-derived outputs",
    async (name) => {
      const { witness, returnValue } = await execute(
        name,
        frozen[name].witness,
      );
      expect(witness.length).toBeGreaterThan(0);

      const outputs = flatten(returnValue);
      const sdk = await sdkOutputs(name, frozen[name].witness as Witness);
      expect(outputs).toEqual(sdk.map((f) => f.toBigInt()));

      for (const [key, at] of Object.entries(DERIVED_AT[name])) {
        const want = frozen[name].derived[key];
        expect(want, `${name}.derived.${key}`).toBeTypeOf("string");
        expect(outputs[at], `${name}.derived.${key}`).toBe(
          BigInt(want as string),
        );
      }
    },
    120_000,
  );

  it("rejects the deposit vector re-minted under an odd-y self ephemeral", async () => {
    const vector = frozen.deposit.witness as {
      compliance_pubkey_x: string;
      compliance_pubkey_y: string;
      note: Record<string, string>;
      eph: string;
    };
    const compliancePk: [bigint, bigint] = [
      BigInt(vector.compliance_pubkey_x),
      BigInt(vector.compliance_pubkey_y),
    ];
    let scalar = BigInt(vector.eph) + 1n;
    while (isEvenY(publicKey(toFr(scalar)))) scalar += 1n;
    const odd = toFr(scalar);
    // psi is recomputed for the new ephemeral, so only the even-y assert is left to fail.
    const psi = await computePsi(deriveCek(odd, compliancePk));

    await expect(
      execute("deposit", {
        ...vector,
        note: { ...vector.note, psi: psi.toString() },
        eph: odd.toString(),
      }),
    ).rejects.toThrow(/deposit discovery tag must be even-y/);
  }, 120_000);
});
