import { Fr } from "@aztec/foundation/fields";
import type { Point } from "@zk-kit/baby-jubjub";
import type { ProofEnvelope } from "@hisoka/howl-protocol";
import type { StandardCircuitId } from "@hisoka/howl-protocol/proving";
import { demEncrypt } from "@hisoka/wallets";
import { WalletRuntimeError } from "../errors.js";

/** Public-input count per circuit: the length each DarkPool entrypoint checks. */
export const PUBLIC_INPUT_COUNTS: Readonly<Record<StandardCircuitId, number>> =
  {
    deposit: 13,
    withdraw: 17,
    transfer: 24,
    join: 14,
    split: 22,
    public_claim: 13,
  };

/** A note the action mints, as the contract reads it: leaf, ephemeral x, then seven ciphertext words. */
export interface MintedOutput {
  readonly commitment: Fr;
  readonly ephPub: Point<bigint>;
  readonly cek: Fr;
  readonly note: {
    readonly noteVersion: Fr;
    readonly assetId: Fr;
    readonly noteType: Fr;
    readonly conditionsHash: Fr;
    readonly value: Fr;
    readonly owner: Fr;
    readonly parents: Fr;
  };
}

/** What the runtime assembled, for each circuit, in the words the contract reads. */
export type BindingInputs =
  | {
      readonly circuit: "deposit";
      readonly compliancePk: Point<bigint>;
      readonly output: MintedOutput;
      readonly value: bigint;
      readonly asset: Fr;
    }
  | {
      readonly circuit: "withdraw";
      readonly compliancePk: Point<bigint>;
      readonly value: bigint;
      readonly recipient: Fr;
      readonly intentHash: Fr;
      readonly nullifier: Fr;
      readonly root: Fr;
      readonly asset: Fr;
      readonly change: MintedOutput;
    }
  | {
      readonly circuit: "transfer";
      readonly compliancePk: Point<bigint>;
      readonly nullifier: Fr;
      readonly root: Fr;
      readonly memo: MintedOutput;
      readonly recipientTag: Fr;
      readonly cekWrap: Fr;
      readonly change: MintedOutput;
    }
  | {
      readonly circuit: "join";
      readonly compliancePk: Point<bigint>;
      /** In ascending leaf-index order, as the circuit and the contract take them. */
      readonly nullifiers: readonly [Fr, Fr];
      readonly root: Fr;
      readonly output: MintedOutput;
    }
  | {
      readonly circuit: "split";
      readonly compliancePk: Point<bigint>;
      readonly nullifier: Fr;
      readonly root: Fr;
      readonly out1: MintedOutput;
      readonly out2: MintedOutput;
    }
  | {
      readonly circuit: "public_claim";
      readonly compliancePk: Point<bigint>;
      readonly memoId: Fr;
      readonly timestamp: bigint;
      readonly output: MintedOutput;
    };

function ciphertext(output: MintedOutput): Promise<Fr[]> {
  const n = output.note;
  return demEncrypt(output.cek, [
    n.noteVersion,
    n.assetId,
    n.noteType,
    n.conditionsHash,
    n.value,
    n.owner,
    n.parents,
  ]);
}

/** Sets the leaf at `leafAt`, the ephemeral x after it, and the seven ciphertext words from `ctAt`. */
async function outputWords(
  leafAt: number,
  output: MintedOutput,
  into: Map<number, Fr>,
  ctAt = leafAt + 2,
): Promise<void> {
  into.set(leafAt, output.commitment);
  into.set(leafAt + 1, new Fr(output.ephPub[0]));
  (await ciphertext(output)).forEach((word, i) => into.set(ctAt + i, word));
}

function compliance(
  at: number,
  pk: Point<bigint>,
  into: Map<number, Fr>,
): void {
  into.set(at, new Fr(pk[0]));
  into.set(at + 1, new Fr(pk[1]));
}

/**
 * Every public-input word the runtime can derive from what it assembled, at the index the contract reads it
 * (DarkPool `deposit`, `_withdraw`, `_transfer`, `_join`, `_split`, `publicClaim`). The layout is the
 * contract's, so this holds for any proving system behind the verifier slot.
 */
export async function expectedPublicInputs(
  b: BindingInputs,
): Promise<ReadonlyMap<number, Fr>> {
  const words = new Map<number, Fr>();
  switch (b.circuit) {
    case "deposit":
      compliance(0, b.compliancePk, words);
      words.set(4, new Fr(b.value));
      words.set(5, b.asset);
      await outputWords(2, b.output, words, 6);
      break;
    case "withdraw":
      words.set(0, new Fr(b.value));
      words.set(1, b.recipient);
      words.set(2, b.intentHash);
      compliance(3, b.compliancePk, words);
      words.set(5, b.nullifier);
      words.set(6, b.root);
      words.set(7, b.asset);
      await outputWords(8, b.change, words);
      break;
    case "transfer":
      compliance(0, b.compliancePk, words);
      words.set(2, b.nullifier);
      words.set(3, b.root);
      words.set(6, b.recipientTag);
      words.set(7, b.cekWrap);
      await outputWords(4, b.memo, words, 8);
      await outputWords(15, b.change, words);
      break;
    case "join":
      compliance(0, b.compliancePk, words);
      words.set(2, b.nullifiers[0]);
      words.set(3, b.nullifiers[1]);
      words.set(4, b.root);
      await outputWords(5, b.output, words);
      break;
    case "split":
      compliance(0, b.compliancePk, words);
      words.set(2, b.nullifier);
      words.set(3, b.root);
      await outputWords(4, b.out1, words);
      await outputWords(13, b.out2, words);
      break;
    case "public_claim":
      words.set(0, b.memoId);
      compliance(1, b.compliancePk, words);
      words.set(3, new Fr(b.timestamp));
      await outputWords(4, b.output, words);
      break;
  }
  return words;
}

/**
 * Refuses a proof whose public inputs are not exactly what was assembled: wrong count, or any known word
 * different. A prover that proves something else (another note, another root, another recipient) is caught
 * here, before anything is sent.
 */
export async function checkPublicInputs(
  envelope: ProofEnvelope<StandardCircuitId>,
  binding: BindingInputs,
): Promise<void> {
  const circuit = binding.circuit;
  if (envelope.circuit_id !== circuit) {
    throw new WalletRuntimeError(
      "PUBLIC_INPUT_MISMATCH",
      `the proof is for circuit ${envelope.circuit_id}, the action assembled ${circuit}`,
      {
        circuit,
        position: "circuit_id",
        expected: circuit,
        actual: envelope.circuit_id,
      },
    );
  }
  const count = PUBLIC_INPUT_COUNTS[circuit];
  if (envelope.public_inputs.length !== count) {
    throw new WalletRuntimeError(
      "PUBLIC_INPUT_MISMATCH",
      `${circuit} proof carries ${envelope.public_inputs.length} public inputs, the contract reads ${count}`,
      {
        circuit,
        position: "length",
        expected: String(count),
        actual: String(envelope.public_inputs.length),
      },
    );
  }
  const expected = await expectedPublicInputs(binding);
  for (const [position, word] of [...expected.entries()].sort(
    (a, b) => a[0] - b[0],
  )) {
    const actual = envelope.public_inputs[position];
    if (actual === undefined || BigInt(actual) !== word.toBigInt()) {
      throw new WalletRuntimeError(
        "PUBLIC_INPUT_MISMATCH",
        `${circuit} public input ${position} is ${actual ?? "absent"}, the runtime assembled ${word.toString()}`,
        {
          circuit,
          position: String(position),
          expected: word.toString(),
          actual: actual ?? "",
        },
      );
    }
  }
}
