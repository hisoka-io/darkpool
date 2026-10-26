import { describe, it, expect } from "vitest";
import { poseidon2Permutation } from "@aztec/foundation/crypto";
import { Fr } from "@aztec/foundation/fields";
import { Poseidon } from "../crypto/Poseidon";

// barretenberg's sponge seeds the capacity element with `(input.length << 64) + out_len - 1`, out_len = 1
// (crypto/poseidon2/sponge/sponge.hpp, `FieldSponge::hash_internal`). The Noir and Solidity sponges use the same
// length IV; it is what keeps hashes of different arities apart.
const LENGTH_SHIFT = 64n;
const RATE = 3;

const fr = (x: bigint): Fr => new Fr(x);

async function referenceSponge(message: bigint[]): Promise<Fr> {
  let state: Fr[] = [
    fr(0n),
    fr(0n),
    fr(0n),
    fr(BigInt(message.length) << LENGTH_SHIFT),
  ];
  for (let start = 0; start < message.length; start += RATE) {
    const block = message.slice(start, start + RATE);
    state = state.map((s, i) => (i < block.length ? s.add(fr(block[i])) : s));
    state = await poseidon2Permutation(state);
  }
  return state[0];
}

const A = 0x0c0ffeen;
const B = 0x2a5de47ed300af27b706aaa14762fc468f5cfc16cd8116eb6b09b0f2643ca2b9n;
const hash = (message: bigint[]): Promise<Fr> => Poseidon.hash(message.map(fr));

describe("Poseidon2 length IV", () => {
  it.each([
    ["1 input", [A]],
    ["2 inputs", [A, B]],
    ["3 inputs, trailing zero", [A, B, 0n]],
    ["8 inputs", [A, B, 3n, 4n, 5n, 6n, 7n, 0n]],
  ])(
    "seeds the capacity with length * 2^64 (%s)",
    async (_label: string, message: bigint[]) => {
      expect((await hash(message)).toBigInt()).toBe(
        (await referenceSponge(message)).toBigInt(),
      );
    },
  );

  it("keeps a zero-padded message apart from the shorter one", async () => {
    const h1 = await hash([A]);
    const h2Padded = await hash([A, 0n]);
    const h2 = await hash([A, B]);
    const h3 = await hash([A, B, 0n]);
    const h8 = await hash([A, B, 0n, 0n, 0n, 0n, 0n, 0n]);
    const zeroIv = (await poseidon2Permutation([A, B, 0n, 0n].map(fr)))[0];
    expect(h1.equals(h2Padded)).toBe(false);
    expect(h2.equals(h3)).toBe(false);
    expect(h2.equals(h8)).toBe(false);
    expect(h3.equals(h8)).toBe(false);
    expect(zeroIv.equals(h2)).toBe(false);
    expect(zeroIv.equals(h3)).toBe(false);
  });

  // Byte-identical to circuits/shared/src/poseidon2_arity.nr `kat_arity_vectors`.
  it("matches the Noir arity vectors", async () => {
    const vectors: [bigint[], bigint][] = [
      [
        [1n],
        0x168758332d5b3e2d13be8048c8011b454590e06c44bce7f702f09103eef5a373n,
      ],
      [
        [1n, 2n],
        0x038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383n,
      ],
      [
        [1n, 2n, 0n],
        0x14e2032f272084a8bcdf0b4af5042a5f11ed8c734d21e906a81adde7da3a9dcdn,
      ],
      [
        [1n, 2n, 0n, 0n, 0n, 0n, 0n, 0n],
        0x16baf281357237ed43d8d518ce9266e45a7f77fe0fcda9de69bbdcc3701090dcn,
      ],
      [
        [1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n],
        0x01dec21c6e1b30609eda618d7e35e5d9d6152f8fa67320d939c1a89603647142n,
      ],
    ];
    for (const [message, expected] of vectors) {
      expect((await hash(message)).toBigInt()).toBe(expected);
    }
    const zeroIv = await poseidon2Permutation([1n, 2n, 0n, 0n].map(fr));
    expect(zeroIv[0].toBigInt()).toBe(
      0x299bfccd7daf3c917e51291383929049ec0eaed800af245056cbf135f7dea636n,
    );
  });
});
