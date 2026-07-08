import { describe, it, expect } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import { Base8, mulPointEscalar } from "@zk-kit/baby-jubjub";
import { scalarBaseMul, polyEval, SUBORDER } from "../tss/index.js";
import {
  bjjCiphersuite as cs,
  encodeMessage,
  commit,
  groupCommitment,
  bindingFactors,
  signShare,
  aggregate,
  verify,
  multisigOwner,
  msgJoin,
  NonceHandle,
  Commitment,
} from "../frost/index.js";
import { leaf, Note } from "../note/note.js";
import { computePsi, computeNullifier } from "../note/nullifier.js";
import { isEvenY } from "../note/keys.js";
import { deriveCek } from "../crypto/kem.js";
import { Poseidon } from "../crypto/Poseidon.js";
import type { Point } from "../tss/index.js";

// Deterministic join_multisig witness + real 3-of-5 FROST (R,z) for join_multisig/src/main.nr. Two inputs
// (same account gpk) at index 0 and 1 in a 2-leaf lean tree: root = Poseidon2(leaf_a, leaf_b).
const ASSET_ID = 0x1234567890123456789012345678901234567890n;
const COMPLIANCE_PK: Point = [
  0x085ed469c9a9f102b6d4f6f909b8ceaf6ca49b39759ac2e0feb7e0aada8b7111n,
  0x245e25ab2bd42f0280a5ade750828dd6868f5225ae798d6b51c676f519c8f4e8n,
];
const A_VALUE = 100n;
const B_VALUE = 50n;
const OUT_VALUE = 150n;
const A_PSI = 0x01n;
const B_PSI = 0x02n;
// pack(index_a=0, index_b=1) = 0 + 1*2^32
const OUT_PARENTS = 0x100000000n;

function firstEvenYEph(): bigint {
  for (let s = 1n; s < 1000n; s++) {
    if (isEvenY(mulPointEscalar(Base8, s))) return s;
  }
  throw new Error("no even-y ephemeral in range");
}

const hex = (x: bigint) => "0x" + x.toString(16).padStart(64, "0");

const msNote = (
  value: bigint,
  owner: Fr,
  psi: Fr,
  noteType: bigint,
  parents: bigint,
): Note => ({
  noteVersion: new Fr(1n),
  assetId: new Fr(ASSET_ID),
  noteType: new Fr(noteType),
  conditionsHash: new Fr(0n),
  value,
  owner,
  psi,
  parents: new Fr(parents),
});

describe("gen join_multisig KAT", () => {
  it("emits a coherent witness + real 3-of-5 FROST (R,z) over the join message", async () => {
    const c = 12345678901234567890123456789012345678901234567890n % SUBORDER;
    const coeffs = [
      c,
      98765432109876543210987654321098765432109876543210n % SUBORDER,
      55555555555555555555555555555555555555555555555555n % SUBORDER,
    ];
    const gpk = scalarBaseMul(c);
    const ids = [1n, 2n, 3n];
    const shares = new Map(ids.map((i) => [i, polyEval(coeffs, i)]));
    const owner = new Fr(await multisigOwner(gpk));

    const noteA = msNote(A_VALUE, owner, new Fr(A_PSI), 1n, 0n);
    const noteB = msNote(B_VALUE, owner, new Fr(B_PSI), 1n, 0n);
    const leafA = await leaf(noteA);
    const leafB = await leaf(noteB);
    const root = await Poseidon.hash([leafA, leafB]);
    const nullifierA = await computeNullifier(new Fr(A_PSI), new Fr(0n));
    const nullifierB = await computeNullifier(new Fr(B_PSI), new Fr(1n));

    const ephOut = firstEvenYEph();
    const psiOut = await computePsi(deriveCek(new Fr(ephOut), COMPLIANCE_PK));
    const outNote = msNote(OUT_VALUE, owner, psiOut, 1n, OUT_PARENTS);
    const outLeaf = await leaf(outNote);

    const m = await msgJoin({
      root: root.toBigInt(),
      nullifierA: nullifierA.toBigInt(),
      nullifierB: nullifierB.toBigInt(),
      outLeaf: outLeaf.toBigInt(),
      asset: ASSET_ID,
    });

    const msg = encodeMessage(m);
    const rounds = new Map<
      bigint,
      { nonces: NonceHandle; commitment: Commitment<Point> }
    >();
    for (const i of ids) {
      const h = new Uint8Array(32).fill(Number(i) * 2 + 40);
      const b = new Uint8Array(32).fill(Number(i) * 2 + 41);
      rounds.set(i, await commit(cs, i, shares.get(i)!, h, b));
    }
    const commitments = ids.map((i) => rounds.get(i)!.commitment);
    const zs: bigint[] = [];
    for (const i of ids)
      zs.push(
        await signShare(
          cs,
          i,
          rounds.get(i)!.nonces,
          shares.get(i)!,
          gpk,
          msg,
          commitments,
        ),
      );
    const R = groupCommitment(
      cs,
      commitments,
      await bindingFactors(cs, gpk, msg, commitments),
    );
    const sig = aggregate(cs, R, zs);
    expect(await verify(cs, gpk, msg, sig)).toBe(true);

    expect(hex(gpk[0])).toBe(
      "0x2546ab52faee9ab8ead1ad868567473b9757c6456c137274b12a5c51330d764d",
    );

    // Parity lock: MUST equal the join_multisig/src/main.nr KAT.
    expect(ephOut).toBe(4n);
    expect(hex(psiOut.toBigInt())).toBe(
      "0x2aaee0e06ff8b0e8cf78d66b27f27fe9d0e82cc687724cee2eb92b0d8a90c2c2",
    );
    expect(hex(leafA.toBigInt())).toBe(
      "0x06231cb767801dfb54ba204853971662673844713bfac80a1365a64395321213",
    );
    expect(hex(leafB.toBigInt())).toBe(
      "0x26afbdd3fb70e3c36549bf153b11f505bd5a09372f3b074bb8a1f3a4c8ef8bbc",
    );
    expect(hex(root.toBigInt())).toBe(
      "0x0fb55082129f15e052308440e29b6a7e2109680582585b886a80ada05f09615b",
    );
    expect(hex(nullifierA.toBigInt())).toBe(
      "0x1e05013a2f40c60dc58cfe36bfa4d7e94676c43436922368628342bc5144d103",
    );
    expect(hex(nullifierB.toBigInt())).toBe(
      "0x176ad1cae93876a4632bc6431edd92ba205845f7e9aa369840c790f261640d1a",
    );
    expect(hex(outLeaf.toBigInt())).toBe(
      "0x1cfb9439a548ad03404b3fa04f0224299c60a38f1e599b8e60978dd571b9c134",
    );
    expect(hex(sig.R[0])).toBe(
      "0x0eb01cc518d80b04ff65166edfe9731d838791e90f07be3857597674b189bc0e",
    );
    expect(hex(sig.R[1])).toBe(
      "0x180531d77c5761fbbb55b43ff7eb01b5e607e17d82e37f2dbb0b72ad5700ed53",
    );
    expect(hex(sig.z)).toBe(
      "0x0413fd66ff083810c4ed2b5983fe1bb590b1f504f72cf71f463c5e2af0665969",
    );
    expect(hex(m)).toBe(
      "0x0c49a937849f04a95cc568a5cc1476d7739e1abfed94f329f509c427acfdec7a",
    );
  });
});
