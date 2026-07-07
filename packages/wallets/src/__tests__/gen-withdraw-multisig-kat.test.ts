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
  msgWithdraw,
  NonceHandle,
  Commitment,
} from "../frost/index.js";
import { leaf, Note } from "../note/note.js";
import { computePsi, computeNullifier } from "../note/nullifier.js";
import { isEvenY } from "../note/keys.js";
import { deriveCek } from "../crypto/kem.js";
import type { Point } from "../tss/index.js";

// Emits a deterministic withdraw_multisig witness + real 3-of-5 FROST (R,z) for the Noir main-level KAT
// (withdraw_multisig/src/main.nr).
const ASSET_ID = 0x1234567890123456789012345678901234567890n;
// FIXTURE_COMPLIANCE (shared/src/test_fixtures.nr).
const COMPLIANCE_PK: Point = [
  0x085ed469c9a9f102b6d4f6f909b8ceaf6ca49b39759ac2e0feb7e0aada8b7111n,
  0x245e25ab2bd42f0280a5ade750828dd6868f5225ae798d6b51c676f519c8f4e8n,
];
const OLD_PSI =
  0x0981a88f9e119b057498a4ab99ed5379a1ea91c642454fc0c07aacc1f5cd5731n;
const OLD_VALUE = 1000n;
const WITHDRAW_VALUE = 300n;
const CHANGE_VALUE = OLD_VALUE - WITHDRAW_VALUE;
const RECIPIENT = 0x00c0ffee00c0ffee00c0ffee00c0ffee00c0ffeen;
const INTENT_HASH = 0n;

function firstEvenYEph(): bigint {
  for (let s = 1n; s < 1000n; s++) {
    if (isEvenY(mulPointEscalar(Base8, s))) return s;
  }
  throw new Error("no even-y ephemeral in range");
}

const hex = (x: bigint) => "0x" + x.toString(16).padStart(64, "0");

describe("gen withdraw_multisig KAT", () => {
  it("emits a coherent witness + real 3-of-5 FROST (R,z) over the withdraw message", async () => {
    // Same secret polynomial as gen-frost-kat -> gpk == the frost.nr KAT gpk.
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

    const oldNote: Note = {
      noteVersion: new Fr(1n),
      assetId: new Fr(ASSET_ID),
      noteType: new Fr(1n),
      conditionsHash: new Fr(0n),
      value: OLD_VALUE,
      owner,
      psi: new Fr(OLD_PSI),
      parents: new Fr(0n),
    };
    // Single-leaf tree at index 0: root is the leaf itself.
    const root = await leaf(oldNote);
    const nullifier = await computeNullifier(new Fr(OLD_PSI), new Fr(0n));

    const changeEph = firstEvenYEph();
    const changePsi = await computePsi(
      deriveCek(new Fr(changeEph), COMPLIANCE_PK),
    );
    const changeNote: Note = {
      noteVersion: new Fr(1n),
      assetId: new Fr(ASSET_ID),
      noteType: new Fr(1n),
      conditionsHash: new Fr(0n),
      value: CHANGE_VALUE,
      owner,
      psi: changePsi,
      parents: new Fr(0n),
    };
    const changeLeaf = await leaf(changeNote);

    const m = await msgWithdraw({
      root: root.toBigInt(),
      nullifier: nullifier.toBigInt(),
      changeLeaf: changeLeaf.toBigInt(),
      publicOut: WITHDRAW_VALUE,
      asset: ASSET_ID,
      recipient: RECIPIENT,
      intentHash: INTENT_HASH,
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

    // Parity lock: MUST equal the withdraw_multisig/src/main.nr KAT.
    expect(hex(gpk[0])).toBe(
      "0x2546ab52faee9ab8ead1ad868567473b9757c6456c137274b12a5c51330d764d",
    );
    expect(hex(gpk[1])).toBe(
      "0x0d7a564269d3675f75799ee9d7574b00d01190b243041994c0e460af507a71aa",
    );
    expect(hex(owner.toBigInt())).toBe(
      "0x0f0c6b3c0a818ce637e33dc7b49438f89a0531ef1ad200710fdb897354f7f2ea",
    );
    expect(hex(sig.R[0])).toBe(
      "0x06b492e9a311833b4dddf083752ab3286f10a82df87703b3b85971501dc72890",
    );
    expect(hex(sig.R[1])).toBe(
      "0x17da10d4e0489493572b7cba2eaa016a6ef5106c003155e32348ef1cfc6d8574",
    );
    expect(hex(sig.z)).toBe(
      "0x0320e625492f31f063eb5423a7644be6d52bba8f7c8c65eb6a33134f3f213c4e",
    );
    expect(changeEph).toBe(4n);
    expect(hex(changePsi.toBigInt())).toBe(
      "0x2aaee0e06ff8b0e8cf78d66b27f27fe9d0e82cc687724cee2eb92b0d8a90c2c2",
    );
    expect(hex(root.toBigInt())).toBe(
      "0x22a6d1f94f293045c43aa45ddaf7bd3ab0a33671ff43846f4bb07576a6da7606",
    );
    expect(hex(nullifier.toBigInt())).toBe(
      "0x2761654f0b4e9f47ac9bafe900c723ead042a888da718a34b6ecc8036850755e",
    );
    expect(hex(changeLeaf.toBigInt())).toBe(
      "0x2021b1c3e922519e2ed11cb7eb53059b0161326c6785de34f57b0f18c6cf3cc7",
    );
    expect(hex(m)).toBe(
      "0x06bc31ddddd4ffbfb796398cfa3f66d66b694a9b5e88e9e6579f64f833cebc70",
    );
  });
});
