import { describe, it, expect } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import {
  bjjCiphersuite as cs,
  encodeMessage,
  commit,
  groupCommitment,
  bindingFactors,
  signShare,
  aggregate,
  verify,
  multisigAddress,
  Commitment,
  NonceHandle,
} from "../frost/index.js";
import { frostAccountDkg } from "../unsafe-sim/index.js";
import { SCHNORR_DOMAIN, scalarBaseMul, pointEq } from "../tss/index.js";
import { Poseidon } from "../crypto/Poseidon.js";
import { isEvenY } from "../note/keys.js";
import type { Point } from "../tss/index.js";

function rand32(): Uint8Array {
  const b = new Uint8Array(32);
  globalThis.crypto.getRandomValues(b);
  return b;
}

describe("FROST account: DKG establishes gpk + shared viewing key + owner", () => {
  it("produces a spendable account whose gpk signs and whose owner = Poseidon2(gpk)", async () => {
    const acct = await frostAccountDkg(5, 3, SCHNORR_DOMAIN);

    // owner commitment matches Poseidon2(gpk.x, gpk.y).
    const expectedOwner = await Poseidon.hash([
      new Fr(acct.gpk[0]),
      new Fr(acct.gpk[1]),
    ]);
    expect(acct.owner.toBigInt()).toBe(expectedOwner.toBigInt());

    // The shared viewing key is consistent: V = v*Base8, every member holds the same v.
    expect(pointEq(acct.viewPub, scalarBaseMul(acct.viewKey))).toBe(true);

    // The ceremony MUST yield an even-y V (the static Raven tag is V.x); the DKG output composes with the
    // note-view layer without throwing. This guards the odd-y regression (a fixed sum cannot be rolled later).
    expect(isEvenY(acct.viewPub)).toBe(true);
    const address = await multisigAddress(acct.gpk, new Fr(acct.viewKey));
    expect(address.ownerCommitment.toBigInt()).toBe(acct.owner.toBigInt());
    expect(pointEq(address.viewPub, acct.viewPub)).toBe(true);

    // The account key actually signs: a 3-of-5 quorum yields a valid FROST signature under gpk.
    const m = 0xabcabcn;
    const msg = encodeMessage(m);
    const quorum = [1n, 2n, 3n];
    const rounds = new Map<
      bigint,
      { nonces: NonceHandle; commitment: Commitment<Point> }
    >();
    for (const id of quorum)
      rounds.set(
        id,
        await commit(cs, id, acct.shares.get(id)!, rand32(), rand32()),
      );
    const commitments = quorum.map((id) => rounds.get(id)!.commitment);
    const zs: bigint[] = [];
    for (const id of quorum)
      zs.push(
        await signShare(
          cs,
          id,
          rounds.get(id)!.nonces,
          acct.shares.get(id)!,
          acct.gpk,
          msg,
          commitments,
        ),
      );
    const R = groupCommitment(
      cs,
      commitments,
      await bindingFactors(cs, acct.gpk, msg, commitments),
    );
    expect(await verify(cs, acct.gpk, msg, aggregate(cs, R, zs))).toBe(true);
  });
});
