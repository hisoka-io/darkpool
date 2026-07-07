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

    const expectedOwner = await Poseidon.hash([
      new Fr(acct.gpk[0]),
      new Fr(acct.gpk[1]),
    ]);
    expect(acct.owner.toBigInt()).toBe(expectedOwner.toBigInt());

    expect(pointEq(acct.viewPub, scalarBaseMul(acct.viewKey))).toBe(true);

    // Even-y V regression: a fixed commit-reveal sum cannot be rolled to even-y after the fact.
    expect(isEvenY(acct.viewPub)).toBe(true);
    const address = await multisigAddress(acct.gpk, new Fr(acct.viewKey));
    expect(address.ownerCommitment.toBigInt()).toBe(acct.owner.toBigInt());
    expect(pointEq(address.viewPub, acct.viewPub)).toBe(true);

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
