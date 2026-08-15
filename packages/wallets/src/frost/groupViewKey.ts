import { Fr } from "@aztec/foundation/fields";
import { Point } from "@zk-kit/baby-jubjub";
import { Kdf } from "../crypto/Kdf.js";
import { Poseidon } from "../crypto/Poseidon.js";
import { toBjjScalar } from "../crypto/index.js";
import { isEvenY, publicKey } from "../note/keys.js";
import type { DarkAccount } from "../keys/DarkAccount.js";

// `v` drives every multisig discovery key, so a group that loses it cannot find its own notes. Sampling it
// as a sum of member contributions made it recoverable by nobody. Contributory generation is essential for
// a SPEND key and buys nothing for a VIEW key, because 1-of-n view means every member holds `v` anyway.
//
// Bound to `gpk`, which is public, so the creator recomputes it from their seed alone, and two groups under
// one seed stay independent. Does NOT give an arbitrary member recovery; that needs `v` under VSS.

const MS_VIEW_LABEL = "hisoka.msView";

// V.x is a discovery tag and a tag is only injective when y is even, so walk a counter to an even-y point.
const MAX_VIEW_ROLL = 256n;

export interface GroupViewKey {
  readonly v: Fr;
  readonly V: Point<bigint>;
  /** The counter that produced an even-y V. Derived, so it never has to travel. */
  readonly roll: bigint;
}

export async function deriveGroupViewKey(
  account: DarkAccount,
  gpk: Point<bigint>,
): Promise<GroupViewKey> {
  const skView = await account.getViewKey();
  for (let roll = 0n; roll < MAX_VIEW_ROLL; roll++) {
    const salt = await Poseidon.hash([
      new Fr(gpk[0]),
      new Fr(gpk[1]),
      new Fr(roll),
    ]);
    const v = toBjjScalar(await Kdf.derive(MS_VIEW_LABEL, skView, salt));
    const V = publicKey(v);
    if (isEvenY(V)) return { v, V, roll };
  }
  throw new Error(
    `group view key: no even-y V within ${MAX_VIEW_ROLL} rolls for this group`,
  );
}
