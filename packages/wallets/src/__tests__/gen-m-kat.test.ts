import { describe, it, expect } from "vitest";
import { msgWithdraw, msgTransfer, msgSplit, msgJoin } from "../frost/index.js";

// Parity lock: these m values MUST match Noir shared/src/multisig/frost.nr kat_msg_parity.
describe("m-preimage TS<->Noir parity", () => {
  it("msg_* match the Noir KAT for fixed inputs", async () => {
    const hex = (x: bigint) => "0x" + x.toString(16).padStart(64, "0");
    expect(
      hex(
        await msgWithdraw({
          root: 1n,
          nullifier: 2n,
          changeLeaf: 3n,
          publicOut: 4n,
          asset: 5n,
          recipient: 6n,
          intentHash: 7n,
        }),
      ),
    ).toBe(
      "0x2dda2d035d6f11d7a9a21090bb7757ffdd0c57c526d7d90431d73dea4831729d",
    );
    expect(
      hex(
        await msgTransfer({
          root: 1n,
          nullifier: 2n,
          memoLeaf: 3n,
          changeLeaf: 4n,
          asset: 5n,
        }),
      ),
    ).toBe(
      "0x18ce2613d1138a758d065683eb7ed8973fd4b875768fa5b376ac0ac89f7a85cd",
    );
    expect(
      hex(
        await msgSplit({
          root: 1n,
          nullifier: 2n,
          out1Leaf: 3n,
          out2Leaf: 4n,
          asset: 5n,
        }),
      ),
    ).toBe(
      "0x0c4d6056bd9bf2ff15f92f1c42fa264c5883b35e6f002abe44d8be2a2f08c6c3",
    );
    expect(
      hex(
        await msgJoin({
          root: 1n,
          nullifierA: 2n,
          nullifierB: 3n,
          outLeaf: 4n,
          asset: 5n,
        }),
      ),
    ).toBe(
      "0x2e41dd14ab7b1910916834caebb1d7e630c493722b2dbd76f269e5cbfc414001",
    );
  });
});
