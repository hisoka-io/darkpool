import { describe, it, expect } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import { Base8, mulPointEscalar, Point } from "@zk-kit/baby-jubjub";
import { NOTE_TYPE_MULTISIG, NOTE_TYPE_STANDARD } from "@hisoka/wallets/frost";
import { memoRecipientPoints } from "../marshal.js";
import { ProofInputError } from "../errors.js";

const STANDARD = new Fr(NOTE_TYPE_STANDARD);
const MULTISIG = new Fr(NOTE_TYPE_MULTISIG);

const IN_PUB: Point<bigint> = mulPointEscalar(Base8, 0xbeefn);
const GPK: Point<bigint> = mulPointEscalar(Base8, 0x5eedn);
const VIEW_PUB: Point<bigint> = mulPointEscalar(Base8, 0xf00dn);

describe("memoRecipientPoints", () => {
  it("collapses spend and view for a STANDARD memo", () => {
    expect(memoRecipientPoints("transfer", STANDARD, IN_PUB)).toStrictEqual({
      spend: IN_PUB,
      view: IN_PUB,
    });
  });

  it("decouples spend and view for a MULTISIG memo", () => {
    expect(
      memoRecipientPoints("transfer_multisig", MULTISIG, undefined, {
        gpk: GPK,
        viewPub: VIEW_PUB,
      }),
    ).toStrictEqual({ spend: GPK, view: VIEW_PUB });
  });

  it("rejects both recipient forms at once", () => {
    const call = () =>
      memoRecipientPoints("transfer", MULTISIG, IN_PUB, {
        gpk: GPK,
        viewPub: VIEW_PUB,
      });
    expect(call).toThrow(ProofInputError);
    expect(call).toThrow(/transfer.*recipientMultisig, never both/);
  });

  it("rejects a multisig recipient on a STANDARD memo", () => {
    const call = () =>
      memoRecipientPoints("transfer", STANDARD, undefined, {
        gpk: GPK,
        viewPub: VIEW_PUB,
      });
    expect(call).toThrow(ProofInputError);
    expect(call).toThrow(
      /transfer.*recipientMultisig requires the memo note_type to be MULTISIG/,
    );
  });

  it("rejects a memo with no recipient at all", () => {
    const call = () => memoRecipientPoints("transfer", STANDARD);
    expect(call).toThrow(ProofInputError);
    expect(call).toThrow(
      /transfer.*recipientInPub or recipientMultisig is required/,
    );
  });

  it("rejects a single recipient key on a MULTISIG memo", () => {
    const call = () =>
      memoRecipientPoints("transfer_multisig", MULTISIG, IN_PUB);
    expect(call).toThrow(ProofInputError);
    expect(call).toThrow(
      /transfer_multisig.*MULTISIG memo requires recipientMultisig/,
    );
  });

  it("rejects a collapsed multisig pair the circuit biconditional would reject", () => {
    const call = () =>
      memoRecipientPoints("transfer_multisig", MULTISIG, undefined, {
        gpk: GPK,
        viewPub: GPK,
      });
    expect(call).toThrow(ProofInputError);
    expect(call).toThrow(/transfer_multisig.*gpk and viewPub must not share x/);
  });
});
