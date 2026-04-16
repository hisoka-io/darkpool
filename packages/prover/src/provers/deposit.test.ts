import { describe, it, expect, beforeAll } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import { Point, mulPointEscalar, Base8 } from "@zk-kit/baby-jubjub";

import { proveDeposit } from "./deposit.js";
import { DepositInputs } from "../types.js";
import { unpackCiphertext } from "../utils.js";

import {
  NotePlaintext,
  addressToFr,
  toFr,
  decryptNoteDeposit,
  complianceDecryptNote,
} from "@hisoka/wallets";

describe("proveDeposit End-to-End (with Packed Ciphertext)", () => {
  const COMPLIANCE_SK = 123456789n;
  const COMPLIANCE_PK: Point<bigint> = mulPointEscalar(Base8, COMPLIANCE_SK);

  const USER_EPHEMERAL_SK = toFr(111n);
  const USER_EPK = mulPointEscalar(Base8, USER_EPHEMERAL_SK.toBigInt());

  let validInputs: DepositInputs;

  beforeAll(() => {
    const notePlaintext: NotePlaintext = {
      value: toFr(100n),
      asset_id: addressToFr("0x0d500b1d8e8ef31e21c99d1db9a6444d3adf1270"),
      secret: toFr(456n),
      nullifier: toFr(789n),
      timelock: toFr(0n),
      hashlock: toFr(0n),
    };

    validInputs = {
      notePlaintext,
      ephemeralSk: USER_EPHEMERAL_SK,
      compliancePk: COMPLIANCE_PK,
    };
  });

  it("should generate, verify, unpack, and allow decryption of a complete deposit proof", async () => {
    const result = await proveDeposit(validInputs);

    expect(result.verified).toBe(true);
    expect(result.publicInputs.length).toBe(13);

    const publicInputsFr = result.publicInputs.map(Fr.fromString);
    const return_values = publicInputsFr.slice(2); // Skip compliance key

    const [epkX_fr, epkY_fr, valueOut_fr, assetIdOut_fr] = return_values.slice(
      0,
      4,
    );
    const packedCiphertext_fr = return_values.slice(4);

    expect(epkX_fr.toBigInt()).toEqual(USER_EPK[0]);
    expect(epkY_fr.toBigInt()).toEqual(USER_EPK[1]);
    expect(valueOut_fr.equals(validInputs.notePlaintext.value)).toBe(true);
    expect(assetIdOut_fr.equals(validInputs.notePlaintext.asset_id)).toBe(true);

    const ciphertext = unpackCiphertext(packedCiphertext_fr);
    // Expect 208 bytes (192 payload + 16 pad)
    expect(ciphertext.length).toBe(208);

    const userDecryptedNote = await decryptNoteDeposit(
      validInputs.ephemeralSk,
      validInputs.compliancePk,
      ciphertext,
    );
    expect(
      userDecryptedNote.value.equals(validInputs.notePlaintext.value),
    ).toBe(true);
    expect(userDecryptedNote.timelock.equals(toFr(0n))).toBe(true);

    const ephemeralPkFromProof: Point<bigint> = [
      epkX_fr.toBigInt(),
      epkY_fr.toBigInt(),
    ];
    const complianceDecryptedNote = await complianceDecryptNote(
      COMPLIANCE_SK,
      ephemeralPkFromProof,
      ciphertext,
    );

    expect(
      complianceDecryptedNote.value.equals(validInputs.notePlaintext.value),
    ).toBe(true);
  }, 60000);

  it("should fail with a constraint violation for a zero ephemeral key", async () => {
    const invalidInputs: DepositInputs = {
      ...validInputs,
      ephemeralSk: Fr.ZERO,
    };
    await expect(proveDeposit(invalidInputs)).rejects.toThrow(
      /ephemeral secret key cannot be zero/i,
    );
  });
});
