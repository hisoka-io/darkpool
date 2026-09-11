import { describe, expect, it } from "vitest";
import { AbiCoder, concat, getBytes, keccak256, toUtf8Bytes } from "ethers";
import { Fr } from "@hisoka/wallets";
import { buildHowlPayment, howlPaymentIntent } from "./howl-payment.js";

const EXECUTION_ID =
  "0x1111111111111111111111111111111111111111111111111111111111111111";
const ADAPTER = "0x2222222222222222222222222222222222222222";
const ASSET = "0x3333333333333333333333333333333333333333";
const PAYMENT_ID =
  "0x4444444444444444444444444444444444444444444444444444444444444444";

describe("Howl Nox payment builder", () => {
  it("matches the raw domain-label plus execution-id reduction", () => {
    const expected =
      BigInt(
        keccak256(
          concat([toUtf8Bytes("hisoka.nox.howl-payment.v1"), EXECUTION_ID]),
        ),
      ) % Fr.MODULUS;
    expect(howlPaymentIntent(EXECUTION_ID).toBigInt()).toBe(expected);
  });

  it("extracts and encodes only an exactly bound withdraw proof", () => {
    const inputs = Array<string>(17).fill(
      "0x0000000000000000000000000000000000000000000000000000000000000000",
    );
    inputs[0] = `0x${40n.toString(16).padStart(64, "0")}`;
    inputs[1] = `0x${BigInt(ADAPTER).toString(16).padStart(64, "0")}`;
    inputs[2] = howlPaymentIntent(EXECUTION_ID).toString();
    inputs[5] = PAYMENT_ID;
    inputs[7] = `0x${BigInt(ASSET).toString(16).padStart(64, "0")}`;
    const proof = new Uint8Array([1, 2, 3]);

    const built = buildHowlPayment(EXECUTION_ID, ADAPTER, {
      proof,
      publicInputs: inputs,
    });
    expect(built.paymentId).toBe(PAYMENT_ID);
    expect(built.feeAsset).toBe(ASSET);
    expect(built.amount).toBe(40n);
    expect(built.intentHash.toString()).toBe(inputs[2]);
    const decoded = AbiCoder.defaultAbiCoder().decode(
      ["bytes", "bytes32[]"],
      built.paymentData,
    );
    expect(getBytes(decoded[0])).toEqual(proof);
    expect([...decoded[1]]).toEqual(inputs);
  });

  it("rejects a proof bound to a different execution", () => {
    const inputs = Array<string>(17).fill(
      "0x0000000000000000000000000000000000000000000000000000000000000000",
    );
    inputs[0] = `0x${40n.toString(16).padStart(64, "0")}`;
    inputs[1] = `0x${BigInt(ADAPTER).toString(16).padStart(64, "0")}`;
    inputs[2] = `0x${1n.toString(16).padStart(64, "0")}`;
    inputs[5] = PAYMENT_ID;
    inputs[7] = `0x${BigInt(ASSET).toString(16).padStart(64, "0")}`;
    expect(() =>
      buildHowlPayment(EXECUTION_ID, ADAPTER, {
        proof: new Uint8Array([1]),
        publicInputs: inputs,
      }),
    ).toThrow(/intent/);
  });
});
