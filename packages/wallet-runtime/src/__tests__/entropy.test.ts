import { describe, expect, it } from "vitest";
import { BJJ_SUBGROUP_ORDER, isEvenY, publicKey } from "@hisoka/wallets";
import { WalletRuntimeError } from "../errors.js";
import {
  MEMO_EPH_MAX_DRAWS,
  newPlanId,
  sampleMemoEphemeral,
  type EntropyPort,
} from "../spend/entropy.js";
import { CountingEntropy } from "./fixtures/env.js";

describe("entropy", () => {
  it("samples a non-zero subgroup scalar whose public key has even y", () => {
    const entropy = new CountingEntropy();
    for (let i = 0; i < 20; i++) {
      const eph = sampleMemoEphemeral(entropy);
      expect(eph.isZero()).toBe(false);
      expect(eph.toBigInt() < BJJ_SUBGROUP_ORDER).toBe(true);
      expect(isEvenY(publicKey(eph))).toBe(true);
    }
  });

  it("redraws past zero and odd-y draws, and gives up loudly on a source that never varies", () => {
    let calls = 0;
    const zeroThenCounting: EntropyPort = {
      randomBytes: (n) => {
        calls += 1;
        const out = new Uint8Array(n);
        if (calls > 1) out[n - 1] = calls;
        return out;
      },
    };
    const eph = sampleMemoEphemeral(zeroThenCounting);
    expect(calls).toBeGreaterThan(1);
    expect(isEvenY(publicKey(eph))).toBe(true);

    const stuck: EntropyPort = { randomBytes: (n) => new Uint8Array(n) };
    let draws = 0;
    const counted: EntropyPort = {
      randomBytes: (n) => {
        draws += 1;
        return stuck.randomBytes(n);
      },
    };
    const err = (() => {
      try {
        sampleMemoEphemeral(counted);
      } catch (e) {
        return e;
      }
      return null;
    })();
    expect((err as WalletRuntimeError).code).toBe("ENTROPY_EXHAUSTED");
    expect(draws).toBe(MEMO_EPH_MAX_DRAWS);
  });

  it("gives distinct plan ids", () => {
    const entropy = new CountingEntropy();
    const a = newPlanId(entropy);
    expect(a).toMatch(/^0x[0-9a-f]{32}$/);
    expect(newPlanId(entropy)).not.toBe(a);
  });
});
