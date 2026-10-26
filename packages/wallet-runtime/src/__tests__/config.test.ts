import { describe, expect, it } from "vitest";
import { parseDeploymentRef } from "@hisoka/howl-protocol";
import { MAX_OCCURRENCES_PER_TAG } from "@hisoka/wallets";
import {
  HARDHAT_CHAIN_CONFIG,
  validateChainConfig,
  type ChainConfig,
} from "../config.js";
import { WalletRuntimeError } from "../errors.js";

const DEPLOYMENT = {
  domain_version: 1,
  chain_id: "421614",
  dark_pool: "0x6dab000000000000000000000000000000000001",
  deployment_block: "123456",
} as const;

function valid(): Record<string, unknown> {
  return {
    deployment: { ...DEPLOYMENT },
    confirmations: {
      spendableNotes: { kind: "depth", blocks: 12 },
      counterAdvance: { kind: "depth", blocks: 0 },
      pssWrite: { kind: "tag", tag: "finalized" },
    },
    logRangeBlocks: 2_000,
    maxReorgBlocks: 128,
    maxOccurrencesPerTag: 1_000,
    rpcTimeoutMs: 15_000,
  };
}

function rejects(input: unknown, field: string): void {
  try {
    validateChainConfig(input);
  } catch (e) {
    expect(e).toBeInstanceOf(WalletRuntimeError);
    expect((e as WalletRuntimeError).code).toBe("CONFIG_INVALID");
    expect((e as WalletRuntimeError).context.field).toBe(field);
    return;
  }
  throw new Error(`config with a bad ${field} was accepted`);
}

describe("chain config", () => {
  it("accepts a complete config and freezes it", () => {
    const config: ChainConfig = validateChainConfig(valid());
    expect(config.confirmations.spendableNotes).toEqual({
      kind: "depth",
      blocks: 12,
    });
    expect(config.confirmations.pssWrite).toEqual({
      kind: "tag",
      tag: "finalized",
    });
    expect(Object.isFrozen(config)).toBe(true);
  });

  it.each([
    "deployment",
    "confirmations",
    "logRangeBlocks",
    "maxReorgBlocks",
    "maxOccurrencesPerTag",
    "rpcTimeoutMs",
  ])("rejects a config missing %s", (field: string) => {
    const input = valid();
    delete input[field];
    rejects(input, `config.${field}`);
  });

  it.each(["spendableNotes", "counterAdvance", "pssWrite"])(
    "rejects a config missing confirmations.%s",
    (field: string) => {
      const input = valid();
      delete (input.confirmations as Record<string, unknown>)[field];
      rejects(input, `config.confirmations.${field}`);
    },
  );

  it("rejects a deployment that is not a DeploymentRef", () => {
    const input = valid();
    input.deployment = { ...DEPLOYMENT, dark_pool: "not-an-address" };
    rejects(input, "config.deployment");
  });

  it("rejects an unknown field instead of ignoring a typo", () => {
    rejects({ ...valid(), logRangeBlock: 10 }, "config.logRangeBlock");
  });

  it.each([
    { kind: "depth", blocks: 1 },
    { kind: "tag", tag: "safe" },
    { kind: "tag", tag: "finalized" },
  ])("rejects counterAdvance %j: only depth 0 is safe", (bad: object) => {
    const input = valid();
    (input.confirmations as Record<string, unknown>).counterAdvance = bad;
    rejects(input, "config.confirmations.counterAdvance");
  });

  it("rejects an occurrence cap above the wallets bound", () => {
    rejects(
      { ...valid(), maxOccurrencesPerTag: MAX_OCCURRENCES_PER_TAG + 1 },
      "config.maxOccurrencesPerTag",
    );
  });

  it.each([
    ["logRangeBlocks", 0],
    ["rpcTimeoutMs", 0],
    ["maxReorgBlocks", -1],
    ["logRangeBlocks", 1.5],
  ] as const)("rejects %s = %d", (field: string, value: number) => {
    rejects({ ...valid(), [field]: value }, `config.${field}`);
  });

  it("rejects an unknown confirmation tag", () => {
    const input = valid();
    (input.confirmations as Record<string, unknown>).pssWrite = {
      kind: "tag",
      tag: "latest",
    };
    rejects(input, "config.confirmations.pssWrite.tag");
  });

  it("presets only the Hardhat chain, every depth 0", () => {
    const config = HARDHAT_CHAIN_CONFIG(
      parseDeploymentRef({ ...DEPLOYMENT, chain_id: "31337" }),
    );
    expect(config.deployment.chain_id).toBe("31337");
    for (const policy of Object.values(config.confirmations)) {
      expect(policy).toEqual({ kind: "depth", blocks: 0 });
    }
    expect(() =>
      HARDHAT_CHAIN_CONFIG(parseDeploymentRef(DEPLOYMENT)),
    ).toThrowError(/CONFIG_INVALID/);
  });
});
