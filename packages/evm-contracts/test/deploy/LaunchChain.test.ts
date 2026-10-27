import { expect } from "chai";
import { ethers } from "hardhat";
import * as fs from "fs";
import * as path from "path";
import { spawnSync } from "child_process";
import { Base8, mulPointEscalar } from "@zk-kit/baby-jubjub";
import {
  CIRCUIT_VERIFIERS,
  KAGE_MODULE_LAYOUT,
  LAUNCH_TOKENS,
  MULTISIG_CIRCUIT_IDS,
  assertFeeAssets,
  assertSafeOwnersDisjoint,
  assertStakingToken,
  deploy,
  isTestChain,
  kageExitDelay,
  kageModuleEnabled,
  kageModuleProblems,
  kageModuleRegistration,
  multisigVerifierMode,
  resolveComplianceKey,
  stakeAmounts,
  type SafeOwnership,
} from "../../scripts/deploy";
import { assertSokaChain } from "../../scripts/deploy-soka";
import { checkKageModule } from "../../scripts/check-kage-module";

const ARBITRUM_ONE = 42161n;
const ETHEREUM = 1n;
const ARBITRUM_SEPOLIA = 421614n;
const HARDHAT = 31337n;
const UNLISTED_CHAIN = 999999n;
const BN254_FR =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const OTHER_TOKEN = "0x1111111111111111111111111111111111111111";

function tokensOf(chainId: bigint): { usdc: string; weth: string } {
  const tokens = LAUNCH_TOKENS.get(chainId);
  if (tokens === undefined) throw new Error(`no row for ${chainId}`);
  return tokens;
}

function withEnv<T>(env: Record<string, string>, body: () => T): T {
  const saved: Record<string, string | undefined> = {};
  for (const [k, v] of Object.entries(env)) {
    saved[k] = process.env[k];
    if (v === "") delete process.env[k];
    else process.env[k] = v;
  }
  try {
    return body();
  } finally {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

async function withEnvAsync<T>(
  env: Record<string, string>,
  body: () => Promise<T>,
): Promise<T> {
  const saved: Record<string, string | undefined> = {};
  for (const [k, v] of Object.entries(env)) {
    saved[k] = process.env[k];
    if (v === "") delete process.env[k];
    else process.env[k] = v;
  }
  try {
    return await body();
  } finally {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

const NO_KEY_ENV = {
  COMPLIANCE_SECRET_KEY: "",
  LOCAL_TEST_COMPLIANCE_SECRET_KEY: "",
  COMPLIANCE_PUBLIC_KEY_X: "",
  COMPLIANCE_PUBLIC_KEY_Y: "",
};

function errorOf(body: () => unknown): string {
  try {
    body();
  } catch (e) {
    return e instanceof Error ? e.message : String(e);
  }
  throw new Error("expected a throw");
}

/**
 * Runtime code that answers each listed selector with fixed ABI-encoded bytes and reverts on anything else, so a
 * Safe's owner set can be served at an address without a Safe deployment on the in-process chain.
 */
function fixedResponseCode(responses: ReadonlyMap<string, string>): string {
  const entries = [...responses].map(([selector, data]) => ({
    selector: selector.slice(2),
    data: data.slice(2),
  }));
  const hex2 = (n: number): string => n.toString(16).padStart(4, "0");
  const prologue = "60003560e01c";
  const dispatchLength = 11;
  const fallbackLength = 4;
  const caseLength = 16;
  let caseStart =
    prologue.length / 2 + entries.length * dispatchLength + fallbackLength;
  let dataStart = caseStart + entries.length * caseLength;
  let dispatch = "";
  let cases = "";
  let blobs = "";
  for (const entry of entries) {
    const length = entry.data.length / 2;
    dispatch += `8063${entry.selector}1461${hex2(caseStart)}57`;
    cases += `5b61${hex2(length)}61${hex2(dataStart)}60003961${hex2(length)}6000f3`;
    blobs += entry.data;
    caseStart += caseLength;
    dataStart += length;
  }
  return `0x${prologue}${dispatch}600080fd${cases}${blobs}`;
}

function safeCode(owners: readonly string[], threshold: number): string {
  const iface = new ethers.Interface([
    "function getOwners() view returns (address[])",
    "function getThreshold() view returns (uint256)",
  ]);
  const coder = ethers.AbiCoder.defaultAbiCoder();
  return fixedResponseCode(
    new Map([
      [
        iface.getFunction("getOwners")?.selector ?? "",
        coder.encode(["address[]"], [owners]),
      ],
      [
        iface.getFunction("getThreshold")?.selector ?? "",
        coder.encode(["uint256"], [threshold]),
      ],
    ]),
  );
}

function ownership(
  label: string,
  owners: readonly string[],
  threshold: bigint,
): SafeOwnership {
  return {
    label,
    address: ethers.Wallet.createRandom().address,
    owners,
    threshold,
  };
}

describe("launch-chain rules: pure checks", function () {
  it("treats exactly the in-process chain, Arbitrum Sepolia and Sepolia as test chains", function () {
    for (const id of [HARDHAT, ARBITRUM_SEPOLIA, 11155111n]) {
      expect(isTestChain(id), `${id}`).to.equal(true);
    }
    for (const id of [ETHEREUM, 10n, 8453n, ARBITRUM_ONE, 43114n]) {
      expect(isTestChain(id), `${id}`).to.equal(false);
    }
  });

  it("pins the reviewed USDC and WETH rows", function () {
    expect(Object.fromEntries(LAUNCH_TOKENS)).to.deep.equal({
      "1": {
        usdc: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
        weth: "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
      },
      "10": {
        usdc: "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85",
        weth: "0x4200000000000000000000000000000000000006",
      },
      "8453": {
        usdc: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
        weth: "0x4200000000000000000000000000000000000006",
      },
      "42161": {
        usdc: "0xaf88d065e77c8cC2239327C5EDb3A432268e5831",
        weth: "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1",
      },
    });
  });

  describe("fee asset", function () {
    it("accepts exactly the chain's USDC off the test chains", function () {
      const { usdc, weth } = tokensOf(ARBITRUM_ONE);
      expect(() => assertFeeAssets(ARBITRUM_ONE, [usdc], weth)).to.not.throw();
      expect(() =>
        assertFeeAssets(ARBITRUM_ONE, [usdc.toLowerCase()], usdc),
      ).to.not.throw();
    });

    it("refuses the staking token as the fee asset", function () {
      const { weth } = tokensOf(ARBITRUM_ONE);
      expect(
        errorOf(() => assertFeeAssets(ARBITRUM_ONE, [weth], weth)),
      ).to.contain(`FEE_ASSETS entry ${weth} is the staking token`);
    });

    it("refuses any fee asset that is not the chain's USDC, alone or next to it", function () {
      const { usdc, weth } = tokensOf(ETHEREUM);
      expect(
        errorOf(() => assertFeeAssets(ETHEREUM, [OTHER_TOKEN], weth)),
      ).to.contain(`FEE_ASSETS entry ${OTHER_TOKEN} is not USDC`);
      expect(
        errorOf(() => assertFeeAssets(ETHEREUM, [usdc, OTHER_TOKEN], weth)),
      ).to.contain("is not USDC");
      expect(
        errorOf(() =>
          assertFeeAssets(ETHEREUM, [tokensOf(ARBITRUM_ONE).usdc], weth),
        ),
      ).to.contain("is not USDC");
      expect(errorOf(() => assertFeeAssets(ETHEREUM, [], weth))).to.contain(
        "FEE_ASSETS is empty",
      );
    });

    it("refuses a launch chain with no reviewed token row", function () {
      expect(
        errorOf(() =>
          assertFeeAssets(UNLISTED_CHAIN, [OTHER_TOKEN], OTHER_TOKEN),
        ),
      ).to.contain("has no USDC/WETH row in LAUNCH_TOKENS");
    });

    it("leaves the test chains free to use their test token for both", function () {
      expect(() =>
        assertFeeAssets(ARBITRUM_SEPOLIA, [OTHER_TOKEN], OTHER_TOKEN),
      ).to.not.throw();
    });
  });

  describe("staking token", function () {
    it("accepts the chain's WETH at 18 decimals and USDC at 6", function () {
      const { usdc, weth } = tokensOf(ARBITRUM_ONE);
      expect(() => assertStakingToken(ARBITRUM_ONE, weth, 18n)).to.not.throw();
      expect(() => assertStakingToken(ARBITRUM_ONE, usdc, 6n)).to.not.throw();
    });

    it("refuses any other token and a decimals mismatch", function () {
      const { usdc, weth } = tokensOf(ARBITRUM_ONE);
      expect(
        errorOf(() => assertStakingToken(ARBITRUM_ONE, OTHER_TOKEN, 18n)),
      ).to.contain("is neither WETH");
      expect(
        errorOf(() => assertStakingToken(ARBITRUM_ONE, usdc, 18n)),
      ).to.contain("reports 18 decimals, expected 6");
      expect(
        errorOf(() => assertStakingToken(ARBITRUM_ONE, weth, 6n)),
      ).to.contain("reports 6 decimals, expected 18");
      expect(
        errorOf(() => assertStakingToken(UNLISTED_CHAIN, OTHER_TOKEN, 18n)),
      ).to.contain("has no USDC/WETH row");
    });

    it("accepts any token on a test chain", function () {
      expect(() =>
        assertStakingToken(ARBITRUM_SEPOLIA, OTHER_TOKEN, 18n),
      ).to.not.throw();
    });
  });

  describe("stake amounts", function () {
    it("scales whole-token amounts by the staking token's decimals", function () {
      withEnv({ MIN_STAKE: "1000", MIN_STAKE_FLOOR: "250.5" }, () => {
        expect(stakeAmounts(ARBITRUM_ONE, 6n)).to.deep.equal({
          minStake: 1000_000000n,
          minStakeFloor: 250_500000n,
        });
        expect(stakeAmounts(ARBITRUM_ONE, 18n)).to.deep.equal({
          minStake: ethers.parseEther("1000"),
          minStakeFloor: ethers.parseEther("250.5"),
        });
      });
    });

    it("requires both amounts off the test chains and defaults them to one token on them", function () {
      withEnv({ MIN_STAKE: "", MIN_STAKE_FLOOR: "" }, () => {
        expect(errorOf(() => stakeAmounts(ARBITRUM_ONE, 6n))).to.contain(
          "MIN_STAKE is required on chain id 42161",
        );
        expect(stakeAmounts(ARBITRUM_SEPOLIA, 6n)).to.deep.equal({
          minStake: 1_000000n,
          minStakeFloor: 1_000000n,
        });
      });
      withEnv({ MIN_STAKE: "5", MIN_STAKE_FLOOR: "" }, () => {
        expect(errorOf(() => stakeAmounts(ETHEREUM, 18n))).to.contain(
          "MIN_STAKE_FLOOR is required",
        );
      });
    });

    it("refuses malformed, zero, over-precise and inverted amounts", function () {
      for (const [env, message] of [
        [
          { MIN_STAKE: "abc", MIN_STAKE_FLOOR: "1" },
          "must be a decimal amount",
        ],
        [
          { MIN_STAKE: "1e6", MIN_STAKE_FLOOR: "1" },
          "must be a decimal amount",
        ],
        [{ MIN_STAKE: "0", MIN_STAKE_FLOOR: "1" }, "must be positive"],
        [
          { MIN_STAKE: "1.0000001", MIN_STAKE_FLOOR: "1" },
          "more fractional digits than the staking token's 6 decimals",
        ],
        [{ MIN_STAKE: "1", MIN_STAKE_FLOOR: "2" }, "is below MIN_STAKE_FLOOR"],
      ] as const) {
        withEnv({ ...env }, () => {
          expect(
            errorOf(() => stakeAmounts(ARBITRUM_ONE, 6n)),
            message,
          ).to.contain(message);
        });
      }
    });
  });

  describe("Safe owner disjointness", function () {
    const [a, b, c, d, e, f, g] = Array.from(
      { length: 7 },
      () => ethers.Wallet.createRandom().address,
    );

    it("passes disjoint Safes", function () {
      expect(
        assertSafeOwnersDisjoint(
          ARBITRUM_ONE,
          ownership("GOV_SAFE", [a, b, c, d, e], 3n),
          ownership(
            "GUARDIAN_SAFE",
            [f, g, ethers.Wallet.createRandom().address],
            2n,
          ),
        ),
      ).to.deep.equal([]);
    });

    it("refuses a single shared owner off the test chains and names it", function () {
      const message = errorOf(() =>
        assertSafeOwnersDisjoint(
          ETHEREUM,
          ownership("GOV_SAFE", [a, b, c, d, e], 3n),
          ownership("GUARDIAN_SAFE", [e.toLowerCase(), f, g], 2n),
        ),
      );
      expect(message).to.contain(`shares owner(s) ${e}`);
      expect(message).to.contain("must have disjoint owners");
    });

    it("refuses a guardian whose owners alone meet the Gov threshold", function () {
      expect(
        errorOf(() =>
          assertSafeOwnersDisjoint(
            ARBITRUM_ONE,
            ownership("GOV_SAFE", [a, b, c, d, e], 3n),
            ownership("GUARDIAN_SAFE", [a, b, c], 2n),
          ),
        ),
      ).to.contain(`shares owner(s) ${a}, ${b}, ${c}`);
    });

    it("reports the overlap without refusing it on a test chain", function () {
      expect(
        assertSafeOwnersDisjoint(
          ARBITRUM_SEPOLIA,
          ownership("GOV_SAFE", [a, b, c, d, e], 3n),
          ownership("GUARDIAN_SAFE", [a, f, g], 2n),
        ),
      ).to.deep.equal([a]);
    });
  });

  describe("multisig verifier slots", function () {
    it("ships the reverting stub off the test chains and refuses the real verifiers there", function () {
      withEnv({ MULTISIG_VERIFIERS: "" }, () => {
        expect(multisigVerifierMode(ARBITRUM_ONE)).to.equal("stub");
        expect(multisigVerifierMode(ETHEREUM)).to.equal("stub");
      });
      withEnv({ MULTISIG_VERIFIERS: "stub" }, () => {
        expect(multisigVerifierMode(ARBITRUM_ONE)).to.equal("stub");
      });
      withEnv({ MULTISIG_VERIFIERS: "real" }, () => {
        expect(errorOf(() => multisigVerifierMode(ARBITRUM_ONE))).to.contain(
          "MULTISIG_VERIFIERS=real is refused on chain id 42161",
        );
      });
    });

    it("defaults to the real verifiers on a test chain and can rehearse the stub there", function () {
      withEnv({ MULTISIG_VERIFIERS: "" }, () => {
        expect(multisigVerifierMode(HARDHAT)).to.equal("real");
      });
      withEnv({ MULTISIG_VERIFIERS: "stub" }, () => {
        expect(multisigVerifierMode(ARBITRUM_SEPOLIA)).to.equal("stub");
      });
      withEnv({ MULTISIG_VERIFIERS: "yes" }, () => {
        expect(errorOf(() => multisigVerifierMode(HARDHAT))).to.contain(
          'must be "stub" or "real"',
        );
      });
    });

    it("maps the stub onto exactly the four multisig circuit ids", function () {
      expect(
        [...MULTISIG_CIRCUIT_IDS].map((id) => CIRCUIT_VERIFIERS[id].key),
      ).to.deep.equal([
        "withdrawMultisigVerifier",
        "transferMultisigVerifier",
        "splitMultisigVerifier",
        "joinMultisigVerifier",
      ]);
    });
  });

  describe("compliance key source", function () {
    const pk = mulPointEscalar(Base8, 123456789n);

    it("takes a public key with no secret on a launch chain", function () {
      withEnv(
        {
          ...NO_KEY_ENV,
          COMPLIANCE_PUBLIC_KEY_X: pk[0].toString(),
          COMPLIANCE_PUBLIC_KEY_Y: `0x${pk[1].toString(16)}`,
        },
        () => {
          const key = resolveComplianceKey(ARBITRUM_ONE, false);
          expect(key.source).to.equal("public-key");
          expect(key.sk).to.equal(null);
          expect(key.pk).to.deep.equal(pk);
        },
      );
    });

    it("refuses a generated or supplied secret off the test chains", function () {
      withEnv(NO_KEY_ENV, () => {
        expect(
          errorOf(() => resolveComplianceKey(ARBITRUM_ONE, false)),
        ).to.contain(
          "takes the compliance key as COMPLIANCE_PUBLIC_KEY_X/Y only",
        );
      });
      withEnv({ ...NO_KEY_ENV, COMPLIANCE_SECRET_KEY: "7" }, () => {
        expect(errorOf(() => resolveComplianceKey(ETHEREUM, false))).to.contain(
          "takes the compliance key as COMPLIANCE_PUBLIC_KEY_X/Y only",
        );
      });
    });

    it("still generates or reuses a secret on a test chain", function () {
      withEnv(NO_KEY_ENV, () => {
        const key = resolveComplianceKey(ARBITRUM_SEPOLIA, false);
        expect(key.source).to.equal("generated");
        expect(typeof key.sk).to.equal("bigint");
      });
      withEnv({ ...NO_KEY_ENV, COMPLIANCE_SECRET_KEY: "7" }, () => {
        const key = resolveComplianceKey(ARBITRUM_SEPOLIA, false);
        expect(key.source).to.equal("supplied-secret");
        expect(key.pk).to.deep.equal(mulPointEscalar(Base8, 7n));
      });
    });

    it("refuses points off the curve, the identity, a low-order point and out-of-field coordinates", function () {
      for (const [x, y, message] of [
        [
          pk[0].toString(),
          (pk[1] + 1n).toString(),
          "not on the BabyJubJub curve",
        ],
        ["0", "1", "is the identity point"],
        [
          "0",
          (BN254_FR - 1n).toString(),
          "not in the BabyJubJub prime-order subgroup",
        ],
        [BN254_FR.toString(), "1", "outside the BN254 scalar field"],
        ["-5", "1", "outside the BN254 scalar field"],
        ["0xzz", "1", "unsigned decimal or 0x-hex integer"],
      ] as const) {
        withEnv(
          {
            ...NO_KEY_ENV,
            COMPLIANCE_PUBLIC_KEY_X: x,
            COMPLIANCE_PUBLIC_KEY_Y: y,
          },
          () => {
            expect(
              errorOf(() => resolveComplianceKey(ARBITRUM_ONE, false)),
              message,
            ).to.contain(message);
          },
        );
      }
    });

    it("refuses half a public key and a public key next to a secret", function () {
      withEnv(
        { ...NO_KEY_ENV, COMPLIANCE_PUBLIC_KEY_X: pk[0].toString() },
        () => {
          expect(
            errorOf(() => resolveComplianceKey(ARBITRUM_ONE, false)),
          ).to.contain(
            "Set both COMPLIANCE_PUBLIC_KEY_X and COMPLIANCE_PUBLIC_KEY_Y",
          );
        },
      );
      withEnv(
        {
          ...NO_KEY_ENV,
          COMPLIANCE_PUBLIC_KEY_X: pk[0].toString(),
          COMPLIANCE_PUBLIC_KEY_Y: pk[1].toString(),
          COMPLIANCE_SECRET_KEY: "7",
        },
        () => {
          expect(errorOf(() => resolveComplianceKey(HARDHAT, true))).to.contain(
            "not both",
          );
        },
      );
    });
  });

  describe("Kage module flag", function () {
    it("defaults off, and refuses on off the test chains while the launch is parked", function () {
      withEnv({ KAGE_MODULE: "" }, () => {
        expect(kageModuleEnabled(ARBITRUM_ONE)).to.equal(false);
        expect(kageModuleEnabled(HARDHAT)).to.equal(false);
      });
      withEnv({ KAGE_MODULE: "off" }, () => {
        expect(kageModuleEnabled(ETHEREUM)).to.equal(false);
      });
      withEnv({ KAGE_MODULE: "on" }, () => {
        expect(kageModuleEnabled(ARBITRUM_SEPOLIA)).to.equal(true);
        expect(errorOf(() => kageModuleEnabled(ARBITRUM_ONE))).to.contain(
          "KAGE_MODULE=on is refused on chain id 42161",
        );
      });
      withEnv({ KAGE_MODULE: "true" }, () => {
        expect(errorOf(() => kageModuleEnabled(HARDHAT))).to.contain(
          'must be "on" or "off"',
        );
      });
    });

    it("defaults the solver exit delay to 7 days and refuses one below a day", function () {
      withEnv({ KAGE_EXIT_DELAY_SECS: "" }, () => {
        expect(kageExitDelay()).to.equal(604800n);
      });
      withEnv({ KAGE_EXIT_DELAY_SECS: "86400" }, () => {
        expect(kageExitDelay()).to.equal(86400n);
      });
      withEnv({ KAGE_EXIT_DELAY_SECS: "86399" }, () => {
        expect(errorOf(() => kageExitDelay())).to.contain(
          "below the registry minimum of 86400s",
        );
      });
      withEnv({ KAGE_EXIT_DELAY_SECS: "1d" }, () => {
        expect(errorOf(() => kageExitDelay())).to.contain(
          "unsigned decimal number of seconds",
        );
      });
    });

    it("encodes the registration as (2 spends, 4 outputs, 0 extras, maxPast 0, maxFuture unbounded)", function () {
      const [pool, settlement, verifier] = Array.from(
        { length: 3 },
        () => ethers.Wallet.createRandom().address,
      );
      const call = kageModuleRegistration(pool, settlement, verifier);
      expect(call.target).to.equal(pool);
      expect(call.value).to.equal("0");
      const iface = new ethers.Interface([
        "function registerSettlementModule(address,address,uint8,uint8,uint8,uint32,uint32)",
      ]);
      const args = iface.decodeFunctionData(
        "registerSettlementModule",
        call.data,
      );
      expect([...args]).to.deep.equal([
        settlement,
        verifier,
        2n,
        4n,
        0n,
        0n,
        2n ** 32n - 1n,
      ]);
      expect(KAGE_MODULE_LAYOUT).to.deep.equal({
        nullifierCount: 2n,
        outputCount: 4n,
        extraCount: 0n,
        maxPast: 0n,
        maxFuture: 4294967295n,
      });
    });
  });

  it("refuses to deploy SOKA off the test chains", function () {
    for (const id of [ETHEREUM, ARBITRUM_ONE, 43114n]) {
      expect(errorOf(() => assertSokaChain(id))).to.contain(
        `refusing to deploy it on chain id ${id}`,
      );
    }
    for (const id of [HARDHAT, ARBITRUM_SEPOLIA, 11155111n]) {
      expect(() => assertSokaChain(id)).to.not.throw();
    }
  });
});

interface LaunchRecord {
  contracts: Record<string, string>;
  compliance: { source: string; publicKeyX: string; publicKeyY: string };
  multisigVerifiers: string;
  vkHashes: Record<string, string>;
  staking: {
    token: string;
    decimals: number;
    minStake: string;
    minStakeFloor: string;
  };
  verifierSlots: {
    circuitId: number;
    verifier: string;
    address: string;
    codeHash: string;
    vkHash: string | null;
  }[];
  governance: {
    timelock: string;
    safeOwners: Record<string, { owners: string[]; threshold: number }>;
  };
  kage: {
    registry: string;
    settlement: string;
    verifier: string;
    stakingToken: string;
    stakingTokenDecimals: number;
    minStake: string;
    minStakeFloor: string;
    exitDelaySeconds: number;
    eip712Domain: {
      name: string;
      version: string;
      chainId: number;
      verifyingContract: string;
    };
    settlementTypehash: string;
    moduleLayout: Record<string, number>;
    moduleRegistration: { target: string; value: string; data: string };
  } | null;
}

async function quietDeploy(env: Record<string, string>): Promise<{
  ok: boolean;
  output: string;
  secretsFile: string | null;
  record: LaunchRecord | null;
}> {
  const lines: string[] = [];
  const realLog = console.log;
  console.log = (...args: unknown[]) => {
    lines.push(args.map(String).join(" "));
  };
  try {
    const result = await withEnvAsync(env, () => deploy());
    return {
      ok: true,
      output: lines.join("\n"),
      secretsFile: result.secretsFile,
      record: result.deployment as unknown as LaunchRecord,
    };
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    return {
      ok: false,
      output: `${lines.join("\n")}\n${message}`,
      secretsFile: null,
      record: null,
    };
  } finally {
    console.log = realLog;
  }
}

describe("launch-shaped deployment on the in-process chain", function () {
  this.timeout(600000);

  const pk = mulPointEscalar(Base8, 987654321n);
  let run: Awaited<ReturnType<typeof quietDeploy>>;
  let record: LaunchRecord;
  let govSafe: string;
  let guardianSafe: string;
  const govOwners = Array.from(
    { length: 5 },
    () => ethers.Wallet.createRandom().address,
  );
  const guardianOwners = Array.from(
    { length: 3 },
    () => ethers.Wallet.createRandom().address,
  );

  before(async function () {
    const usdcLike = await (
      await ethers.getContractFactory("MockERC20")
    ).deploy("USD Coin", "USDC", 6);
    const feeToken = await (
      await ethers.getContractFactory("MockERC20")
    ).deploy("Fee Coin", "FEE", 6);
    govSafe = ethers.Wallet.createRandom().address;
    guardianSafe = ethers.Wallet.createRandom().address;
    await ethers.provider.send("hardhat_setCode", [
      govSafe,
      safeCode(govOwners, 3),
    ]);
    await ethers.provider.send("hardhat_setCode", [
      guardianSafe,
      safeCode(guardianOwners, 2),
    ]);
    run = await quietDeploy({
      ...NO_KEY_ENV,
      GOV_SAFE: govSafe,
      GUARDIAN_SAFE: guardianSafe,
      STAKING_TOKEN: await usdcLike.getAddress(),
      FEE_ASSETS: await feeToken.getAddress(),
      MIN_STAKE: "1000",
      MIN_STAKE_FLOOR: "250",
      MULTISIG_VERIFIERS: "stub",
      COMPLIANCE_PUBLIC_KEY_X: pk[0].toString(),
      COMPLIANCE_PUBLIC_KEY_Y: pk[1].toString(),
    });
    if (run.record !== null) record = run.record;
  });

  it("runs to completion", function () {
    expect(run.ok, run.output.slice(-2000)).to.equal(true);
  });

  it("binds the pool to the supplied public key and writes no secret", async function () {
    expect(run.secretsFile).to.equal(null);
    expect(run.output).to.not.contain("Compliance secret written");
    expect(run.output).to.contain(
      "Using the supplied compliance public key; no compliance secret exists on this machine",
    );
    expect(record.compliance.source).to.equal("public-key");
    const darkPool = await ethers.getContractAt(
      "DarkPool",
      record.contracts.darkPool,
    );
    const [x, y] = await darkPool.complianceKey();
    expect([x, y]).to.deep.equal([pk[0], pk[1]]);
  });

  it("writes the stake and its floor in the 6-decimal token's own units", async function () {
    const registry = await ethers.getContractAt(
      "NoxRegistry",
      record.contracts.noxRegistry,
    );
    expect(await registry.minStakeAmount()).to.equal(1000_000000n);
    expect(await registry.minStakeFloor()).to.equal(250_000000n);
    expect(record.staking).to.deep.equal({
      token: record.contracts.stakingToken,
      decimals: 6,
      minStake: "1000000000",
      minStakeFloor: "250000000",
    });
  });

  it("reads both Safes' owners and records them when they are disjoint", function () {
    expect(run.output).to.contain(
      "Safe owners disjoint: Gov 3-of-5, Guardian 2-of-3",
    );
    expect(record.governance.safeOwners).to.deep.equal({
      GOV_SAFE: { owners: govOwners, threshold: 3 },
      GUARDIAN_SAFE: { owners: guardianOwners, threshold: 2 },
    });
  });

  it("puts the reverting stub in the four multisig slots and real verifiers everywhere else", async function () {
    const darkPool = await ethers.getContractAt(
      "DarkPool",
      record.contracts.darkPool,
    );
    const stub = record.contracts.revertingVerifier;
    expect(stub).to.match(/^0x[0-9a-fA-F]{40}$/);
    expect(record.multisigVerifiers).to.equal("stub");
    const stubCodeHash = ethers.keccak256(await ethers.provider.getCode(stub));
    for (let circuitId = 0; circuitId < CIRCUIT_VERIFIERS.length; circuitId++) {
      const address = await darkPool.verifier(circuitId);
      const slot = record.verifierSlots[circuitId];
      expect(slot.address, `slot ${circuitId}`).to.equal(address);
      expect(slot.codeHash, `slot ${circuitId}`).to.equal(
        ethers.keccak256(await ethers.provider.getCode(address)),
      );
      if (MULTISIG_CIRCUIT_IDS.has(circuitId)) {
        expect(address, `slot ${circuitId}`).to.equal(stub);
        expect(slot.verifier).to.equal("RevertingVerifier");
        expect(slot.vkHash).to.equal(null);
      } else {
        expect(address, `slot ${circuitId}`).to.not.equal(stub);
        expect(slot.codeHash).to.not.equal(stubCodeHash);
        expect(slot.vkHash).to.match(/^0x[0-9a-fA-F]{64}$/);
      }
    }
    for (const name of [
      "WithdrawMultisigVerifier",
      "TransferMultisigVerifier",
      "SplitMultisigVerifier",
      "JoinMultisigVerifier",
    ]) {
      expect(record.vkHashes, name).to.not.have.property(name);
    }
    expect(run.output).to.contain(
      "[ok] Every circuit slot holds its intended verifier (multisig slots: stub)",
    );
  });

  it("rejects a multisig spend at the stub with its own error", async function () {
    const darkPool = await ethers.getContractAt(
      "DarkPool",
      record.contracts.darkPool,
    );
    const stub = await ethers.getContractAt(
      "RevertingVerifier",
      record.contracts.revertingVerifier,
    );
    const [rootLog] = await ethers.provider.getLogs({
      address: record.contracts.darkPool,
      topics: [ethers.id("RootSaved(bytes32)")],
      fromBlock: 0,
    });
    expect(await darkPool.isKnownRoot(rootLog.topics[1])).to.equal(true);
    const inputs: string[] = Array.from({ length: 17 }, () => ethers.ZeroHash);
    inputs[3] = ethers.toBeHex(pk[0], 32);
    inputs[4] = ethers.toBeHex(pk[1], 32);
    inputs[6] = rootLog.topics[1];
    await expect(
      darkPool.withdrawMultisig("0x", inputs),
    ).to.be.revertedWithCustomError(stub, "VerifierNotConfigured");
    await expect(stub.verify("0x", [])).to.be.revertedWithCustomError(
      stub,
      "VerifierNotConfigured",
    );
  });

  it("leaves the Kage module out by default", function () {
    expect(record.kage).to.equal(null);
    expect(record.contracts).to.not.have.property("kageRegistry");
    expect(run.output).to.contain("Kage module: off");
  });

  it("does not leave a secrets file behind for this run", function () {
    const deployFile = /Deployment record: (\S+)/.exec(run.output)?.[1];
    expect(deployFile, "record path").to.be.a("string");
    const secrets = (deployFile as string).replace(/\.json$/, ".secrets.json");
    expect(fs.existsSync(secrets)).to.equal(false);
  });
});

describe("Kage module deployment on the in-process chain", function () {
  this.timeout(600000);

  const GOV = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
  const GUARDIAN = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC";
  let run: Awaited<ReturnType<typeof quietDeploy>>;
  let record: LaunchRecord;
  let kage: NonNullable<LaunchRecord["kage"]>;
  let kageToken: string;
  let recordFile: string;

  async function throughTimelock(target: string, data: string): Promise<void> {
    const gov = await ethers.getSigner(GOV);
    const timelock = await ethers.getContractAt(
      "TimelockController",
      record.governance.timelock,
      gov,
    );
    const salt = ethers.hexlify(ethers.randomBytes(32));
    await (
      await timelock.schedule(target, 0, data, ethers.ZeroHash, salt, 0)
    ).wait();
    await (
      await timelock.execute(target, 0, data, ethers.ZeroHash, salt)
    ).wait();
  }

  before(async function () {
    const token = await (
      await ethers.getContractFactory("MockERC20")
    ).deploy("USD Coin", "USDC", 6);
    kageToken = await token.getAddress();
    run = await quietDeploy({
      ...NO_KEY_ENV,
      GOV_SAFE: GOV,
      GUARDIAN_SAFE: GUARDIAN,
      STAKING_TOKEN: "",
      FEE_ASSETS: "",
      MIN_STAKE: "",
      MIN_STAKE_FLOOR: "",
      MULTISIG_VERIFIERS: "",
      TIMELOCK_MIN_DELAY_SECS: "0",
      ADMIN_TRANSFER_DELAY_SECS: "0",
      KAGE_MODULE: "on",
      KAGE_STAKING_TOKEN: kageToken,
      KAGE_MIN_STAKE: "10000",
      KAGE_MIN_STAKE_FLOOR: "1000",
      KAGE_EXIT_DELAY_SECS: "",
    });
    if (run.record !== null && run.record.kage !== null) {
      record = run.record;
      kage = run.record.kage;
    }
    recordFile = /Deployment record: (\S+)/.exec(run.output)?.[1] ?? "";
  });

  it("deploys the registry and settlement and wires them to the pool", async function () {
    expect(run.ok, run.output.slice(-2000)).to.equal(true);
    const settlement = await ethers.getContractAt(
      "KageSettlement",
      kage.settlement,
    );
    expect(await settlement.DARK_POOL()).to.equal(record.contracts.darkPool);
    expect(await settlement.REGISTRY()).to.equal(kage.registry);
    expect(record.contracts.kageRegistry).to.equal(kage.registry);
    expect(record.contracts.kageSettlement).to.equal(kage.settlement);
    expect(kage.verifier).to.equal(record.contracts.kageVerifier);
    expect(kage.settlementTypehash).to.equal(
      "0x7ffa2d5aad35edb790ebb58164e6295a1d3de164ece1e8683f412d87f1157fda",
    );
    expect(kage.eip712Domain).to.deep.equal({
      name: "HisokaKageSettlement",
      version: "1",
      chainId: 31337,
      verifyingContract: kage.settlement,
    });
  });

  it("stakes the 6-decimal token in its own units with a 7-day exit delay", async function () {
    const registry = await ethers.getContractAt("KageRegistry", kage.registry);
    expect(await registry.stakingToken()).to.equal(kageToken);
    expect(await registry.minStake()).to.equal(10000_000000n);
    expect(await registry.minStakeFloor()).to.equal(1000_000000n);
    expect(await registry.exitDelay()).to.equal(604800n);
    expect(kage.stakingTokenDecimals).to.equal(6);
  });

  it("hands every registry role to governance and pins it before and after the renounce", async function () {
    const registry = await ethers.getContractAt("KageRegistry", kage.registry);
    expect(await registry.defaultAdmin()).to.equal(record.governance.timelock);
    expect(
      await registry.hasRole(await registry.SLASHER_ROLE(), GUARDIAN),
    ).to.equal(true);
    for (const role of [
      await registry.CONFIG_ROLE(),
      await registry.UPGRADER_ROLE(),
    ]) {
      expect(await registry.hasRole(role, record.governance.timelock)).to.equal(
        true,
      );
    }
    expect(run.output).to.contain(
      "[ok] Every role on Timelock, DarkPool, NoxRegistry, NoxRewardPool, ComplianceRegistry and KageRegistry is still held",
    );
    expect(run.output).to.contain(
      "[ok] KageSettlement is linked to DarkPool and KageRegistry",
    );
  });

  it("leaves the module unregistered until the Timelock runs the recorded call", async function () {
    const darkPool = await ethers.getContractAt(
      "DarkPool",
      record.contracts.darkPool,
    );
    expect(
      await kageModuleProblems(darkPool, kage.settlement, kage.verifier),
    ).to.deep.equal([
      `no settlement module is registered for ${kage.settlement}`,
    ]);
    let error = "";
    try {
      await checkKageModule(recordFile);
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
    expect(error).to.contain("no settlement module is registered");
  });

  it("registers with maxPast 0 through the Timelock and passes the post-registration check", async function () {
    await throughTimelock(
      kage.moduleRegistration.target,
      kage.moduleRegistration.data,
    );
    const darkPool = await ethers.getContractAt(
      "DarkPool",
      record.contracts.darkPool,
    );
    const m = await darkPool.settlementModule(kage.settlement);
    expect(m.maxPast).to.equal(0n);
    expect(m.maxFuture).to.equal(2n ** 32n - 1n);
    expect(
      await kageModuleProblems(darkPool, kage.settlement, kage.verifier),
    ).to.deep.equal([]);
    const realLog = console.log;
    console.log = () => undefined;
    try {
      await checkKageModule(recordFile);
    } finally {
      console.log = realLog;
    }
  });

  it("flags a Kage controller registered with the generic 300-second past window", async function () {
    const settlement = await (
      await ethers.getContractFactory("KageSettlement")
    ).deploy(record.contracts.darkPool, kage.registry);
    const controller = await settlement.getAddress();
    const iface = new ethers.Interface([
      "function registerSettlementModule(address,address,uint8,uint8,uint8,uint32,uint32)",
    ]);
    await throughTimelock(
      record.contracts.darkPool,
      iface.encodeFunctionData("registerSettlementModule", [
        controller,
        kage.verifier,
        2,
        4,
        0,
        300,
        2n ** 32n - 1n,
      ]),
    );
    const darkPool = await ethers.getContractAt(
      "DarkPool",
      record.contracts.darkPool,
    );
    expect(
      await kageModuleProblems(darkPool, controller, kage.verifier),
    ).to.deep.equal(["maxPast is 300, expected 0"]);
  });

  it("flags a Kage controller registered with a verifier other than the Kage verifier", async function () {
    const settlement = await (
      await ethers.getContractFactory("KageSettlement")
    ).deploy(record.contracts.darkPool, kage.registry);
    const controller = await settlement.getAddress();
    const otherVerifier = record.verifierSlots[0].address;
    expect(otherVerifier).to.not.equal(kage.verifier);
    const iface = new ethers.Interface([
      "function registerSettlementModule(address,address,uint8,uint8,uint8,uint32,uint32)",
    ]);
    await throughTimelock(
      record.contracts.darkPool,
      iface.encodeFunctionData("registerSettlementModule", [
        controller,
        otherVerifier,
        2,
        4,
        0,
        0,
        2n ** 32n - 1n,
      ]),
    );
    const darkPool = await ethers.getContractAt(
      "DarkPool",
      record.contracts.darkPool,
    );
    expect(
      await kageModuleProblems(darkPool, controller, kage.verifier),
    ).to.deep.equal([
      `module verifier is ${otherVerifier}, expected ${kage.verifier}`,
    ]);
  });

  it("flags the registered Kage module once the pauser disables it", async function () {
    const darkPool = await ethers.getContractAt(
      "DarkPool",
      record.contracts.darkPool,
      await ethers.getSigner(GUARDIAN),
    );
    await (await darkPool.disableModule(kage.settlement)).wait();
    try {
      expect(
        await kageModuleProblems(darkPool, kage.settlement, kage.verifier),
      ).to.deep.equal(["module is not active"]);
      let error = "";
      try {
        await checkKageModule(recordFile);
      } catch (e) {
        error = e instanceof Error ? e.message : String(e);
      }
      expect(error).to.contain("module is not active");
    } finally {
      await throughTimelock(
        record.contracts.darkPool,
        darkPool.interface.encodeFunctionData("enableModule", [
          kage.settlement,
        ]),
      );
    }
  });
});

describe("archive-deployment.sh", function () {
  this.timeout(600000);

  const root = path.join(__dirname, "../..");
  const deployments = path.join(root, "deployments");
  let name: string;
  const created: string[] = [];

  function archive(deploymentName: string): {
    status: number | null;
    output: string;
  } {
    const r = spawnSync(
      "bash",
      [path.join(root, "scripts/archive-deployment.sh"), deploymentName],
      { cwd: root, encoding: "utf8" },
    );
    return { status: r.status, output: `${r.stdout}${r.stderr}` };
  }

  before(async function () {
    const r = await quietDeploy({
      ...NO_KEY_ENV,
      GOV_SAFE: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
      GUARDIAN_SAFE: "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
      STAKING_TOKEN: "",
      FEE_ASSETS: "",
      MIN_STAKE: "",
      MIN_STAKE_FLOOR: "",
      MULTISIG_VERIFIERS: "stub",
    });
    expect(r.ok, r.output.slice(-2000)).to.equal(true);
    expect(r.output).to.contain(
      "multisig actions and multisig Nox fees revert until the Timelock sets the real verifiers",
    );
    const deployFile = /Deployment record: (\S+)/.exec(r.output)?.[1] ?? "";
    name = path.basename(deployFile, ".json");
    created.push(path.join(deployments, "archives", name));
  });

  after(function () {
    for (const target of created) {
      fs.rmSync(target, { recursive: true, force: true });
    }
  });

  it("archives the stub verifier, the hook interface and both payment adapters' identity", function () {
    const r = archive(name);
    expect(r.status, r.output).to.equal(0);
    const dir = path.join(deployments, "archives", name);
    expect(
      fs.existsSync(path.join(dir, "verifiers/RevertingVerifier.sol")),
    ).to.equal(true);
    for (const abi of [
      "IDarkPoolSettlement",
      "IProofVerifier",
      "RevertingVerifier",
    ]) {
      expect(fs.existsSync(path.join(dir, `abis/${abi}.json`)), abi).to.equal(
        true,
      );
    }
    const record = JSON.parse(
      fs.readFileSync(path.join(deployments, `${name}.json`), "utf8"),
    ) as LaunchRecord & {
      contractCodeHashes: Record<string, string>;
      constructorArgs: Record<string, unknown[]>;
    };
    const identity = JSON.parse(
      fs.readFileSync(path.join(dir, "identity.json"), "utf8"),
    ) as {
      settlementHook: { contract: string };
      multisigVerifiers: string;
      verifierSlots: LaunchRecord["verifierSlots"];
      paymentAdapters: Record<
        string,
        { address: string; codeHash: string; constructorArgs: unknown[] }
      >;
    };
    expect(identity.settlementHook.contract).to.equal(
      record.contracts.darkPool,
    );
    expect(identity.multisigVerifiers).to.equal("stub");
    expect(identity.verifierSlots).to.deep.equal(record.verifierSlots);
    expect(identity.paymentAdapters).to.deep.equal({
      standard: {
        address: record.contracts.howlPaymentAdapter,
        codeHash: record.contractCodeHashes.howlPaymentAdapter,
        constructorArgs: record.constructorArgs.howlPaymentAdapter,
      },
      multisig: {
        address: record.contracts.howlMultisigPaymentAdapter,
        codeHash: record.contractCodeHashes.howlMultisigPaymentAdapter,
        constructorArgs: record.constructorArgs.howlMultisigPaymentAdapter,
      },
    });
  });

  it("refuses a record that lacks the multisig adapter or the verifier identity", function () {
    const record = JSON.parse(
      fs.readFileSync(path.join(deployments, `${name}.json`), "utf8"),
    ) as Record<string, Record<string, unknown>>;
    delete record.contracts.howlMultisigPaymentAdapter;
    delete record.constructorArgs.howlMultisigPaymentAdapter;
    delete record.verifierSlots;
    const broken = `${name}-incomplete`;
    const brokenFile = path.join(deployments, `${broken}.json`);
    fs.writeFileSync(brokenFile, JSON.stringify(record));
    created.push(brokenFile, path.join(deployments, "archives", broken));
    const r = archive(broken);
    expect(r.status).to.equal(1);
    expect(r.output).to.contain("contracts.howlMultisigPaymentAdapter missing");
    expect(r.output).to.contain(
      "constructorArgs.howlMultisigPaymentAdapter missing",
    );
    expect(r.output).to.contain("verifierSlots must list 10 circuit slots");
    expect(fs.existsSync(path.join(deployments, "archives", broken))).to.equal(
      false,
    );
  });

  it("archives a Kage deployment's module and refuses one whose layout is not maxPast 0", async function () {
    const r = await quietDeploy({
      ...NO_KEY_ENV,
      GOV_SAFE: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
      GUARDIAN_SAFE: "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
      STAKING_TOKEN: "",
      FEE_ASSETS: "",
      MIN_STAKE: "",
      MIN_STAKE_FLOOR: "",
      MULTISIG_VERIFIERS: "",
      KAGE_MODULE: "on",
      KAGE_STAKING_TOKEN: "",
      KAGE_MIN_STAKE: "",
      KAGE_MIN_STAKE_FLOOR: "",
    });
    expect(r.ok, r.output.slice(-2000)).to.equal(true);
    const kageName = path.basename(
      /Deployment record: (\S+)/.exec(r.output)?.[1] ?? "",
      ".json",
    );
    created.push(path.join(deployments, "archives", kageName));
    const ok = archive(kageName);
    expect(ok.status, ok.output).to.equal(0);
    const dir = path.join(deployments, "archives", kageName);
    for (const abi of ["KageRegistry", "KageSettlement", "IKageRegistry"]) {
      expect(fs.existsSync(path.join(dir, `abis/${abi}.json`)), abi).to.equal(
        true,
      );
    }
    const kageRecord = r.record?.kage;
    const identity = JSON.parse(
      fs.readFileSync(path.join(dir, "identity.json"), "utf8"),
    ) as {
      settlementHook: {
        modules: { controller: string; layout: Record<string, number> }[];
      };
      kage: LaunchRecord["kage"];
    };
    expect(identity.kage).to.deep.equal(kageRecord);
    expect(identity.settlementHook.modules).to.have.length(1);
    expect(identity.settlementHook.modules[0].controller).to.equal(
      kageRecord?.settlement,
    );
    expect(identity.settlementHook.modules[0].layout.maxPast).to.equal(0);

    const tampered = JSON.parse(
      fs.readFileSync(path.join(deployments, `${kageName}.json`), "utf8"),
    ) as { kage: { moduleLayout: { maxPast: number } } };
    tampered.kage.moduleLayout.maxPast = 300;
    const broken = `${kageName}-maxpast`;
    const brokenFile = path.join(deployments, `${broken}.json`);
    fs.writeFileSync(brokenFile, JSON.stringify(tampered));
    created.push(brokenFile, path.join(deployments, "archives", broken));
    const refused = archive(broken);
    expect(refused.status).to.equal(1);
    expect(refused.output).to.contain(
      "kage section lacks its contracts, its registration call, or maxPast 0",
    );
  });
});

describe("Safe ownership checks on the in-process chain", function () {
  this.timeout(600000);

  it("warns, without refusing, when the Safes share an owner on a test chain", async function () {
    const shared = ethers.Wallet.createRandom().address;
    const govSafe = ethers.Wallet.createRandom().address;
    const guardianSafe = ethers.Wallet.createRandom().address;
    const others = Array.from(
      { length: 6 },
      () => ethers.Wallet.createRandom().address,
    );
    await ethers.provider.send("hardhat_setCode", [
      govSafe,
      safeCode([shared, ...others.slice(0, 4)], 3),
    ]);
    await ethers.provider.send("hardhat_setCode", [
      guardianSafe,
      safeCode([shared, ...others.slice(4)], 2),
    ]);
    const r = await quietDeploy({
      ...NO_KEY_ENV,
      GOV_SAFE: govSafe,
      GUARDIAN_SAFE: guardianSafe,
      STAKING_TOKEN: "",
      FEE_ASSETS: "",
      MIN_STAKE: "",
      MIN_STAKE_FLOOR: "",
      MULTISIG_VERIFIERS: "",
    });
    expect(r.ok, r.output.slice(-2000)).to.equal(true);
    expect(r.output).to.contain(
      `WARNING: GUARDIAN_SAFE shares owner(s) ${shared} with GOV_SAFE; accepted only on test chain 31337.`,
    );
  });

  it("refuses, before any transaction, a Safe address whose code does not answer as a Safe", async function () {
    const [deployer] = await ethers.getSigners();
    const notASafe = ethers.Wallet.createRandom().address;
    const govSafe = ethers.Wallet.createRandom().address;
    await ethers.provider.send("hardhat_setCode", [
      notASafe,
      fixedResponseCode(new Map()),
    ]);
    await ethers.provider.send("hardhat_setCode", [
      govSafe,
      safeCode([ethers.Wallet.createRandom().address], 1),
    ]);
    const nonceBefore = await ethers.provider.getTransactionCount(
      deployer.address,
    );
    const r = await quietDeploy({
      ...NO_KEY_ENV,
      GOV_SAFE: govSafe,
      GUARDIAN_SAFE: notASafe,
    });
    expect(r.ok).to.equal(false);
    expect(r.output).to.contain(
      `GUARDIAN_SAFE ${notASafe} does not answer as a Safe (getOwners/getThreshold)`,
    );
    expect(r.output).to.not.contain("Step 1: Poseidon2");
    expect(
      await ethers.provider.getTransactionCount(deployer.address),
    ).to.equal(nonceBefore);
  });
});
