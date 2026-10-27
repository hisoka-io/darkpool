import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import { howlPaymentIntent } from "@hisoka/adaptors";
import { keccak256, TypedDataEncoder, hexlify } from "ethers";
import { WalletRuntimeError } from "../errors.js";
import {
  EXECUTION_QUOTE_TYPES,
  executionIdOf,
  verifyFeeQuoteForSigning,
  type ApprovedFeeSpend,
  type ExecutionQuote,
} from "../submit/noxQuote.js";

const here = dirname(fileURLToPath(import.meta.url));

const ENTRY = "0x00000000000000000000000000000000000e0001";
const ADAPTER = "0x00000000000000000000000000000000000ad0a7";
const EXIT = "0x00000000000000000000000000000000000e0e17";
const FEE_ASSET = "0x00000000000000000000000000000000000a55e7";
const POOL = "0x6dab000000000000000000000000000000000001";
const ACTION = Uint8Array.from([0x2e, 0x1a, 0x7d, 0x4d, 1, 2, 3]);
const NULLIFIER = `0x${"5a".repeat(32)}`;

const APPROVED: ApprovedFeeSpend = {
  chainId: 31337n,
  entryPoint: ENTRY,
  paymentAdapter: ADAPTER,
  feeNoteNullifier: NULLIFIER,
  feeAsset: FEE_ASSET,
  maxTotalFee: 1_000n,
  action: { target: POOL, data: ACTION },
};

const QUOTE: ExecutionQuote = {
  quoteVersion: 1,
  chainId: 31337n,
  entryPoint: ENTRY,
  exitAddress: EXIT,
  clientIntentId: `0x${"11".repeat(32)}`,
  paymentAdapter: ADAPTER,
  paymentId: NULLIFIER,
  feeAsset: FEE_ASSET,
  exitFee: 600n,
  networkFee: 150n,
  paymentGasLimit: 1_955_800n,
  actionTarget: POOL,
  actionCalldataHash: keccak256(hexlify(ACTION)),
  actionGasLimit: 1_914_000n,
  trackedAssetsHash: `0x${"00".repeat(32)}`,
  maximumTransactionGas: 4_200_000n,
  maximumFeePerGas: 2_000_000_000n,
  returnDataLimit: 256n,
  validAfterUnix: 0n,
  validUntilUnix: 2_000_000_000n,
  quoteNonce: 7n,
};

function honestMessage(quote: ExecutionQuote = QUOTE) {
  return {
    value: quote.exitFee + quote.networkFee,
    recipient: ADAPTER,
    intentHash: howlPaymentIntent(executionIdOf(quote)),
  };
}

function refusedField(fn: () => unknown): string {
  try {
    fn();
  } catch (e) {
    expect(e).toBeInstanceOf(WalletRuntimeError);
    expect((e as WalletRuntimeError).code).toBe("QUOTE_REJECTED");
    return (e as WalletRuntimeError).context.field ?? "";
  }
  return "signed";
}

describe("multisig fee quote check before signing", () => {
  it("hashes the quote with exactly the struct NoxEntryPoint hashes", () => {
    const source = readFileSync(
      join(
        here,
        "..",
        "..",
        "..",
        "evm-contracts",
        "contracts",
        "nox",
        "NoxEntryPoint.sol",
      ),
      "utf8",
    );
    const literal = /"(ExecutionQuote\([^"]+\))"/.exec(source)?.[1];
    expect(literal).toBeDefined();
    expect(
      TypedDataEncoder.from(EXECUTION_QUOTE_TYPES).encodeType("ExecutionQuote"),
    ).toBe(literal);
    expect(source).toContain('EIP712("NoxEntryPoint", "1")');
    expect(executionIdOf(QUOTE)).toBe(
      TypedDataEncoder.hash(
        {
          name: "NoxEntryPoint",
          version: "1",
          chainId: 31337n,
          verifyingContract: ENTRY,
        },
        EXECUTION_QUOTE_TYPES,
        QUOTE,
      ),
    );
    expect(executionIdOf({ ...QUOTE, quoteNonce: 8n })).not.toBe(
      executionIdOf(QUOTE),
    );
  });

  it("signs an honest quote and returns the recomputed execution id and intent", () => {
    const out = verifyFeeQuoteForSigning(QUOTE, APPROVED, honestMessage());
    expect(out.executionId).toBe(executionIdOf(QUOTE));
    expect(out.intentHash.equals(howlPaymentIntent(out.executionId))).toBe(
      true,
    );
  });

  it.each([
    ["quoteVersion", { quoteVersion: 2 }],
    ["chainId", { chainId: 1n }],
    ["entryPoint", { entryPoint: `0x${"99".repeat(20)}` }],
    ["paymentAdapter", { paymentAdapter: `0x${"98".repeat(20)}` }],
    ["paymentId", { paymentId: `0x${"5b".repeat(32)}` }],
    ["feeAsset", { feeAsset: `0x${"97".repeat(20)}` }],
    ["actionTarget", { actionTarget: `0x${"96".repeat(20)}` }],
    ["actionCalldataHash", { actionCalldataHash: `0x${"95".repeat(32)}` }],
    ["exitFee + networkFee", { exitFee: 900n }],
  ] as const)(
    "refuses a quote whose %s is not what the group approved",
    (field: string, change: Partial<ExecutionQuote>) => {
      const quote = { ...QUOTE, ...change };
      expect(
        refusedField(() =>
          verifyFeeQuoteForSigning(quote, APPROVED, honestMessage(quote)),
        ),
      ).toBe(field);
    },
  );

  it("refuses a withdraw message that pays another amount, another recipient or another execution", () => {
    const honest = honestMessage();
    expect(
      refusedField(() =>
        verifyFeeQuoteForSigning(QUOTE, APPROVED, {
          ...honest,
          value: honest.value + 1n,
        }),
      ),
    ).toBe("withdraw value");
    expect(
      refusedField(() =>
        verifyFeeQuoteForSigning(QUOTE, APPROVED, {
          ...honest,
          recipient: EXIT,
        }),
      ),
    ).toBe("withdraw recipient");
    // A coordinator swaps the exit (and so the execution id) under the same message.
    const otherExit = { ...QUOTE, exitAddress: `0x${"ee".repeat(20)}` };
    expect(
      refusedField(() => verifyFeeQuoteForSigning(otherExit, APPROVED, honest)),
    ).toBe("withdraw intent");
    expect(
      refusedField(() =>
        verifyFeeQuoteForSigning(QUOTE, APPROVED, {
          ...honest,
          intentHash: new Fr(1n),
        }),
      ),
    ).toBe("withdraw intent");
  });
});
