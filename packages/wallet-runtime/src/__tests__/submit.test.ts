import { describe, expect, it } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import { hexlify } from "ethers";
import { DARK_POOL_INTERFACE } from "../abi.js";
import { DirectSubmitter } from "../submit/direct.js";
import {
  decodeNoxResume,
  encodeNoxResume,
  NoxSubmitter,
  type NoxPaidOptions,
  type NoxPaidResult,
} from "../submit/nox.js";
import type { FeeWithdrawProver, SubmissionContext } from "../submit/ports.js";
import { scriptedRpc } from "./fixtures/rpc.js";

const POOL = "0x6dab000000000000000000000000000000000001";
const CALL = { to: POOL, data: "0x12345678" };
const CONTEXT: SubmissionContext = {
  planId: "p",
  nullifiers: [],
  commitments: [],
};
const TX = `0x${"ab".repeat(32)}`;

function direct(
  handlers: Parameters<typeof scriptedRpc>[0],
  send = async () => TX,
) {
  const { rpc, calls } = scriptedRpc(handlers);
  return {
    submitter: new DirectSubmitter({
      rpc,
      from: "0x00000000000000000000000000000000000000f0",
      sendTransaction: send,
      pollIntervalMs: 1,
      receiptTimeoutMs: 50,
    }),
    calls,
  };
}

describe("direct submitter", () => {
  it("simulates first and never sends a call the pool would reject, naming the pool's error", async () => {
    let sent = 0;
    const revert = DARK_POOL_INTERFACE.encodeErrorResult("ComplianceKeyStale", [
      2n,
      5n,
      6n,
    ]);
    const { submitter, calls } = direct(
      {
        eth_call: () => {
          throw Object.assign(new Error("execution reverted"), {
            code: 3,
            data: revert,
          });
        },
      },
      async () => {
        sent += 1;
        return TX;
      },
    );
    const out = await submitter.submit(CALL, CONTEXT);
    expect(out).toMatchObject({
      status: "not-sent",
      stage: "simulation",
      errorName: "ComplianceKeyStale",
    });
    expect(sent).toBe(0);
    expect(calls[0]!.params[1]).toBe("latest");
  });

  it("finds the revert payload nested where client libraries put it", async () => {
    const revert = DARK_POOL_INTERFACE.encodeErrorResult(
      "NullifierAlreadySpent",
      [],
    );
    const { submitter } = direct({
      eth_call: () => {
        throw { error: { code: 3, data: { data: revert } } };
      },
    });
    expect(await submitter.submit(CALL, CONTEXT)).toMatchObject({
      errorName: "NullifierAlreadySpent",
    });
  });

  it("reports included and reverted receipts with their block, and unknown after the receipt timeout", async () => {
    const receipts = [null, { status: "0x1", blockNumber: "0x2a" }];
    const ok = direct({
      eth_call: () => "0x",
      eth_getTransactionReceipt: () => receipts.shift() ?? null,
    });
    expect(await ok.submitter.submit(CALL, CONTEXT)).toEqual({
      status: "included",
      txHash: TX,
      blockNumber: 42,
    });
    const reverted = direct({
      eth_call: () => "0x",
      eth_getTransactionReceipt: () => ({ status: "0x0", blockNumber: "0x2b" }),
    });
    expect(await reverted.submitter.submit(CALL, CONTEXT)).toMatchObject({
      status: "reverted",
      blockNumber: 43,
    });
    const slow = direct({
      eth_call: () => "0x",
      eth_getTransactionReceipt: () => null,
    });
    expect(await slow.submitter.submit(CALL, CONTEXT)).toMatchObject({
      status: "unknown",
      resumeToken: TX,
    });
    const refused = direct({ eth_call: () => "0x" }, async () => {
      throw Object.assign(new Error("user rejected"), { code: 4001 });
    });
    expect(await refused.submitter.submit(CALL, CONTEXT)).toMatchObject({
      status: "not-sent",
      stage: "send",
      detail: "user rejected",
    });
  });

  it("reports unknown, never not-sent, when the signer fails after the transaction may have left", async () => {
    const lost = direct({ eth_call: () => "0x" }, async () => {
      throw new Error("request timed out after eth_sendRawTransaction");
    });
    expect(await lost.submitter.submit(CALL, CONTEXT)).toMatchObject({
      status: "unknown",
      resumeToken: null,
    });
    const wrapped = direct({ eth_call: () => "0x" }, async () => {
      throw Object.assign(new Error("ethers: user rejected action"), {
        code: "ACTION_REJECTED",
      });
    });
    expect(await wrapped.submitter.submit(CALL, CONTEXT)).toMatchObject({
      status: "not-sent",
      stage: "send",
    });
  });
});

/** An executor shaped like nox-client 0.8.0's `executePaid` binding: options in, result union out. */
function executor(results: NoxPaidResult[]) {
  const seen: NoxPaidOptions[] = [];
  return {
    seen,
    executor: {
      async execute(options: NoxPaidOptions): Promise<NoxPaidResult> {
        seen.push(options);
        const next = results.shift();
        if (next === undefined) throw new Error("no scripted result");
        return next;
      },
    },
  };
}

const ADAPTER = "0x00000000000000000000000000000000000ad0a7";
const FEE_ASSET = "0x00000000000000000000000000000000000a55e7";
const FEE: FeeWithdrawProver = {
  nullifier: new Fr(0x0505n),
  assetId: new Fr(BigInt(FEE_ASSET)),
  value: 500n,
  prove: async () => {
    throw new Error(
      "the fee is proved only when the executor builds payment data",
    );
  },
};
const PAID: SubmissionContext = { ...CONTEXT, fee: FEE };

function nox(results: NoxPaidResult[]) {
  const ex = executor(results);
  return {
    ...ex,
    submitter: new NoxSubmitter({
      executor: ex.executor,
      chainId: 31337n,
      entryPoint: "0x00000000000000000000000000000000000e0001",
      paymentAdapter: ADAPTER,
      maxTotalFee: 1_000n,
      intentSalt: new Uint8Array(32).fill(9),
      preflight: {
        // The withdraw adapter instance: MULTISIG() answers false.
        call: async () => `0x${"00".repeat(32)}`,
        estimateGas: async () => 21_000n,
      },
    }),
  };
}

describe("Nox submitter", () => {
  it("passes the pool call as the paid action with the fee note's payment source", async () => {
    const { submitter, seen } = nox([
      {
        status: "settled",
        executionId: `0x${"01".repeat(32)}`,
        transactionHash: TX,
        blockNumber: 77n,
      },
    ]);
    expect(await submitter.submit(CALL, PAID)).toEqual({
      status: "included",
      txHash: TX,
      blockNumber: 77,
    });
    const options = seen[0]!;
    expect(options.action.target).toBe(POOL);
    expect([...options.action.data]).toEqual([0x12, 0x34, 0x56, 0x78]);
    expect(options.payment.adapter.toLowerCase()).toBe(ADAPTER);
    expect(options.payment.feeAsset.toLowerCase()).toBe(FEE_ASSET);
    expect(BigInt(hexlify(options.payment.paymentId))).toBe(0x0505n);
    expect(options.maxTotalFee).toBe(1_000n);
    expect(options.pending).toBeUndefined();
  });

  it("maps every executePaid outcome, and resumes an unknown one instead of paying twice", async () => {
    const pending = {
      executionId: `0x${"02".repeat(32)}`,
      validUntilUnix: 123n,
    };
    const { submitter, seen } = nox([
      { status: "unknown", ...pending, detail: "exit went silent" },
      {
        status: "paid-action-failed",
        executionId: pending.executionId,
        transactionHash: TX,
        blockNumber: 9n,
        returnPrefixHash: `0x${"03".repeat(32)}`,
      },
      {
        status: "not-paid",
        stage: "quote",
        code: "NO_EXIT",
        detail: "no exit quoted",
      },
      { status: "dry-run", executionId: pending.executionId },
      {
        status: "unknown",
        executionId: null,
        validUntilUnix: null,
        detail: "consumed",
      },
    ]);
    const unknown = await submitter.submit(CALL, PAID);
    expect(unknown).toEqual({
      status: "unknown",
      detail: "exit went silent",
      resumeToken: encodeNoxResume(pending),
    });
    expect(
      unknown.status === "unknown" &&
        submitter.resume(PAID.planId, unknown.resumeToken ?? ""),
    ).toBe(true);
    expect(await submitter.submit(CALL, PAID)).toMatchObject({
      status: "reverted",
      blockNumber: 9,
    });
    expect(seen[1]!.pending).toEqual(pending);
    expect(await submitter.submit(CALL, PAID)).toEqual({
      status: "not-sent",
      stage: "quote",
      detail: "NO_EXIT: no exit quoted",
    });
    expect(seen[2]!.pending).toBeUndefined();
    expect(await submitter.submit(CALL, PAID)).toMatchObject({
      status: "not-sent",
      stage: "dry-run",
    });
    expect(await submitter.submit(CALL, PAID)).toMatchObject({
      status: "unknown",
      resumeToken: null,
    });
  });

  it("resumes an unknown execution only for the plan that sent it", async () => {
    const pending = {
      executionId: `0x${"06".repeat(32)}`,
      validUntilUnix: 456n,
    };
    const other: SubmissionContext = { ...PAID, planId: "other" };
    const { submitter, seen } = nox([
      { status: "unknown", ...pending, detail: "exit went silent" },
      {
        status: "not-paid",
        stage: "quote",
        code: "NO_EXIT",
        detail: "no exit quoted",
      },
      {
        status: "settled",
        executionId: pending.executionId,
        transactionHash: TX,
        blockNumber: 12n,
      },
      {
        status: "not-paid",
        stage: "quote",
        code: "NO_EXIT",
        detail: "no exit quoted",
      },
    ]);
    const unknown = await submitter.submit(CALL, PAID);
    expect(
      unknown.status === "unknown" &&
        submitter.resume(PAID.planId, unknown.resumeToken ?? ""),
    ).toBe(true);
    expect(submitter.resume(other.planId, "not a token")).toBe(false);

    await submitter.submit(CALL, other);
    expect(seen[1]!.pending).toBeUndefined();
    expect(await submitter.submit(CALL, PAID)).toMatchObject({
      status: "included",
    });
    expect(seen[2]!.pending).toEqual(pending);
    await submitter.submit(CALL, PAID);
    expect(seen[3]!.pending).toBeUndefined();
  });

  it("sends nothing for an action that leased no fee note, or whose fee note cannot pay", async () => {
    const { submitter, seen } = nox([]);
    expect(await submitter.submit(CALL, CONTEXT)).toMatchObject({
      status: "not-sent",
      stage: "payment",
    });
    expect(
      await submitter.submit(CALL, { ...CONTEXT, fee: { ...FEE, value: 0n } }),
    ).toMatchObject({ status: "not-sent", stage: "payment" });
    expect(seen).toEqual([]);
  });

  it("reads the adapter kind through the preflight port and refuses the multisig instance before proving", async () => {
    const reads: { to: string; data: string; block: bigint | "latest" }[] = [];
    let proved = false;
    const submitter = new NoxSubmitter({
      executor: {
        async execute(options) {
          await options.payment.buildPaymentData({
            executionId: new Uint8Array(32).fill(1),
            amount: 5n,
            feeAsset: options.payment.feeAsset,
          });
          throw new Error("the payment data must be refused");
        },
      },
      chainId: 31337n,
      entryPoint: "0x00000000000000000000000000000000000e0001",
      paymentAdapter: ADAPTER,
      maxTotalFee: 1_000n,
      intentSalt: new Uint8Array(32).fill(9),
      preflight: {
        call: async (tx, block) => {
          reads.push({ to: tx.to, data: tx.data, block });
          return `0x${"00".repeat(31)}01`;
        },
        estimateGas: async () => 21_000n,
      },
    });
    const fee: FeeWithdrawProver = {
      ...FEE,
      prove: async () => {
        proved = true;
        throw new Error("must not prove");
      },
    };
    await expect(submitter.submit(CALL, { ...CONTEXT, fee })).rejects.toThrow(
      /MULTISIG\(\) is true/,
    );
    expect(proved).toBe(false);
    expect(reads.map((r) => ({ ...r, to: r.to.toLowerCase() }))).toEqual([
      { to: ADAPTER, data: "0x2530b145", block: "latest" },
    ]);
  });

  it("round-trips a resume token and refuses a malformed one", () => {
    const pending = { executionId: `0x${"04".repeat(32)}`, validUntilUnix: 5n };
    expect(decodeNoxResume(encodeNoxResume(pending))).toEqual(pending);
    expect(decodeNoxResume("{}")).toBeNull();
    expect(decodeNoxResume("not json")).toBeNull();
    expect(
      decodeNoxResume(
        JSON.stringify({ executionId: "0x12", validUntilUnix: "5" }),
      ),
    ).toBeNull();
  });
});
