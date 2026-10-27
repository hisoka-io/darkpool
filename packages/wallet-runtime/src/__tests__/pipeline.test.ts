import { describe, expect, it } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import { WalletRuntimeError } from "../errors.js";
import { noteKey } from "../store/noteStore.js";
import {
  addressToFr,
  derivePublicIncomingKey,
  publicKey,
  publicMemoId,
} from "@hisoka/wallets";
import { AbiCoder, getBytes, hexlify } from "ethers";
import { howlPaymentIntent } from "@hisoka/adaptors";
import { DARK_POOL_INTERFACE } from "../abi.js";
import { RpcLogSource } from "../chain/logs.js";
import {
  encodeNoxResume,
  NoxSubmitter,
  type NoxPaidExecutor,
} from "../submit/nox.js";
import { readPublicMemos } from "../history/publicMemos.js";
import { funded, runtimeEnv, type RuntimeEnv } from "./fixtures/env.js";
import { evenIncomingIndex } from "./fixtures/mint.js";
import { COMPLIANCE_PK } from "./fixtures/pool.js";

const RECIPIENT = "0x00000000000000000000000000000000000000c0";

async function failure(p: Promise<unknown>): Promise<WalletRuntimeError> {
  const e = await p.then(
    () => null,
    (err: unknown) => err,
  );
  expect(e).toBeInstanceOf(WalletRuntimeError);
  return e as WalletRuntimeError;
}

/** Records the order the pipeline reaches each port. */
function recordOrder(env: RuntimeEnv): string[] {
  const order: string[] = [];
  const notes = env.notes as unknown as {
    acquire: (...a: unknown[]) => Promise<void>;
  };
  const acquire = notes.acquire.bind(env.notes);
  notes.acquire = async (...a: unknown[]) => {
    order.push("select");
    return acquire(...a);
  };
  const index = env.index as unknown as {
    witness: (i: number, n: number) => Promise<unknown>;
  };
  const witness = index.witness.bind(env.index);
  index.witness = async (i: number, n: number) => {
    order.push("witness");
    return witness(i, n);
  };
  const chain = env.chain as unknown as {
    isKnownRoot: (...a: unknown[]) => Promise<boolean>;
  };
  const known = chain.isKnownRoot.bind(env.chain);
  chain.isKnownRoot = async (...a: unknown[]) => {
    order.push("root check");
    return known(...a);
  };
  const prover = env.prover;
  const prove = prover.prove.bind(prover);
  prover.prove = async (c, w) => {
    order.push("prove");
    return prove(c, w);
  };
  const verify = prover.verify.bind(prover);
  prover.verify = async (e) => {
    order.push("verify");
    return verify(e);
  };
  env.submitter.onSubmit = () => order.push("submit");
  return order;
}

describe("spend pipeline", () => {
  it("runs select, witness, root check, assemble, prove, verify, submit in that order and the change is found after", async () => {
    const env = await runtimeEnv();
    const [note] = await funded(env, [100n]);
    const order = recordOrder(env);
    const counterBefore = await env.counter.highWater("self");
    const result = await env.pipeline.withdraw(note!, 30n, RECIPIENT);

    const assembleAt = order.indexOf("prove");
    expect(order.slice(0, 3)).toEqual(["select", "witness", "root check"]);
    expect(order.slice(assembleAt)).toEqual(["prove", "verify", "submit"]);
    // Assembly reserved the change ephemeral between the root check and proving.
    expect(await env.counter.highWater("self")).toBeGreaterThan(counterBefore);
    expect(env.submitter.calls.map((c) => c.name)).toEqual(["withdraw"]);
    expect(
      env.notes.plans.find((p) => p.planId === result.planId)?.status,
    ).toBe("included");

    const after = await env.refresh();
    expect(
      after.find((n) => noteKey(n) === noteKey(note!))?.spent,
    ).not.toBeNull();
    const change = after.find((n) =>
      n.commitment.equals(result.commitments[0]!),
    );
    expect(change?.note.value).toBe(70n);
  });

  it("stops at ROOT_UNKNOWN before reserving an ephemeral or proving, and frees the note", async () => {
    const env = await runtimeEnv();
    const [note] = await funded(env, [100n]);
    const order = recordOrder(env);
    const chain = env.chain as unknown as {
      isKnownRoot: () => Promise<boolean>;
    };
    chain.isKnownRoot = async () => {
      order.push("root check");
      return false;
    };
    const counterBefore = await env.counter.highWater("self");
    expect(
      (await failure(env.pipeline.withdraw(note!, 30n, RECIPIENT))).code,
    ).toBe("ROOT_UNKNOWN");
    expect(order).toEqual(["select", "witness", "root check"]);
    expect(await env.counter.highWater("self")).toBe(counterBefore);
    const plan = env.notes.plans[env.notes.plans.length - 1];
    expect(plan).toMatchObject({ status: "failed", leased: [] });
  });

  it("takes both join witnesses at the one pinned tree size while the live tree grows", async () => {
    const env = await runtimeEnv();
    const [a, b] = await funded(env, [40n, 50n]);
    const sizes: number[] = [];
    const index = env.index as unknown as {
      witness: (i: number, n: number) => Promise<unknown>;
    };
    const witness = index.witness.bind(env.index);
    index.witness = async (i: number, n: number) => {
      sizes.push(n);
      // Between the two paths a new leaf lands and discovery syncs it.
      if (sizes.length === 1) {
        env.pool.chain.mine();
        await env.pool.insertRaw(
          env.pool.chain.head,
          new Fr(77n),
          new Fr(1n),
          Array(7).fill(new Fr(2n)),
        );
        await env.index.sync();
      }
      return witness(i, n);
    };
    const result = await env.pipeline.join(b!, a!);
    expect(sizes).toHaveLength(2);
    expect(sizes[0]).toBe(sizes[1]);
    const after = await env.refresh();
    expect(
      after.find((n) => n.commitment.equals(result.commitments[0]!))?.note
        .value,
    ).toBe(90n);
  });

  it.each([
    ["withdraw", [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 16]],
    ["transfer", [0, 1, 2, 3, 4, 5, 6, 7, 8, 14, 15, 16, 17, 23]],
    ["split", [0, 1, 2, 3, 4, 5, 6, 12, 13, 14, 15, 21]],
    ["join", [0, 1, 2, 3, 4, 5, 6, 7, 13]],
    ["deposit", [0, 1, 2, 3, 4, 5, 6, 12]],
  ] as const)(
    "%s: a proof with any bound public input changed is refused naming the position, and nothing is sent",
    async (circuit: string, positions: readonly number[]) => {
      const env = await runtimeEnv();
      const notes = await funded(env, [100n, 60n]);
      const recipient = await env.bob.getIncomingPub(
        BigInt(await evenIncomingIndex(env.bob, 0)),
      );
      const run = () => {
        const [n0, n1] = notes;
        switch (circuit) {
          case "withdraw":
            return env.pipeline.withdraw(n0!, 30n, RECIPIENT);
          case "transfer":
            return env.pipeline.transfer(n0!, 30n, recipient);
          case "split":
            return env.pipeline.split(n0!, 30n);
          case "join":
            return env.pipeline.join(n0!, n1!);
          default:
            return env.pipeline.deposit(RECIPIENT, 5n);
        }
      };
      for (const position of positions) {
        env.prover.corrupt = { index: position, value: new Fr(0xdeadn) };
        const err = await failure(run());
        expect(err.code).toBe("PUBLIC_INPUT_MISMATCH");
        expect(err.context.position).toBe(String(position));
      }
      env.prover.corrupt = null;
      env.prover.truncate = true;
      expect((await failure(run())).context.position).toBe("length");
      expect(env.submitter.calls).toEqual([]);
      env.prover.truncate = false;
      await run();
      expect(env.submitter.calls.length).toBeGreaterThan(0);
    },
  );

  it("public_claim: claims a posted memo at chain time, and refuses any changed bound public input", async () => {
    const env = await runtimeEnv();
    const asset = "0x00000000000000000000000000000000000a55e7";
    const viewKey = await env.alice.getViewKey();
    const owner = publicKey(await derivePublicIncomingKey(viewKey, 2n));
    const terms = {
      assetId: addressToFr(asset),
      value: 40n,
      timelock: 0n,
      salt: new Fr(9n),
    };
    const memoId = await publicMemoId(terms, owner);
    env.pool.chain.emit(12, "NewPublicMemo", [
      memoId.toString(),
      asset,
      40n,
      0n,
      9n,
    ]);
    const read = await readPublicMemos(
      {
        config: env.pool.config,
        chain: env.chain,
        logs: RpcLogSource.over(env.pool.chain.rpc, env.pool.config),
      },
      viewKey,
    );
    const memo = read.memos[0]!;
    expect(memo.claimable).toBe(true);
    for (const position of [0, 1, 2, 3, 4, 5, 6, 12]) {
      env.prover.corrupt = { index: position, value: new Fr(0xdeadn) };
      const err = await failure(env.pipeline.claimPublic(memo));
      expect(err.code).toBe("PUBLIC_INPUT_MISMATCH");
      expect(err.context.position).toBe(String(position));
    }
    env.prover.corrupt = null;
    expect(env.submitter.calls).toEqual([]);
    const result = await env.pipeline.claimPublic(memo);
    const after = await env.refresh();
    expect(
      after.find((n) => n.commitment.equals(result.commitments[0]!))?.note
        .value,
    ).toBe(40n);
    expect(
      (await failure(env.pipeline.claimPublic({ ...memo, claimable: false })))
        .code,
    ).toBe("INPUT_SPENT");
  });

  it("refuses an unverified proof and wraps a prover failure, sending nothing either way", async () => {
    const env = await runtimeEnv();
    const [note] = await funded(env, [100n]);
    env.prover.verdict = false;
    const unverified = await failure(
      env.pipeline.withdraw(note!, 30n, RECIPIENT),
    );
    expect(unverified.code).toBe("PROOF_UNVERIFIED");
    expect(unverified.context.circuit).toBe("withdraw");
    env.prover.verdict = true;
    env.prover.failProve = new Error("wasm out of memory");
    const failed = await failure(env.pipeline.withdraw(note!, 30n, RECIPIENT));
    expect(failed.code).toBe("PROOF_FAILED");
    expect(failed.message).toContain("wasm out of memory");
    expect(env.submitter.calls).toEqual([]);
    expect(
      env.notes.plans.every(
        (p) => p.status === "failed" && p.leased.length === 0,
      ),
    ).toBe(true);
  });

  it("refuses to submit when the input was spent while the proof was built", async () => {
    const env = await runtimeEnv();
    const [note] = await funded(env, [100n]);
    env.prover.onProve = async () => {
      env.pool.chain.mine();
      env.pool.spend(env.pool.chain.head, note!.nullifier);
    };
    const err = await failure(env.pipeline.withdraw(note!, 30n, RECIPIENT));
    expect(err.code).toBe("INPUT_SPENT");
    expect(env.submitter.calls).toEqual([]);
  });

  it("maps a reverted simulation to SIMULATION_REVERTED and an unknown outcome to SUBMIT_UNKNOWN that keeps the lease", async () => {
    const env = await runtimeEnv();
    const [note] = await funded(env, [100n]);
    env.submitter.next = {
      status: "not-sent",
      stage: "simulation",
      detail: "eth_call reverted: ComplianceKeyStale",
      errorName: "ComplianceKeyStale",
    };
    const sim = await failure(env.pipeline.withdraw(note!, 30n, RECIPIENT));
    expect(sim.code).toBe("SIMULATION_REVERTED");
    expect(sim.context.errorName).toBe("ComplianceKeyStale");

    env.submitter.next = {
      status: "unknown",
      detail: "relayer timed out",
      resumeToken: JSON.stringify({
        executionId: `0x${"12".repeat(32)}`,
        validUntilUnix: "9999999999",
      }),
    };
    const unknown = await failure(env.pipeline.withdraw(note!, 30n, RECIPIENT));
    expect(unknown.code).toBe("SUBMIT_UNKNOWN");
    expect(unknown.message).toContain("later than chain time 9999999999");
    const plan = env.notes.plans[env.notes.plans.length - 1]!;
    expect(plan.status).toBe("submitted");
    expect(plan.leased).toEqual([noteKey(note!)]);
    expect(plan.resume).toEqual({
      executionId: `0x${"12".repeat(32)}`,
      validUntilUnix: 9999999999n,
    });
    expect(
      (await failure(env.pipeline.withdraw(note!, 30n, RECIPIENT))).code,
    ).toBe("INPUT_SPENT");
  });

  it("does not take the submitter's word for inclusion: a block without the action's logs is SUBMIT_UNKNOWN", async () => {
    const env = await runtimeEnv();
    const [note] = await funded(env, [100n]);
    env.submitter.next = {
      status: "included",
      txHash: `0x${"ab".repeat(32)}`,
      blockNumber: env.pool.chain.head,
    };
    const err = await failure(env.pipeline.withdraw(note!, 30n, RECIPIENT));
    expect(err.code).toBe("SUBMIT_UNKNOWN");
    expect(err.message).toContain(`nullifier ${note!.nullifier.toString()}`);
    const plan = env.notes.plans[env.notes.plans.length - 1]!;
    expect(plan).toMatchObject({
      status: "submitted",
      leased: [noteKey(note!)],
    });
  });

  it("refuses inclusion from a block that spends the nullifier but lacks the new leaf", async () => {
    const env = await runtimeEnv();
    const [note] = await funded(env, [100n]);
    env.submitter.onSubmit = () => {
      env.pool.chain.mine();
      env.pool.spend(env.pool.chain.head, note!.nullifier);
    };
    env.submitter.next = {
      status: "included",
      txHash: `0x${"ac".repeat(32)}`,
      blockNumber: env.pool.chain.head + 1,
    };
    const err = await failure(env.pipeline.withdraw(note!, 30n, RECIPIENT));
    expect(err.code).toBe("SUBMIT_UNKNOWN");
    expect(err.message).toContain("lack leaf");
    expect(err.message).not.toContain("nullifier");
    expect(env.notes.plans[env.notes.plans.length - 1]?.status).toBe(
      "submitted",
    );
  });

  it("releases an unknown action's notes once a confirmed block passes validUntilUnix, and counts a late landing once", async () => {
    const env = await runtimeEnv();
    const [note] = await funded(env, [100n]);
    let sent = "";
    const submit = env.submitter.submit.bind(env.submitter);
    env.submitter.submit = async (call, context) => {
      sent = call.data;
      return submit(call, context);
    };
    const validUntil = (await env.chain.latest()).timestamp + 60n;
    env.submitter.next = {
      status: "unknown",
      detail: "exit went silent",
      resumeToken: encodeNoxResume({
        executionId: `0x${"12".repeat(32)}`,
        validUntilUnix: validUntil,
      }),
    };
    expect(
      (await failure(env.pipeline.withdraw(note!, 30n, RECIPIENT))).code,
    ).toBe("SUBMIT_UNKNOWN");
    const unknownPlan = env.notes.plans[env.notes.plans.length - 1]!.planId;

    // Up to the deadline the lease holds, through a sync too.
    env.pool.chain.mine(5);
    await env.refresh();
    expect(
      (await failure(env.pipeline.withdraw(note!, 30n, RECIPIENT))).code,
    ).toBe("INPUT_SPENT");

    // A confirmed block past validUntilUnix with the nullifier unspent: the sync releases the note.
    env.pool.chain.mine(1);
    await env.refresh();
    const view = {
      confirmedHead: env.pool.chain.head,
      sweptThrough: env.notes.sweptThrough,
      now: (await env.chain.latest()).timestamp,
    };
    expect(env.notes.plans.find((p) => p.planId === unknownPlan)).toMatchObject(
      { status: "failed", leased: [] },
    );
    expect(env.notes.spendable(view).map((n) => n.leafIndex)).toEqual([1]);

    // The late transaction lands while a new action on the same note proves: refused before sending.
    const withdrawsBefore = env.submitter.calls.filter(
      (c) => c.name === "withdraw",
    ).length;
    env.prover.onProve = async () => {
      env.prover.onProve = null;
      env.pool.chain.mine();
      await env.submitter.play(sent, env.pool.chain.head);
    };
    const late = await failure(env.pipeline.withdraw(note!, 30n, RECIPIENT));
    expect(late.code).toBe("INPUT_SPENT");
    expect(
      env.submitter.calls.filter((c) => c.name === "withdraw").length,
    ).toBe(withdrawsBefore);

    // After a sync the funds are the change alone: the input is spent, never counted beside its change.
    await env.refresh();
    const after = {
      confirmedHead: env.pool.chain.head,
      sweptThrough: env.notes.sweptThrough,
      now: (await env.chain.latest()).timestamp,
    };
    const spendable = env.notes.spendable(after);
    expect(spendable.map((n) => n.note.value)).toEqual([70n]);
    expect(env.notes.state(env.notes.find(noteKey(note!))!, after)).toBe(
      "spent",
    );
  });

  it("stops before proving when discovery rewinds past an input during preflight", async () => {
    const env = await runtimeEnv(20);
    const [note] = await funded(env, [100n]);
    let proved = false;
    env.prover.onProve = async () => {
      proved = true;
    };
    const chain = env.chain as unknown as {
      isKnownRoot: (...a: unknown[]) => Promise<boolean>;
    };
    const known = chain.isKnownRoot.bind(env.chain);
    chain.isKnownRoot = async (...a: unknown[]) => {
      const answer = await known(...a);
      chain.isKnownRoot = known;
      env.pool.reorgFrom(10);
      return answer;
    };
    const err = await failure(env.pipeline.withdraw(note!, 30n, RECIPIENT));
    expect(err.code).toBe("HEAD_REORGED");
    expect(err.context).toMatchObject({ rewoundTo: "1", leafIndex: "1" });
    expect(proved).toBe(false);
    expect(env.notes.plans[0]).toMatchObject({ status: "failed", leased: [] });
  });

  it("refuses to mint on a read-only install before reserving any ephemeral index", async () => {
    const env = await runtimeEnv();
    const [note] = await funded(env, [100n]);
    env.pss.state = {
      mode: "readonly",
      heldBy: { installId: "0x01", platform: "mobile/ios" },
    };
    const before = await env.counter.highWater("self");
    const err = await failure(env.pipeline.withdraw(note!, 30n, RECIPIENT));
    expect(err.code).toBe("NOT_WRITER");
    expect(err.context.heldByPlatform).toBe("mobile/ios");
    expect(await env.counter.highWater("self")).toBe(before);
    expect(env.notes.plans).toEqual([]);
  });

  it("deposits after an exact approval of the deposit amount", async () => {
    const env = await runtimeEnv();
    const asset = "0x00000000000000000000000000000000000a55e7";
    const result = await env.pipeline.deposit(asset, 25n);
    expect(env.submitter.calls).toEqual([
      { name: "approve", to: asset },
      { name: "deposit", to: env.pool.config.deployment.dark_pool },
    ]);
    expect(env.submitter.approvals).toEqual([25n]);
    const after = await env.refresh();
    expect(
      after.find((n) => n.commitment.equals(result.commitments[0]!))?.note
        .value,
    ).toBe(25n);
  });

  it("refuses to assemble when the compliance key rotated after the history was read", async () => {
    const env = await runtimeEnv();
    const [note] = await funded(env, [100n]);
    const deps = (
      env.pipeline as unknown as { deps: { history: () => Promise<unknown> } }
    ).deps;
    const stale = await deps.history();
    env.pool.chain.mine();
    env.pool.rotate(env.pool.chain.head, 2);
    deps.history = async () => stale;
    const err = await failure(env.pipeline.withdraw(note!, 30n, RECIPIENT));
    expect(err.code).toBe("COMPLIANCE_HISTORY_INVALID");
    expect(COMPLIANCE_PK).toHaveLength(3);
  });
});

const ADAPTER = "0x00000000000000000000000000000000000000ad";
const EXECUTION_ID = `0x${"5e".repeat(32)}`;

/**
 * Stands in for nox-client's `executePaid` against the simulated pool: checks the action, asks the payment
 * source for the fee at the quote's amount and execution id, then lands the fee withdraw and the action in
 * one block, as `NoxEntryPoint` does.
 */
function noxOver(env: RuntimeEnv, feeAmount: bigint) {
  const seen: { paymentData: string | null } = { paymentData: null };
  const executor: NoxPaidExecutor = {
    async execute(options) {
      options.payment.checkAction?.({ data: options.action.data });
      const paymentData = await options.payment.buildPaymentData({
        executionId: getBytes(EXECUTION_ID),
        amount: feeAmount,
        feeAsset: options.payment.feeAsset,
      });
      seen.paymentData = hexlify(paymentData);
      const [proof, inputs] = AbiCoder.defaultAbiCoder().decode(
        ["bytes", "bytes32[]"],
        paymentData,
      ) as unknown as [string, string[]];
      env.pool.chain.mine();
      const block = env.pool.chain.head;
      await env.submitter.play(
        DARK_POOL_INTERFACE.encodeFunctionData("withdraw", [proof, inputs]),
        block,
      );
      await env.submitter.play(hexlify(options.action.data), block);
      return {
        status: "settled",
        executionId: EXECUTION_ID,
        transactionHash: `0x${"cc".repeat(32)}`,
        blockNumber: BigInt(block),
      };
    },
  };
  const submitter = new NoxSubmitter({
    executor,
    chainId: 31337n,
    entryPoint: "0x00000000000000000000000000000000000000e0",
    paymentAdapter: ADAPTER,
    maxTotalFee: 10n,
    intentSalt: new Uint8Array(32),
    preflight: {
      // The withdraw adapter instance: MULTISIG() answers false.
      call: async () => `0x${"00".repeat(32)}`,
      estimateGas: async () => 0n,
    },
  });
  (
    env.pipeline as unknown as { deps: { submitter: NoxSubmitter } }
  ).deps.submitter = submitter;
  return seen;
}

describe("spend pipeline over Nox", () => {
  it("leases the fee note with the input, proves the fee withdraw at the quote, and confirms both from the block", async () => {
    const env = await runtimeEnv();
    const [input, fee] = await funded(env, [100n, 10n]);
    const seen = noxOver(env, 3n);
    const counterBefore = await env.counter.highWater("self");
    const result = await env.pipeline.withdraw(
      input!,
      30n,
      RECIPIENT,
      undefined,
      {
        fee: fee!,
      },
    );
    const plan = env.notes.plans.find((p) => p.planId === result.planId)!;
    expect(plan.status).toBe("included");
    expect(plan.leased).toEqual([noteKey(input!), noteKey(fee!)]);
    // One reservation for the action's change, one for the fee change.
    expect(await env.counter.highWater("self")).toBeGreaterThanOrEqual(
      counterBefore + 2,
    );
    const [, feeInputs] = AbiCoder.defaultAbiCoder().decode(
      ["bytes", "bytes32[]"],
      seen.paymentData!,
    ) as unknown as [string, string[]];
    expect(BigInt(feeInputs[0]!)).toBe(3n);
    expect(BigInt(feeInputs[1]!)).toBe(BigInt(ADAPTER));
    expect(BigInt(feeInputs[2]!)).toBe(
      howlPaymentIntent(EXECUTION_ID).toBigInt(),
    );
    expect(BigInt(feeInputs[5]!)).toBe(fee!.nullifier.toBigInt());

    const after = await env.refresh();
    const values = after
      .filter((n) => n.spent === null)
      .map((n) => n.note.value)
      .sort((a, b) => Number(a - b));
    expect(values).toEqual([7n, 70n]);
    expect(
      after.find((n) => noteKey(n) === noteKey(fee!))?.spent,
    ).not.toBeNull();
  });

  it("refuses a fee withdraw proof whose public inputs are not the quote's, before anything lands", async () => {
    const env = await runtimeEnv();
    const [input, fee] = await funded(env, [100n, 10n]);
    noxOver(env, 3n);
    let proofs = 0;
    env.prover.onProve = async () => {
      proofs += 1;
      env.prover.corrupt =
        proofs === 2 ? { index: 2, value: new Fr(0xdeadn) } : null;
    };
    const head = env.pool.chain.head;
    const err = await failure(
      env.pipeline.withdraw(input!, 30n, RECIPIENT, undefined, { fee: fee! }),
    );
    expect(err.code).toBe("PUBLIC_INPUT_MISMATCH");
    expect(err.context.position).toBe("2");
    expect(proofs).toBe(2);
    expect(env.pool.chain.head).toBe(head);
    expect(env.notes.plans[env.notes.plans.length - 1]).toMatchObject({
      status: "failed",
      leased: [],
    });
  });

  it("refuses a fee note that is also an input, and a Nox action with no fee note, sending nothing", async () => {
    const env = await runtimeEnv();
    const [input] = await funded(env, [100n]);
    noxOver(env, 3n);
    const same = await failure(
      env.pipeline.withdraw(input!, 30n, RECIPIENT, undefined, { fee: input! }),
    );
    expect(same.code).toBe("LEASE_HELD");
    expect(env.notes.plans).toEqual([]);
    const unpaid = await failure(env.pipeline.withdraw(input!, 30n, RECIPIENT));
    expect(unpaid.code).toBe("SUBMIT_FAILED");
    expect(unpaid.context.stage).toBe("payment");
    expect(env.notes.plans[env.notes.plans.length - 1]).toMatchObject({
      status: "failed",
      leased: [],
    });
  });
});
