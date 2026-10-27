import { Fr } from "@aztec/foundation/fields";
import type { Point } from "@zk-kit/baby-jubjub";
import type { ProofEnvelope } from "@hisoka/howl-protocol";
import type {
  StandardCircuitId,
  StandardWitnessByCircuit,
} from "@hisoka/howl-protocol/proving";
import {
  addressToFr,
  buildPublicClaim,
  computeNullifier,
  deriveCek,
  publicKey,
  pubkeyOwner,
  reconcileCounterWithChain,
  SelfMintPreflight,
  type CompleteComplianceHistory,
  type EphemeralCounterStore,
  type IDarkAccount,
  type MintedNote,
  type SelfMintAllocator,
  type SelfMintAuthorization,
  type SelfMintCandidate,
} from "@hisoka/wallets";
import {
  assembleDeposit,
  assembleJoin,
  assembleSplit,
  assembleTransfer,
  assembleWithdraw,
  toStandardWitnessDto,
  type AssemblyContext,
  type SpendableNote,
} from "@hisoka/wallets/tx";
import { DARK_POOL_INTERFACE, ERC20_INTERFACE, EVENT_TOPICS } from "../abi.js";
import type { ChainReader, TreeState } from "../chain/chainReader.js";
import {
  MAX_STABLE_READ_ATTEMPTS,
  readPinned,
  type LogSource,
} from "../chain/logs.js";
import { deploymentBlock, type ChainConfig } from "../config.js";
import { describeCause, WalletRuntimeError } from "../errors.js";
import { discoverySourceOver } from "../discovery/feedSource.js";
import type { DiscoveryPort, WitnessPort } from "../discovery/ports.js";
import {
  DISCOVERY_LOOKAHEAD,
  MAX_DISCOVERY_INDEX,
  walletCandidates,
} from "../discovery/sync.js";
import { requireWriter, type PssStatePort } from "../pss/noteMirror.js";
import {
  noteKey,
  submittedDeadline,
  type NoteState,
  type NoteStore,
  type NoteView,
  type StoredNote,
} from "../store/noteStore.js";
import type {
  FeeWithdrawProver,
  SubmissionOutcome,
  SubmitterPort,
} from "../submit/ports.js";
import { encodeNoxResume, decodeNoxResume } from "../submit/nox.js";
import { newPlanId, sampleMemoEphemeral, type EntropyPort } from "./entropy.js";
import type { RuntimePublicMemo } from "../history/publicMemos.js";
import { pinnedWitnessSource } from "./pinnedWitness.js";
import {
  checkPublicInputs,
  type BindingInputs,
  type MintedOutput,
} from "./publicInputs.js";

/**
 * Proving, always local: the witness carries the spend scalar. The runtime treats the proof as opaque bytes
 * plus public inputs and assumes no proving system.
 */
export interface ProverPort {
  prove<C extends StandardCircuitId>(
    circuit: C,
    witness: StandardWitnessByCircuit[C],
  ): Promise<ProofEnvelope<C>>;
  /** Verifies with the same backend; true only for a valid proof. */
  verify<C extends StandardCircuitId>(
    envelope: ProofEnvelope<C>,
  ): Promise<boolean>;
}

export interface SpendPipelineDeps {
  readonly config: ChainConfig;
  readonly chain: Pick<
    ChainReader,
    | "latest"
    | "blockByNumber"
    | "confirmedHead"
    | "treeState"
    | "isKnownRoot"
    | "complianceKey"
  >;
  readonly logs: LogSource;
  readonly discovery: DiscoveryPort & WitnessPort;
  readonly notes: NoteStore;
  readonly pss: Pick<PssStatePort, "state">;
  /**
   * Hands out derived self ephemerals reserved through the durable counter. Any wallets
   * `SelfMintAllocator` fits; preflight checks every candidate's provenance before use.
   */
  readonly allocator: SelfMintAllocator<SelfMintCandidate>;
  /** The durable counter `allocator` reserves from; ratcheted past every index the chain shows used. */
  readonly counters: EphemeralCounterStore;
  readonly account: Pick<
    IDarkAccount,
    | "getSelfSpendKey"
    | "getSelfSpendPub"
    | "getSelfEphemeral"
    | "getIncomingKey"
    | "getViewKey"
  >;
  readonly prover: ProverPort;
  readonly submitter: SubmitterPort;
  readonly entropy: EntropyPort;
  /** The complete compliance history (the runtime's producer). */
  readonly history: () => Promise<CompleteComplianceHistory>;
  /** Brings the whole-set nullifier sweep to `latest`. */
  readonly sweep: () => Promise<void>;
  /** How long an action may hold its notes, in chain seconds. */
  readonly leaseSeconds: bigint;
}

/** Per-action options. */
export interface ActionOptions {
  /**
   * A second spendable note that pays a relayer through the submitter (the Nox path). It is leased with the
   * action's inputs, witnessed at the same pin, never one of the inputs, and proved only when the submitter
   * asks with the quote's amount, recipient and intent.
   */
  readonly fee?: StoredNote;
}

export interface PlanResult {
  readonly planId: string;
  readonly txHash: string;
  readonly blockNumber: number;
  /** Leaves this action inserted, for discovery to find. */
  readonly commitments: readonly Fr[];
}

interface Built<C extends StandardCircuitId> {
  readonly witness: Parameters<typeof toStandardWitnessDto<C>>[1];
  readonly binding: BindingInputs & { readonly circuit: C };
  readonly commitments: readonly Fr[];
}

interface Landed {
  readonly txHash: string;
  readonly block: { readonly number: number; readonly hash: string };
}

type Assembler<C extends StandardCircuitId> = (
  ctx: AssemblyContext,
  inputs: readonly SpendableNote[],
  mints: readonly SelfMintAuthorization[],
  pin: TreeState,
  history: CompleteComplianceHistory,
) => Promise<Built<C>>;

/** The counter scope wallets' `SelfEphemeralAllocator` reserves self ephemerals in. */
const SELF_COUNTER_SCOPE = "self";

const ENTRYPOINT: Readonly<Record<StandardCircuitId, string>> = {
  deposit: "deposit",
  withdraw: "withdraw",
  transfer: "privateTransfer",
  split: "split",
  join: "join",
  public_claim: "publicClaim",
};

function asOutput(
  m: Pick<MintedNote, "commitment" | "ephPub" | "cek" | "note">,
): MintedOutput {
  return {
    commitment: m.commitment,
    ephPub: m.ephPub,
    cek: m.cek,
    note: m.note,
  };
}

function addressFr(address: string): Fr {
  if (!/^0x[0-9a-fA-F]{40}$/.test(address)) {
    throw new WalletRuntimeError(
      "CONFIG_INVALID",
      `${address} is not a 20-byte address`,
      { field: "address", value: address },
    );
  }
  return addressToFr(address);
}

/**
 * The spend pipeline, in its fixed order: select -> witness -> root check -> assemble -> prove -> verify ->
 * submit. Each step's failure stops the action with a typed error and releases its notes; no step is skipped
 * for an action that consumes a note, and deposit and public claim run the steps that apply to them.
 */
export class SpendPipeline {
  #queue: Promise<void> = Promise.resolve();
  #counterReconciled = false;

  constructor(private readonly deps: SpendPipelineDeps) {}

  /** One action at a time: two actions must never select the same note or race one counter. */
  #exclusive<T>(work: () => Promise<T>): Promise<T> {
    const run = this.#queue.then(work, work);
    this.#queue = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  withdraw(
    input: StoredNote,
    value: bigint,
    recipient: string,
    intentHash?: Fr,
    options: ActionOptions = {},
  ): Promise<PlanResult> {
    const recipientFr = addressFr(recipient);
    return this.#run(
      "withdraw",
      [input],
      1,
      async (ctx, [spend], mints, pin) => {
        const assembled = await assembleWithdraw(ctx, {
          input: this.#one(spend),
          value,
          recipient: recipientFr,
          selfSpendScalar: await this.deps.account.getSelfSpendKey(),
          changeMint: this.#mint(mints, 0),
          ...(intentHash === undefined ? {} : { intentHash }),
        });
        return {
          witness: assembled.inputs,
          binding: {
            circuit: "withdraw",
            compliancePk: ctx.compliancePk,
            value,
            recipient: recipientFr,
            intentHash: assembled.inputs.intentHash,
            nullifier: input.nullifier,
            root: pin.root,
            asset: input.note.assetId,
            change: asOutput(assembled.change),
          },
          commitments: [assembled.change.commitment],
        };
      },
      options,
    );
  }

  transfer(
    input: StoredNote,
    value: bigint,
    recipientInPub: Point<bigint>,
    options: ActionOptions = {},
  ): Promise<PlanResult> {
    return this.#run(
      "transfer",
      [input],
      1,
      async (ctx, [spend], mints, pin) => {
        const assembled = await assembleTransfer(ctx, {
          input: this.#one(spend),
          value,
          recipientInPub,
          selfSpendScalar: await this.deps.account.getSelfSpendKey(),
          memoEph: sampleMemoEphemeral(this.deps.entropy),
          changeMint: this.#mint(mints, 0),
        });
        return {
          witness: assembled.inputs,
          binding: {
            circuit: "transfer",
            compliancePk: ctx.compliancePk,
            nullifier: input.nullifier,
            root: pin.root,
            memo: asOutput(assembled.memo),
            recipientTag: new Fr(recipientInPub[0]),
            cekWrap: assembled.memo.cekWrap,
            change: asOutput(assembled.change),
          },
          commitments: [assembled.memo.commitment, assembled.change.commitment],
        };
      },
      options,
    );
  }

  split(
    input: StoredNote,
    value1: bigint,
    options: ActionOptions = {},
  ): Promise<PlanResult> {
    return this.#run(
      "split",
      [input],
      2,
      async (ctx, [spend], mints, pin) => {
        const assembled = await assembleSplit(ctx, {
          input: this.#one(spend),
          value1,
          selfSpendScalar: await this.deps.account.getSelfSpendKey(),
          selfMints: [this.#mint(mints, 0), this.#mint(mints, 1)],
        });
        return {
          witness: assembled.inputs,
          binding: {
            circuit: "split",
            compliancePk: ctx.compliancePk,
            nullifier: input.nullifier,
            root: pin.root,
            out1: asOutput(assembled.out1),
            out2: asOutput(assembled.out2),
          },
          commitments: [assembled.out1.commitment, assembled.out2.commitment],
        };
      },
      options,
    );
  }

  join(
    a: StoredNote,
    b: StoredNote,
    options: ActionOptions = {},
  ): Promise<PlanResult> {
    const [lo, hi] = a.leafIndex < b.leafIndex ? [a, b] : [b, a];
    return this.#run(
      "join",
      [lo, hi],
      1,
      async (ctx, spends, mints, pin) => {
        const [sa, sb] = spends;
        if (sa === undefined || sb === undefined) {
          throw new WalletRuntimeError(
            "WITNESS_MISMATCH",
            "join needs two inputs",
            {
              leafIndex: String(lo.leafIndex),
              leafCount: String(pin.leafCount),
            },
          );
        }
        const assembled = await assembleJoin(ctx, {
          inputA: sa,
          inputB: sb,
          selfSpendScalar: await this.deps.account.getSelfSpendKey(),
          selfMint: this.#mint(mints, 0),
        });
        return {
          witness: assembled.inputs,
          binding: {
            circuit: "join",
            compliancePk: ctx.compliancePk,
            nullifiers: [lo.nullifier, hi.nullifier],
            root: pin.root,
            output: asOutput(assembled.out),
          },
          commitments: [assembled.out.commitment],
        };
      },
      options,
    );
  }

  /** Deposit consumes no note: assemble -> prove -> verify -> an exact ERC20 approve -> submit. */
  deposit(asset: string, value: bigint): Promise<PlanResult> {
    const assetFr = addressFr(asset);
    return this.#run(
      "deposit",
      [],
      1,
      async (ctx, _spends, mints) => {
        const assembled = await assembleDeposit(ctx, {
          value,
          assetId: assetFr,
          spendScalar: await this.deps.account.getSelfSpendKey(),
          selfMint: this.#mint(mints, 0),
        });
        return {
          witness: assembled.inputs,
          binding: {
            circuit: "deposit",
            compliancePk: ctx.compliancePk,
            output: asOutput(assembled.minted),
            value,
            asset: assetFr,
          },
          commitments: [assembled.minted.commitment],
        };
      },
      { approve: { asset, value } },
    );
  }

  /**
   * Claims a public memo into a self note. Chain time (the latest block's timestamp) is the claim's
   * `current_timestamp`, never the device clock: the pool ceilings it against its own block time.
   */
  claimPublic(
    memo: RuntimePublicMemo,
    options: ActionOptions = {},
  ): Promise<PlanResult> {
    return this.#run(
      "public_claim",
      [],
      1,
      async (ctx, _spends, mints) => {
        if (!memo.claimable) {
          throw new WalletRuntimeError(
            "INPUT_SPENT",
            `public memo ${memo.memoId.toString()} is not claimable (spent ${memo.spent}, matured ${memo.matured})`,
            { nullifier: memo.memoId.toString() },
          );
        }
        const latest = await this.deps.chain.latest();
        const assembled = await buildPublicClaim({
          memo: {
            memoId: memo.memoId,
            assetId: memo.assetId,
            value: memo.value,
            timelock: memo.timelock,
            salt: memo.salt,
          },
          viewKey: await this.deps.account.getViewKey(),
          ownerIndex: memo.ownerIndex,
          compliancePk: ctx.compliancePk,
          complianceVersion: ctx.complianceVersion,
          complianceHistory: ctx.complianceHistory,
          chainId: ctx.chainId,
          poolAddress: ctx.poolAddress,
          deploymentAnchor: ctx.deploymentAnchor,
          keys: this.deps.account,
          selfMint: this.#mint(mints, 0),
          currentTimestamp: Number(latest.timestamp),
        });
        const eph = assembled.inputs.eph;
        return {
          witness: assembled.inputs,
          binding: {
            circuit: "public_claim",
            compliancePk: ctx.compliancePk,
            memoId: memo.memoId,
            timestamp: latest.timestamp,
            output: {
              commitment: assembled.commitment,
              ephPub: publicKey(eph),
              cek: deriveCek(eph, ctx.compliancePk),
              note: assembled.inputs.noteOut,
            },
          },
          commitments: [assembled.commitment],
        };
      },
      options,
    );
  }

  #one(spend: SpendableNote | undefined): SpendableNote {
    if (spend === undefined) {
      throw new WalletRuntimeError(
        "WITNESS_MISMATCH",
        "the action has no input note",
        { leafIndex: "", leafCount: "" },
      );
    }
    return spend;
  }

  #mint(
    mints: readonly SelfMintAuthorization[],
    i: number,
  ): SelfMintAuthorization {
    const mint = mints[i];
    if (mint === undefined) {
      throw new WalletRuntimeError(
        "PSS_UNAVAILABLE",
        `preflight returned ${mints.length} self-mint authorizations; the action needs mint ${i}`,
        { operation: "reserve" },
      );
    }
    return mint;
  }

  async #spendScalar(note: StoredNote): Promise<Fr> {
    return note.origin === "self"
      ? this.deps.account.getSelfSpendKey()
      : this.deps.account.getIncomingKey(BigInt(note.derivationIndex));
  }

  /** Re-pins until the pinned block is still canonical when both tree reads land. */
  async #pin(): Promise<TreeState> {
    let last: unknown;
    for (let attempt = 1; attempt <= MAX_STABLE_READ_ATTEMPTS; attempt++) {
      const block = await this.deps.chain.confirmedHead(
        this.deps.config.confirmations.spendableNotes,
      );
      try {
        return await readPinned(this.deps.chain, block, () =>
          this.deps.chain.treeState(block),
        );
      } catch (e) {
        if (e instanceof WalletRuntimeError && e.code === "HEAD_REORGED") {
          last = e;
          continue;
        }
        throw e;
      }
    }
    throw new WalletRuntimeError(
      "HEAD_REORGED",
      `the confirmed head reorged under each of ${MAX_STABLE_READ_ATTEMPTS} pins`,
      { attempts: String(MAX_STABLE_READ_ATTEMPTS), head: "" },
      last,
    );
  }

  async #run<C extends StandardCircuitId>(
    circuit: C,
    inputs: readonly StoredNote[],
    mintCount: 0 | 1 | 2,
    assemble: Assembler<C>,
    options: {
      readonly approve?: { readonly asset: string; readonly value: bigint };
      readonly fee?: StoredNote;
    } = {},
  ): Promise<PlanResult> {
    if (mintCount > 0 || options.fee !== undefined) {
      requireWriter(this.deps.pss);
    }
    const fee = options.fee;
    if (fee !== undefined && inputs.some((i) => noteKey(i) === noteKey(fee))) {
      throw new WalletRuntimeError(
        "LEASE_HELD",
        `the fee note at leaf ${fee.leafIndex} is also an input of this ${circuit}; the fee withdraw runs first, so the action would fail after the fee is paid`,
        { leafIndex: String(fee.leafIndex), planId: "" },
      );
    }
    return this.#exclusive(async () => {
      const { notes, chain } = this.deps;
      const pin = await this.#pin();
      const history = await this.deps.history();
      await this.deps.sweep();

      // select: the store's copy decides, never the caller's
      const view = {
        confirmedHead: pin.block.number,
        sweptThrough: notes.sweptThrough,
        now: pin.block.timestamp,
      };
      await notes.settleSubmitted(view);
      const held = (fee === undefined ? inputs : [...inputs, fee]).map((n) =>
        this.#stored(circuit, n, "select"),
      );
      for (const input of held) {
        // An unverified note is checked against the pinned tree at the witness step, or the action stops.
        const state = notes.state(
          input.verification === "unverified"
            ? { ...input, verification: "verified" }
            : input,
          view,
        );
        if (state !== "spendable") throw this.#unselectable(input, state, view);
      }
      const planId = newPlanId(this.deps.entropy);
      await notes.acquire(
        planId,
        held.map(noteKey),
        pin.block.timestamp + this.deps.leaseSeconds,
        pin.block.timestamp,
      );

      try {
        // witness, then root check: every input at the one pinned tree size
        const merkle = pinnedWitnessSource(
          { witnesses: this.deps.discovery, chain },
          pin,
          new Map(held.map((i) => [i.leafIndex, i.commitment])),
        );
        for (const input of held) {
          await merkle.witnessFor(input.commitment, input.leafIndex);
          if (input.verification === "unverified") {
            await notes.setVerification(noteKey(input), "verified");
          }
        }

        // assemble
        const current = await chain.complianceKey("latest");
        if (
          current.version !== history.currentVersion ||
          current.point[0] !== history.currentPk[0] ||
          current.point[1] !== history.currentPk[1]
        ) {
          throw new WalletRuntimeError(
            "COMPLIANCE_HISTORY_INVALID",
            `the pool's compliance key is version ${current.version}, the history read for this action ends at ${history.currentVersion}; refresh the history and re-assemble`,
            { reason: "CURRENT_KEY_MISMATCH" },
          );
        }
        const mints = await this.#reserve(mintCount, history, held);
        const ctx: AssemblyContext = {
          compliancePk: history.currentPk,
          complianceVersion: history.currentVersion,
          complianceHistory: history,
          chainId: BigInt(this.deps.config.deployment.chain_id),
          poolAddress: this.deps.config.deployment.dark_pool,
          deploymentAnchor: BigInt(deploymentBlock(this.deps.config)),
          merkle,
        };
        const spends: SpendableNote[] = [];
        for (const input of held) {
          spends.push({
            note: {
              noteVersion: input.note.noteVersion,
              assetId: input.note.assetId,
              noteType: input.note.noteType,
              conditionsHash: input.note.conditionsHash,
              value: new Fr(input.note.value),
              owner: input.note.owner,
              psi: input.note.psi,
              parents: input.note.parents,
            },
            leaf: input.commitment,
            leafIndex: input.leafIndex,
            spendScalar: await this.#spendScalar(input),
          });
        }
        for (const input of held) {
          const expected = await computeNullifier(
            input.note.psi,
            new Fr(BigInt(input.leafIndex)),
          );
          if (!expected.equals(input.nullifier)) {
            throw new WalletRuntimeError(
              "PUBLIC_INPUT_MISMATCH",
              `stored nullifier of leaf ${input.leafIndex} is not Poseidon2(psi, leafIndex)`,
              {
                circuit,
                position: "nullifier",
                expected: expected.toString(),
                actual: input.nullifier.toString(),
              },
            );
          }
        }
        const built = await assemble(
          ctx,
          spends.slice(0, inputs.length),
          mints,
          pin,
          history,
        );
        await notes.updatePlan(planId, (p) => ({ ...p, status: "proving" }));

        // prove
        let envelope: ProofEnvelope<C>;
        try {
          envelope = await this.deps.prover.prove(
            circuit,
            toStandardWitnessDto(circuit, built.witness),
          );
        } catch (cause) {
          throw new WalletRuntimeError(
            "PROOF_FAILED",
            `proving ${circuit} failed: ${describeCause(cause)}`,
            { circuit },
            cause,
          );
        }

        // verify
        if (!(await this.deps.prover.verify(envelope))) {
          throw new WalletRuntimeError(
            "PROOF_UNVERIFIED",
            `the ${circuit} proof does not verify locally`,
            { circuit },
          );
        }
        await checkPublicInputs(envelope, built.binding);

        // submit
        await this.deps.sweep();
        for (const input of held) {
          const now = this.#stored(circuit, input, "submit");
          if (now.spent !== null) {
            throw new WalletRuntimeError(
              "INPUT_SPENT",
              `note at leaf ${input.leafIndex} was spent in block ${now.spent.block.number} while this action was being built`,
              {
                nullifier: input.nullifier.toString(),
                leafIndex: String(input.leafIndex),
              },
            );
          }
        }
        if (options.approve !== undefined) {
          await this.#send(
            circuit,
            planId,
            {
              to: options.approve.asset,
              data: ERC20_INTERFACE.encodeFunctionData("approve", [
                this.deps.config.deployment.dark_pool,
                options.approve.value,
              ]),
            },
            [],
            [],
          );
        }
        const nullifiers = held.slice(0, inputs.length).map((i) => i.nullifier);
        const feeNote = fee === undefined ? undefined : held[inputs.length];
        const feeProver =
          feeNote === undefined
            ? undefined
            : this.#feeProver(feeNote, ctx, pin, history, spends);
        let outcome: Landed;
        try {
          outcome = await this.#send(
            circuit,
            planId,
            {
              to: this.deps.config.deployment.dark_pool,
              data: DARK_POOL_INTERFACE.encodeFunctionData(
                ENTRYPOINT[circuit],
                [envelope.proof, envelope.public_inputs],
              ),
            },
            nullifiers,
            built.commitments,
            feeProver?.prover,
          );
        } catch (e) {
          if (
            e instanceof WalletRuntimeError &&
            e.code === "SIMULATION_REVERTED" &&
            e.context.errorName === "NullifierAlreadySpent"
          ) {
            throw await this.#spentElsewhere(circuit, held, e);
          }
          throw e;
        }
        const feeSpent = feeProver?.proven() ?? null;
        await this.#confirm(
          circuit,
          outcome,
          feeSpent === null ? nullifiers : [...nullifiers, feeSpent.nullifier],
          feeSpent === null
            ? built.commitments
            : [...built.commitments, feeSpent.change],
        );
        await notes.updatePlan(planId, (p) => ({
          ...p,
          status: "included",
          submission: {
            txHash: outcome.txHash,
            block: outcome.block,
          },
        }));
        return {
          planId,
          txHash: outcome.txHash,
          blockNumber: outcome.block.number,
          commitments: built.commitments,
        };
      } catch (e) {
        const keep =
          e instanceof WalletRuntimeError && e.code === "SUBMIT_UNKNOWN";
        await notes.updatePlan(planId, (p) => ({
          ...p,
          status: keep ? "submitted" : "failed",
          leased: keep ? p.leased : [],
        }));
        throw e;
      }
    });
  }

  /**
   * The fee withdraw for a leased fee note. It runs when the submitter has a quote, inside this action's
   * exclusive window, at the action's pin: the witness was checked with the inputs, the change gets its own
   * preflight take, and the proof passes the same local verify and public-input binding as the action.
   */
  #feeProver(
    fee: StoredNote,
    ctx: AssemblyContext,
    pin: TreeState,
    history: CompleteComplianceHistory,
    spends: readonly SpendableNote[],
  ): {
    readonly prover: FeeWithdrawProver;
    proven(): { readonly nullifier: Fr; readonly change: Fr } | null;
  } {
    let proven: { readonly nullifier: Fr; readonly change: Fr } | null = null;
    const spend = spends[spends.length - 1];
    const prover: FeeWithdrawProver = {
      nullifier: fee.nullifier,
      assetId: fee.note.assetId,
      value: fee.note.value,
      prove: async (amount, recipient, intentHash) => {
        if (proven !== null) {
          throw new WalletRuntimeError(
            "LEASE_HELD",
            `the fee note at leaf ${fee.leafIndex} was already proved for this action; a second fee withdraw would reuse its nullifier`,
            { leafIndex: String(fee.leafIndex), planId: "" },
          );
        }
        const recipientFr = addressFr(recipient);
        const [changeMint] = await this.#reserve(1, history, [fee]);
        const assembled = await assembleWithdraw(ctx, {
          input: this.#one(spend),
          value: amount,
          recipient: recipientFr,
          selfSpendScalar: await this.deps.account.getSelfSpendKey(),
          changeMint: this.#mint(
            changeMint === undefined ? [] : [changeMint],
            0,
          ),
          intentHash,
        });
        let envelope: ProofEnvelope<"withdraw">;
        try {
          envelope = await this.deps.prover.prove(
            "withdraw",
            toStandardWitnessDto("withdraw", assembled.inputs),
          );
        } catch (cause) {
          throw new WalletRuntimeError(
            "PROOF_FAILED",
            `proving the fee withdraw failed: ${describeCause(cause)}`,
            { circuit: "withdraw" },
            cause,
          );
        }
        if (!(await this.deps.prover.verify(envelope))) {
          throw new WalletRuntimeError(
            "PROOF_UNVERIFIED",
            "the fee withdraw proof does not verify locally",
            { circuit: "withdraw" },
          );
        }
        await checkPublicInputs(envelope, {
          circuit: "withdraw",
          compliancePk: ctx.compliancePk,
          value: amount,
          recipient: recipientFr,
          intentHash,
          nullifier: fee.nullifier,
          root: pin.root,
          asset: fee.note.assetId,
          change: asOutput(assembled.change),
        });
        proven = {
          nullifier: fee.nullifier,
          change: assembled.change.commitment,
        };
        return { proof: envelope.proof, publicInputs: envelope.public_inputs };
      },
    };
    return { prover, proven: () => proven };
  }

  /**
   * The store's copy of a note the caller named. A note the store no longer holds (a reorg rollback dropped it)
   * stops the action, and so does a caller copy whose nullifier or asset is not the store's.
   */
  #stored(
    circuit: StandardCircuitId,
    note: StoredNote,
    step: "select" | "submit",
  ): StoredNote {
    const stored = this.deps.notes.find(noteKey(note));
    if (stored === undefined) {
      throw new WalletRuntimeError(
        "HEAD_REORGED",
        `the note at leaf ${note.leafIndex} is no longer in the note store at ${step} (a reorg rollback dropped it); sync the wallet and plan the action again`,
        { leafIndex: String(note.leafIndex), head: "" },
      );
    }
    for (const [position, expected, actual] of [
      ["nullifier", stored.nullifier, note.nullifier],
      ["asset", stored.note.assetId, note.note.assetId],
    ] as const) {
      if (!expected.equals(actual)) {
        throw new WalletRuntimeError(
          "PUBLIC_INPUT_MISMATCH",
          `the note passed for leaf ${note.leafIndex} carries a ${position} the note store does not hold for it`,
          {
            circuit,
            position,
            expected: expected.toString(),
            actual: actual.toString(),
          },
        );
      }
    }
    return stored;
  }

  /** Why a stored note cannot be selected, as the error the caller can act on. */
  #unselectable(
    note: StoredNote,
    state: Exclude<NoteState, "spendable">,
    view: NoteView,
  ): WalletRuntimeError {
    const leafIndex = String(note.leafIndex);
    if (note.spent !== null) {
      return new WalletRuntimeError(
        "INPUT_SPENT",
        `note at leaf ${note.leafIndex} is ${state}: spent in block ${note.spent.block.number}`,
        { nullifier: note.nullifier.toString(), leafIndex },
      );
    }
    const holder = this.deps.notes.leasedBy(noteKey(note), view.now);
    if (holder !== null) {
      const plan = this.deps.notes.plans.find((p) => p.planId === holder);
      if (plan?.status === "submitted") {
        return new WalletRuntimeError(
          "INPUT_SPENT",
          `note at leaf ${note.leafIndex} is being spent by submitted plan ${holder}, whose outcome settles after chain time ${submittedDeadline(plan)}`,
          { nullifier: note.nullifier.toString(), leafIndex, planId: holder },
        );
      }
      return new WalletRuntimeError(
        "LEASE_HELD",
        `note at leaf ${note.leafIndex} is leased by plan ${holder}`,
        { leafIndex, planId: holder },
      );
    }
    return new WalletRuntimeError(
      "INPUT_PENDING",
      `note at leaf ${note.leafIndex} (block ${note.block.number}) is ${state}: the confirmed head is ${view.confirmedHead} and the nullifier sweep has covered through block ${view.sweptThrough}`,
      {
        leafIndex,
        block: String(note.block.number),
        confirmedHead: String(view.confirmedHead),
        sweptThrough: String(view.sweptThrough),
      },
    );
  }

  /**
   * The pool refused an input nullifier as already spent, which the incremental sweep did not see. Re-reads
   * every spend from the oldest input's block, so the store learns the truth before the action fails.
   */
  async #spentElsewhere(
    circuit: StandardCircuitId,
    held: readonly StoredNote[],
    cause: WalletRuntimeError,
  ): Promise<WalletRuntimeError> {
    if (held.length === 0) return cause;
    const from = Math.min(...held.map((n) => n.block.number));
    await this.deps.notes.resweepFrom(from);
    await this.deps.sweep();
    for (const input of held) {
      const spent = this.deps.notes.find(noteKey(input))?.spent ?? null;
      if (spent !== null) {
        return new WalletRuntimeError(
          "INPUT_SPENT",
          `the pool refused the ${circuit} because an input is already spent; a re-sweep from block ${from} finds the note at leaf ${input.leafIndex} spent in block ${spent.block.number}`,
          {
            nullifier: input.nullifier.toString(),
            leafIndex: String(input.leafIndex),
          },
          cause,
        );
      }
    }
    return new WalletRuntimeError(
      "SIMULATION_REVERTED",
      `the ${circuit} simulation reverted with NullifierAlreadySpent, but a re-sweep from block ${from} through block ${this.deps.notes.sweptThrough} finds no input spent; the log source lags the node that simulated, so sync and retry`,
      { errorName: "NullifierAlreadySpent", circuit },
      cause,
    );
  }

  /**
   * Before the first mint of this pipeline, ratchets the durable self counter past every index the chain shows
   * occupied, scanning windows of `DISCOVERY_LOOKAHEAD` past the counter and past each occupied index. Preflight
   * would otherwise burn one candidate per used index and give up after its candidate bound when the counter
   * lost its place.
   */
  async #reconcileCounter(
    source: ReturnType<typeof discoverySourceOver>,
  ): Promise<void> {
    if (this.#counterReconciled) return;
    const { counters } = this.deps;
    let from = 0;
    let to = 0;
    try {
      to = Math.min(
        MAX_DISCOVERY_INDEX,
        (await counters.highWater(SELF_COUNTER_SCOPE)) + DISCOVERY_LOOKAHEAD,
      );
      while (from < to) {
        const tags = (
          await walletCandidates(this.deps.account, "self", from, to)
        ).map((c) => ({ index: c.candidate.index, tag: c.tag }));
        const { occupied } = await reconcileCounterWithChain(
          source,
          counters,
          SELF_COUNTER_SCOPE,
          tags,
        );
        const highest = occupied[occupied.length - 1] ?? -1;
        from = to;
        to = Math.min(
          MAX_DISCOVERY_INDEX,
          Math.max(to, highest + 1 + DISCOVERY_LOOKAHEAD),
        );
      }
    } catch (cause) {
      if (cause instanceof WalletRuntimeError) throw cause;
      throw new WalletRuntimeError(
        "PSS_UNAVAILABLE",
        `reconciling the self counter with the chain failed at indices [${from}, ${to}): ${describeCause(cause)}`,
        { operation: "reconcile" },
        cause,
      );
    }
    this.#counterReconciled = true;
  }

  /**
   * Self-mint preflight syncs discovery to `latest`. A rewind there that reaches an input's leaf stops the
   * action before it proves: the input may be gone from the chain, and the next wallet sync rolls the store
   * back from block hashes. A rewind above every input changes only occupancy, which preflight reads after it.
   */
  async #reserve(
    count: 0 | 1 | 2,
    history: CompleteComplianceHistory,
    held: readonly StoredNote[],
  ): Promise<readonly SelfMintAuthorization[]> {
    if (count === 0) return [];
    requireWriter(this.deps.pss);
    const onRewind = (head: {
      readonly rewoundTo: number;
      readonly block: { readonly number: number };
    }): void => {
      const hit = held.find((i) => i.leafIndex >= head.rewoundTo);
      if (hit === undefined) return;
      throw new WalletRuntimeError(
        "HEAD_REORGED",
        `discovery dropped every leaf from ${head.rewoundTo} on while this action was assembling, which includes input leaf ${hit.leafIndex}; sync the wallet and plan the action again`,
        {
          head: String(head.block.number),
          rewoundTo: String(head.rewoundTo),
          leafIndex: String(hit.leafIndex),
        },
      );
    };
    const source = discoverySourceOver(
      this.deps.discovery,
      this.deps.config.maxOccurrencesPerTag,
      onRewind,
    );
    await this.#reconcileCounter(source);
    const preflight = new SelfMintPreflight({
      allocator: this.deps.allocator,
      discovery: source,
      history,
      ownerCommitment: await pubkeyOwner(
        await this.deps.account.getSelfSpendPub(),
      ),
      domain: {
        chainId: BigInt(this.deps.config.deployment.chain_id),
        poolAddress: this.deps.config.deployment.dark_pool,
        deploymentAnchor: BigInt(deploymentBlock(this.deps.config)),
      },
    });
    try {
      return count === 1 ? await preflight.take(1) : await preflight.take(2);
    } catch (cause) {
      if (this.deps.pss.state.mode !== "writer") {
        requireWriter(this.deps.pss);
      }
      if (cause instanceof WalletRuntimeError) throw cause;
      // Preflight wraps what its discovery source threw; a runtime error there keeps its own code.
      if (cause instanceof Error && cause.cause instanceof WalletRuntimeError) {
        throw cause.cause;
      }
      throw new WalletRuntimeError(
        "PSS_UNAVAILABLE",
        `reserving ${count} self ephemeral(s) failed: ${describeCause(cause)}`,
        { operation: "reserve" },
        cause,
      );
    }
  }

  async #send(
    circuit: StandardCircuitId,
    planId: string,
    call: { readonly to: string; readonly data: string },
    nullifiers: readonly Fr[],
    commitments: readonly Fr[],
    fee?: FeeWithdrawProver,
  ): Promise<Landed> {
    const outcome: SubmissionOutcome = await this.deps.submitter.submit(call, {
      planId,
      nullifiers,
      commitments,
      ...(fee === undefined ? {} : { fee }),
    });
    if (outcome.status === "included") {
      const block = await this.deps.chain.blockByNumber(outcome.blockNumber);
      return {
        txHash: outcome.txHash,
        block: { number: block.number, hash: block.hash },
      };
    }
    if (outcome.status === "unknown") {
      const resume =
        outcome.resumeToken === null
          ? null
          : decodeNoxResume(outcome.resumeToken);
      const plan = await this.deps.notes.updatePlan(planId, (p) => ({
        ...p,
        resume,
      }));
      throw new WalletRuntimeError(
        "SUBMIT_UNKNOWN",
        `${circuit} submission outcome is unknown: ${outcome.detail}; the notes stay leased until a confirmed block is later than chain time ${submittedDeadline(plan)}${resume === null ? " (the lease end; with no resume token the transaction can still land after it)" : " (the execution's validUntilUnix)"}, then a sync or the next action releases the ones the sweep shows unspent`,
        {
          resumeToken:
            resume === null
              ? (outcome.resumeToken ?? "")
              : encodeNoxResume(resume),
        },
      );
    }
    if (outcome.status === "not-sent" && outcome.stage === "simulation") {
      throw new WalletRuntimeError(
        "SIMULATION_REVERTED",
        `${circuit} simulation reverted: ${outcome.detail}`,
        { errorName: outcome.errorName ?? "", circuit },
      );
    }
    throw new WalletRuntimeError(
      "SUBMIT_FAILED",
      outcome.status === "reverted"
        ? `${circuit} transaction ${outcome.txHash} reverted in block ${outcome.blockNumber}: ${outcome.reason}`
        : `${circuit} was not sent (${outcome.stage}): ${outcome.detail}`,
      {
        stage: outcome.status === "reverted" ? "reverted" : outcome.stage,
        detail: outcome.status === "reverted" ? outcome.reason : outcome.detail,
      },
    );
  }

  /** Inclusion is what the pool's logs say: every input nullifier spent and every leaf inserted, in one block. */
  async #confirm(
    circuit: StandardCircuitId,
    outcome: {
      readonly txHash: string;
      readonly block: { number: number; hash: string };
    },
    nullifiers: readonly Fr[],
    commitments: readonly Fr[],
  ): Promise<void> {
    const logs = await this.deps.logs.logs({
      topic0: [EVENT_TOPICS.NullifierSpent, EVENT_TOPICS.LeafInserted],
      fromBlock: outcome.block.number,
      toBlock: outcome.block.number,
    });
    const inBlock = logs.filter(
      (l) => l.blockHash === outcome.block.hash && !l.removed,
    );
    const spent = new Set<string>();
    const inserted = new Set<string>();
    for (const log of inBlock) {
      const parsed = DARK_POOL_INTERFACE.parseLog({
        topics: [...log.topics],
        data: log.data,
      });
      if (parsed?.name === "NullifierSpent")
        spent.add(BigInt(parsed.args[0] as string).toString());
      if (parsed?.name === "LeafInserted")
        inserted.add(BigInt(parsed.args[1] as string).toString());
    }
    const missing = [
      ...nullifiers
        .filter((n) => !spent.has(n.toBigInt().toString()))
        .map((n) => `nullifier ${n.toString()}`),
      ...commitments
        .filter((c) => !inserted.has(c.toBigInt().toString()))
        .map((c) => `leaf ${c.toString()}`),
    ];
    if (missing.length > 0) {
      throw new WalletRuntimeError(
        "SUBMIT_UNKNOWN",
        `${circuit} transaction ${outcome.txHash} was reported in block ${outcome.block.number}, but that block's logs lack ${missing.join(", ")}`,
        { resumeToken: outcome.txHash },
      );
    }
  }
}
