import { Fr } from "@aztec/foundation/fields";
import { SelfEphemeralAllocator, type DarkAccount } from "@hisoka/wallets";
import { DARK_POOL_INTERFACE, ERC20_INTERFACE } from "../../abi.js";
import { SelfIndexDiscovery } from "../../adapters/selfIndex/selfIndex.js";
import { RpcChainReader } from "../../chain/chainReader.js";
import { RpcLogSource } from "../../chain/logs.js";
import { readComplianceHistory } from "../../history/compliance.js";
import { sweepNullifiers } from "../../history/nullifiers.js";
import { PssEphemeralCounterStore } from "../../pss/counterStore.js";
import type { PssStatePort } from "../../pss/noteMirror.js";
import type { EntropyPort } from "../../spend/entropy.js";
import { syncWallet } from "../../walletSync.js";
import { SpendPipeline } from "../../spend/pipeline.js";
import { NoteStore, type StoredNote } from "../../store/noteStore.js";
import type {
  PoolCall,
  SubmissionContext,
  SubmissionOutcome,
  SubmitterPort,
} from "../../submit/ports.js";
import { ASSET, evenSelfIndex, selfNote } from "./mint.js";
import { accounts, COMPLIANCE_PK, SimPool } from "./pool.js";
import { FakePss } from "./pss.js";
import { ReferenceProver } from "./prover.js";
import { MemoryStore } from "./store.js";

/** Deterministic entropy: a counter, so plan ids and memo ephemerals repeat across runs. */
export class CountingEntropy implements EntropyPort {
  #n = 1;
  randomBytes(n: number): Uint8Array {
    const out = new Uint8Array(n);
    let v = this.#n++;
    for (let i = n - 1; i >= 0 && v > 0; i--) {
      out[i] = v & 0xff;
      v = Math.floor(v / 256);
    }
    return out;
  }
}

/**
 * Plays a pool call into the simulated pool the way DarkPool would on success: nullifiers spent, then every
 * output inserted in the entrypoint's order, in one new block. Records every call.
 */
export class PoolSubmitter implements SubmitterPort {
  readonly calls: { readonly name: string; readonly to: string }[] = [];
  /** Amount of every ERC20 approval sent, in order. */
  readonly approvals: bigint[] = [];
  next: SubmissionOutcome | null = null;
  onSubmit: (() => void) | null = null;

  constructor(private readonly pool: SimPool) {}

  async submit(
    call: PoolCall,
    _context: SubmissionContext,
  ): Promise<SubmissionOutcome> {
    this.onSubmit?.();
    if (call.to.toLowerCase() !== this.pool.config.deployment.dark_pool) {
      this.calls.push({ name: "approve", to: call.to });
      const approval = ERC20_INTERFACE.parseTransaction({ data: call.data });
      if (
        approval === null ||
        String(approval.args[0]).toLowerCase() !==
          this.pool.config.deployment.dark_pool.toLowerCase()
      ) {
        throw new Error("approval names another spender than the pool");
      }
      this.approvals.push(approval.args[1] as bigint);
      return {
        status: "included",
        txHash: `0x${"aa".repeat(32)}`,
        blockNumber: this.pool.chain.head,
      };
    }
    const parsed = DARK_POOL_INTERFACE.parseTransaction({ data: call.data });
    if (parsed === null) throw new Error("not a pool call");
    this.calls.push({ name: parsed.name, to: call.to });
    if (this.next !== null) {
      const outcome = this.next;
      this.next = null;
      return outcome;
    }
    this.pool.chain.mine();
    const block = this.pool.chain.head;
    await this.play(call.data, block);
    return {
      status: "included",
      txHash: `0x${"bb".repeat(32)}`,
      blockNumber: block,
    };
  }

  /** Applies one successful pool call's logs to `block`. */
  async play(data: string, block: number): Promise<void> {
    const parsed = DARK_POOL_INTERFACE.parseTransaction({ data });
    if (parsed === null) throw new Error("not a pool call");
    const pi = (parsed.args[1] as string[]).map((w) => new Fr(BigInt(w)));
    const at = (i: number): Fr => {
      const w = pi[i];
      if (w === undefined) throw new Error(`no public input ${i}`);
      return w;
    };
    const note = async (leaf: number, eph: number, ct: number) =>
      this.pool.insertRaw(block, at(leaf), at(eph), pi.slice(ct, ct + 7));
    switch (parsed.name) {
      case "deposit":
        await note(2, 3, 6);
        break;
      case "withdraw":
        this.pool.spend(block, at(5));
        await note(8, 9, 10);
        break;
      case "privateTransfer":
        this.pool.spend(block, at(2));
        await this.pool.insertRawMemo(
          block,
          at(4),
          at(6),
          at(5),
          at(7),
          pi.slice(8, 15),
        );
        await note(15, 16, 17);
        break;
      case "join":
        this.pool.spend(block, at(2));
        this.pool.spend(block, at(3));
        await note(5, 6, 7);
        break;
      case "split":
        this.pool.spend(block, at(2));
        await note(4, 5, 6);
        await note(13, 14, 15);
        break;
      case "publicClaim":
        this.pool.chain.emit(block, "PublicMemoSpent", [
          `0x${at(0).toBigInt().toString(16).padStart(64, "0")}`,
        ]);
        await note(4, 5, 6);
        break;
      default:
        throw new Error(`unscripted entrypoint ${parsed.name}`);
    }
  }
}

export interface RuntimeEnv {
  readonly pool: SimPool;
  readonly alice: DarkAccount;
  readonly bob: DarkAccount;
  readonly store: MemoryStore;
  readonly index: SelfIndexDiscovery;
  readonly notes: NoteStore;
  readonly prover: ReferenceProver;
  readonly submitter: PoolSubmitter;
  readonly counter: PssEphemeralCounterStore;
  readonly pss: { state: PssStatePort["state"] };
  readonly pipeline: SpendPipeline;
  readonly chain: RpcChainReader;
  /** Sync discovery and the nullifier sweep, and record what alice owns. */
  refresh(): Promise<readonly StoredNote[]>;
}

export async function runtimeEnv(height = 40): Promise<RuntimeEnv> {
  const pool = await SimPool.create(height);
  const { alice, bob } = await accounts();
  const store = new MemoryStore();
  const config = pool.config;
  const chain = RpcChainReader.over(pool.chain.rpc, config);
  const logs = RpcLogSource.over(pool.chain.rpc, config);
  const index = await SelfIndexDiscovery.open({ config, chain, logs, store });
  const notes = await NoteStore.open(store, "hisoka.runtime.v1.test.notes");
  const pss = new FakePss();
  const counter = new PssEphemeralCounterStore(pss);
  const prover = new ReferenceProver();
  const submitter = new PoolSubmitter(pool);
  const historyDeps = { config, chain, logs, store };
  const pipeline = new SpendPipeline({
    config,
    chain,
    logs,
    discovery: index,
    notes,
    pss,
    allocator: new SelfEphemeralAllocator(alice, counter),
    counters: counter,
    account: alice,
    prover,
    submitter,
    entropy: new CountingEntropy(),
    history: async () => (await readComplianceHistory(historyDeps)).history,
    sweep: async () => {
      await sweepNullifiers({ config, chain, logs }, notes);
    },
    leaseSeconds: 600n,
  });
  const refresh = async (): Promise<readonly StoredNote[]> => {
    await syncWallet({
      config,
      chain,
      logs,
      discovery: index,
      notes,
      account: alice,
      history: async () => (await readComplianceHistory(historyDeps)).history,
      highWater: async () => ({
        self: await counter.highWater("self"),
        incoming: 0,
      }),
    });
    return notes.notes;
  };
  return {
    pool,
    alice,
    bob,
    store,
    index,
    notes,
    prover,
    submitter,
    counter,
    pss,
    pipeline,
    chain,
    refresh,
  };
}

/** Funds alice with self notes of `values`, mined at blocks 10, 11, ... and returns them from the store. */
export async function funded(
  env: RuntimeEnv,
  values: readonly bigint[],
): Promise<StoredNote[]> {
  let index = -1;
  for (const [i, value] of values.entries()) {
    index = await evenSelfIndex(env.alice, index + 1);
    await env.pool.insertSelf(
      10 + i,
      await selfNote(env.alice, index, value, COMPLIANCE_PK[0]!, ASSET),
    );
  }
  const all = await env.refresh();
  return [...all];
}
