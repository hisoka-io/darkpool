// One wave of the Fuji simulation: seven wallets with distinct habits send real proofs to the deployed Howl pool,
// and every note each wallet holds, and every Merkle path it spends with, comes through a Raven Howl node
// following Fuji. After every transaction each wallet is graded against an independent scan of the pool's own
// logs and against the pool's token balances; the wave stops at the first mismatch.
//
// Ported from Raven's adapters/howl-node/e2e RavenSim for a deployed pool on a public chain: it attaches to the
// recorded deployment instead of deploying, reads logs in windows the endpoint accepts, keeps wallet and node
// state across waves, paces each persona on its own clock, caps the cheater, and refuses to send above a gas price
// ceiling or past a spend cap. Anvil-only phases (forced reorganisation, bulk growth) are not ported.
//
// Run by test/fuji-sim/run.sh. Environment: SIM_RPC_URL (sends and graded reads), SIM_NODE_RPC_URL (the node's
// endpoint; defaults to SIM_RPC_URL), SIM_STATE_DIR (persists across waves), SIM_OUT_DIR
// (this wave's records), SIM_RECORD (the deployment record), SIM_TOKENS, SIM_VENUE, SIM_AGENTS (wallet keys, mode
// 600), SIM_NODE_PORT, HOWL_NODE_BIN, RAVEN_SDK, RAVEN_WASM, SIM_WAVE, SIM_WAVE_MINUTES, SIM_MAX_ACTIONS,
// SIM_PACE (persona pause multiplier, 0 for a rehearsal), SIM_SEED, SIM_MAX_CHEATS, SIM_MAX_GAS_PRICE_WEI,
// SIM_SPEND_CAP_WEI, SIM_FINAL (claim everything left), SIM_LOG_MAX_BLOCKS; optional SIM_PLANT_DROP_FEED_LEAF.
import { expect } from "chai";
import { ethers } from "ethers";
import type { ContractTransactionResponse } from "ethers";
import { spawn, type ChildProcess } from "node:child_process";
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { createRequire } from "node:module";
import { join } from "node:path";
import {
  Fr,
  toFr,
  addressToFr,
  newSeededTree,
  packParents,
} from "@hisoka/wallets";
import { mintSelfNote } from "@hisoka/wallets/unsafe-sim";
import { proveWithdraw, type ProofData } from "@hisoka/prover";
import { hashUniswapIntent, SwapType } from "@hisoka/adaptors";
import type { Point } from "@zk-kit/baby-jubjub";
import { evenYEphemeral, userSpendScalar } from "../helpers/fixtures";
import {
  FujiAgent,
  poolDomain,
  useRavenPorts,
  type FoundNote,
  type RavenPorts,
  type RavenSource,
} from "./fujiAgent";
import { PoolLogs, withRetry } from "./poolLogs";
import {
  DarkPool__factory,
  IERC20__factory,
  UniswapAdaptor__factory,
  type DarkPool,
  type IERC20,
  type UniswapAdaptor,
} from "../../typechain-types";

const env = (k: string): string => {
  const v = process.env[k];
  if (v === undefined || v === "")
    throw new Error(`${k} is required (see the header of this file)`);
  return v;
};
const num = (k: string): number => {
  const v = Number(env(k));
  if (!Number.isFinite(v) || v < 0)
    throw new Error(`${k} must be a non-negative number`);
  return v;
};

const STATE = env("SIM_STATE_DIR");
const OUT = env("SIM_OUT_DIR");
const WAVE = num("SIM_WAVE");
const WAVE_MS = num("SIM_WAVE_MINUTES") * 60_000;
const MAX_ACTIONS = num("SIM_MAX_ACTIONS");
const PACE = num("SIM_PACE");
const SEED = num("SIM_SEED") + WAVE;
const MAX_CHEATS = num("SIM_MAX_CHEATS");
const MAX_GAS_PRICE = BigInt(env("SIM_MAX_GAS_PRICE_WEI"));
const SPEND_CAP = BigInt(env("SIM_SPEND_CAP_WEI"));
const FINAL = process.env.SIM_FINAL === "1";
const LOG_MAX_BLOCKS = num("SIM_LOG_MAX_BLOCKS");
const PLANT_DROP_LEAF =
  process.env.SIM_PLANT_DROP_FEED_LEAF === undefined
    ? -1
    : Number(process.env.SIM_PLANT_DROP_FEED_LEAF);
const LEAF_INSERTED = ethers.id("LeafInserted(uint256,bytes32,bytes32)");
// after a transaction the node has a few blocks to read; at a wave start it may have the whole gap since the last one
const NODE_CATCH_UP_MS = 300_000;
const NODE_FIRST_SYNC_MS = 3_600_000;
const CHEAT_GAS_LIMIT = 3_000_000;
// Howl's generated verifiers revert from assembly with these selectors (their Errors.sol names)
const VERIFIER_ERRORS: Record<string, string> = {
  "0xeb73e0bd": "ValueGeLimbMax",
  "0x607be13e": "ValueGeGroupOrder",
  "0x20a33589": "ValueGeFieldOrder",
  "0x9fc3a218": "SumcheckFailed",
  "0xa5d82e8a": "ShpleminiFailed",
  "0x59895a53": "ProofLengthWrongWithLogN",
  "0xfa066593": "PublicInputsLengthWrong",
  "0xf442f163": "ModexpFailed",
  "0xa2a2ac83": "ConsistencyCheckFailed",
  "0x835eb8f7": "GeminiChallengeInSubgroup",
};
const PROOF_REJECTED = new Set([
  "InvalidProof",
  ...Object.values(VERIFIER_ERRORS),
]);

// ---------------------------------------------------------------- deterministic choices
function rng(seed: number) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const rand = rng(SEED);
const randInt = (lo: number, hi: number) =>
  lo + Math.floor(rand() * (hi - lo + 1));
const pickOne = <T>(xs: readonly T[]): T => xs[Math.floor(rand() * xs.length)]!;
function shuffle<T>(xs: T[]): T[] {
  for (let i = xs.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    [xs[i], xs[j]] = [xs[j]!, xs[i]!];
  }
  return xs;
}
function weighted<T extends string>(w: Record<T, number>): T {
  const entries = (Object.entries(w) as [T, number][]).filter(([, x]) => x > 0);
  const total = entries.reduce((s, [, x]) => s + x, 0);
  let r = rand() * total;
  for (const [k, x] of entries) if ((r -= x) <= 0) return k;
  return entries[entries.length - 1]![0];
}

// ---------------------------------------------------------------- records
const stringify = (row: unknown, space?: number) =>
  JSON.stringify(
    row,
    (_, v) => (typeof v === "bigint" ? v.toString() : v),
    space,
  );
const jsonl = (file: string, row: unknown) =>
  appendFileSync(join(OUT, file), stringify(row) + "\n");
function writeAtomic(file: string, body: string): void {
  writeFileSync(`${file}.tmp`, body);
  renameSync(`${file}.tmp`, file);
}

/** What later waves need to know about earlier ones. */
interface RunState {
  wavesDone: number;
  cheatsUsed: number;
  spentWei: string;
  transactions: number;
  mismatches: number;
}
const RUN_FILE = join(STATE, "run.json");
const readRun = (): RunState =>
  existsSync(RUN_FILE)
    ? (JSON.parse(readFileSync(RUN_FILE, "utf8")) as RunState)
    : {
        wavesDone: 0,
        cheatsUsed: 0,
        spentWei: "0",
        transactions: 0,
        mismatches: 0,
      };

interface Exchange {
  status: number;
  body: Uint8Array;
}
interface Transport {
  get(p: string): Promise<Exchange>;
  post(p: string, b: Uint8Array): Promise<Exchange>;
}
interface RavenSdk extends RavenPorts {
  fetchTransport(url: string, options: { timeoutMs: number }): Transport;
  RavenHowlSource: new (options: {
    transport: Transport;
    wasm: unknown;
    field: { fromBytes(b: Uint8Array): Fr; toBytes(f: Fr): Uint8Array };
    keyMode: "inline" | "session";
  }) => RavenSource;
}

interface RouteSample {
  agent: string;
  method: string;
  route: string;
  ms: number;
  status: number;
}
const routeSamples: RouteSample[] = [];

/**
 * The planted node: blank feed row PLANT_DROP_LEAF in every sync and prefixes answer. The feed is not bound by the
 * root, so the client takes the row as served, exactly as from a node that lost it.
 */
let plantHits = 0;
function plantDroppedRow(route: string, ex: Exchange): Exchange {
  if (PLANT_DROP_LEAF < 0 || ex.status !== 200) return ex;
  if (route !== "/howl/v1/sync" && route !== "/howl/v1/prefixes") return ex;
  const body = new Uint8Array(ex.body);
  const view = new DataView(body.buffer);
  const base = Number(view.getBigUint64(56));
  const next = Number(view.getBigUint64(64));
  if (PLANT_DROP_LEAF < base || PLANT_DROP_LEAF >= next) return ex;
  const at = 72 + (PLANT_DROP_LEAF - base) * 6;
  body.fill(0, at, at + 6);
  plantHits += 1;
  return { ...ex, body };
}

function timedTransport(base: Transport, agent: string): Transport {
  const route = (p: string) => p.split("?")[0]!.replace(/\/\d+$/, "/:n");
  return {
    async get(path: string) {
      const t0 = performance.now();
      const ex = plantDroppedRow(route(path), await base.get(path));
      routeSamples.push({
        agent,
        method: "GET",
        route: route(path),
        ms: performance.now() - t0,
        status: ex.status,
      });
      return ex;
    },
    async post(path: string, body: Uint8Array) {
      const t0 = performance.now();
      const ex = await base.post(path, body);
      routeSamples.push({
        agent,
        method: "POST",
        route: route(path),
        ms: performance.now() - t0,
        status: ex.status,
      });
      return ex;
    },
  };
}

/**
 * A wallet that counts its own nonces: it reads the chain's count once, then advances it for every transaction the
 * endpoint accepts. Each wallet sends from this one process, one transaction at a time, so the local count is exact,
 * while a node's reported count can lag a mined transaction (an anvil fork does; so can a load-balanced endpoint).
 * A refusal for a stale nonce drops the local count, so the next send reads the chain again.
 */
class CountingNonceWallet extends ethers.Wallet {
  #next: number | null = null;

  override async getNonce(): Promise<number> {
    if (this.#next === null)
      this.#next = await withRetry("nonce", () =>
        this.provider!.getTransactionCount(this.address, "latest"),
      );
    return this.#next;
  }

  override async sendTransaction(
    tx: ethers.TransactionRequest,
  ): Promise<ethers.TransactionResponse> {
    const nonce = await this.getNonce();
    try {
      const sent = await super.sendTransaction({ ...tx, nonce });
      this.#next = nonce + 1;
      return sent;
    } catch (e: unknown) {
      if (ethers.isError(e, "NONCE_EXPIRED")) this.#next = null;
      throw e;
    }
  }
}

// ---------------------------------------------------------------- the node
class HowlNode {
  proc: ChildProcess | null = null;
  readonly url: string;
  constructor(
    readonly bin: string,
    readonly rpc: string,
    readonly dataDir: string,
    readonly chainId: bigint,
    readonly pool: string,
    readonly deploymentBlock: number,
    readonly port: number,
  ) {
    this.url = `http://127.0.0.1:${port}`;
  }
  start() {
    process.once("exit", () => this.proc?.kill("SIGKILL"));
    const args = [
      "--data-dir",
      this.dataDir,
      "--chain-id",
      this.chainId.toString(),
      "--pool",
      this.pool,
      "--deployment-block",
      String(this.deploymentBlock),
      "--listen",
      `127.0.0.1:${this.port}`,
      "--poll-ms",
      "1000",
      "--max-range",
      String(LOG_MAX_BLOCKS),
    ];
    this.proc = spawn(this.bin, args, {
      env: { ...process.env, HOWL_NODE_RPC_URL: this.rpc, RUST_LOG: "info" },
      stdio: ["ignore", "pipe", "pipe"],
    });
    const log = join(OUT, "node.log");
    this.proc.stdout!.on("data", (d) => appendFileSync(log, d));
    this.proc.stderr!.on("data", (d) => appendFileSync(log, d));
  }
  async stop() {
    if (this.proc && this.proc.exitCode === null) {
      const p = this.proc;
      p.kill("SIGINT");
      await new Promise((r) => p.once("exit", r));
    }
    this.proc = null;
  }
  async health(): Promise<{
    leaves: number;
    block: number;
    shards: number;
    sessions: number;
  } | null> {
    try {
      const r = await fetch(`${this.url}/howl/v1/health`);
      if (r.status !== 200) return null;
      const f = Object.fromEntries(
        (await r.text())
          .trim()
          .split(/\s+/)
          .slice(1)
          .map((kv) => kv.split("=")),
      );
      return {
        leaves: Number(f.leaves),
        block: Number(f.block),
        shards: Number(f.shards),
        sessions: Number(f.sessions),
      };
    } catch {
      return null;
    }
  }
  async ready(): Promise<number> {
    try {
      return (await fetch(`${this.url}/howl/v1/ready`)).status;
    } catch {
      return 0;
    }
  }
  memory(): { rssKiB: number; hwmKiB: number } {
    const s = readFileSync(`/proc/${this.proc!.pid}/status`, "utf8");
    const kib = (k: string) =>
      Number(new RegExp(`${k}:\\s+(\\d+)`).exec(s)![1]);
    return { rssKiB: kib("VmRSS"), hwmKiB: kib("VmHWM") };
  }
}

// ---------------------------------------------------------------- personas
interface Persona {
  name: string;
  strategy: string;
  /** Seconds between this wallet's actions, before SIM_PACE. */
  pause: [number, number];
}
const ROSTER: Persona[] = [
  { name: "alice", strategy: "greedy", pause: [60, 240] },
  { name: "bob", strategy: "cheater", pause: [90, 300] },
  { name: "charlie", strategy: "donor", pause: [120, 420] },
  { name: "david", strategy: "philanthropist", pause: [150, 480] },
  { name: "ellie", strategy: "trader", pause: [45, 180] },
  { name: "frank", strategy: "whale", pause: [1200, 2700] },
  { name: "grace", strategy: "privacy", pause: [480, 1200] },
];

// ---------------------------------------------------------------- the wave
describe("Fuji simulation: one wave of seven wallets through Raven", function () {
  this.timeout(0);

  it("every transaction graded against the chain, zero mismatches", async function () {
    mkdirSync(OUT, { recursive: true });
    mkdirSync(join(STATE, "keys"), { recursive: true, mode: 0o700 });
    const run = readRun();
    if (run.mismatches > 0)
      throw new Error(
        `an earlier wave recorded ${run.mismatches} mismatches; the run is stopped`,
      );

    const load = createRequire(__filename);
    const sdk = load(env("RAVEN_SDK")) as RavenSdk;
    const wasm = load(env("RAVEN_WASM")) as unknown;
    useRavenPorts(sdk);

    const provider = new ethers.JsonRpcProvider(env("SIM_RPC_URL"), undefined, {
      staticNetwork: true,
      batchMaxCount: 1,
      // a read right after a receipt must see that block, so ethers' 250 ms reuse of identical requests is off
      cacheTimeout: -1,
    });
    const network = await withRetry("chain id", () => provider.getNetwork());
    const record = JSON.parse(readFileSync(env("SIM_RECORD"), "utf8")) as {
      meta: { chainId: number; startBlock: number };
      contracts: { darkPool: string };
    };
    if (BigInt(record.meta.chainId) !== network.chainId)
      throw new Error(
        `the record is for chain ${record.meta.chainId}, the endpoint serves ${network.chainId}`,
      );
    const tokensRecord = JSON.parse(
      readFileSync(env("SIM_TOKENS"), "utf8"),
    ) as {
      tokens: Record<string, { address: string; decimals: number }>;
    };
    const venue = JSON.parse(readFileSync(env("SIM_VENUE"), "utf8")) as {
      chainId: number;
      router: string;
      adaptor: string;
    };
    if (BigInt(venue.chainId) !== network.chainId)
      throw new Error("the swap venue record is for another chain");
    const keys = JSON.parse(readFileSync(env("SIM_AGENTS"), "utf8")) as {
      chainId: number;
      agents: Record<string, { address: string; privateKey: string }>;
    };
    if ((statSync(env("SIM_AGENTS")).mode & 0o077) !== 0)
      throw new Error("the agents key file must be mode 600");

    const startBlock = record.meta.startBlock;
    const poolAddr = ethers.getAddress(record.contracts.darkPool);
    const darkPool: DarkPool = DarkPool__factory.connect(poolAddr, provider);
    const [pkX, pkY, version] = await withRetry("compliance key", () =>
      darkPool.complianceKey(),
    );
    const domain = poolDomain([pkX, pkY], Number(version), startBlock);

    const assetDai = ethers.getAddress(tokensRecord.tokens.mDAI!.address);
    const assetWeth = ethers.getAddress(tokensRecord.tokens.mWETH!.address);
    const assetUsdc = ethers.getAddress(tokensRecord.tokens.mUSDC!.address);
    const ASSETS = [assetDai, assetWeth, assetUsdc];
    const LABEL: Record<string, string> = {
      [assetDai]: "mDAI",
      [assetWeth]: "mWETH",
      [assetUsdc]: "mUSDC",
    };
    // one thousandth of a whole token: every amount below is a multiple of it
    const UNIT: Record<string, bigint> = {
      [assetDai]: 10n ** 15n,
      [assetWeth]: 10n ** 15n,
      [assetUsdc]: 10n ** 3n,
    };
    const tokens = new Map<string, IERC20>(
      ASSETS.map((a) => [a, IERC20__factory.connect(a, provider)]),
    );
    const erc = (asset: string) => tokens.get(asset)!;
    const adaptor: UniswapAdaptor = UniswapAdaptor__factory.connect(
      venue.adaptor,
      provider,
    );

    const poolLogs = new PoolLogs(
      provider,
      darkPool as unknown as ethers.Contract,
      startBlock,
      LOG_MAX_BLOCKS,
    );
    const chainRootAt = async (count: number) => {
      await poolLogs.refresh();
      for (const l of poolLogs.byTopic(LEAF_INSERTED))
        if (Number(BigInt(l.topics[1]!)) + 1 === count)
          return "0x" + l.data.slice(66, 130);
      return undefined;
    };
    const leafAt = (i: number): string | undefined => {
      for (const l of poolLogs.byTopic(LEAF_INSERTED))
        if (Number(BigInt(l.topics[1]!)) === i)
          return "0x" + l.data.slice(2, 66);
      return undefined;
    };

    const node = new HowlNode(
      env("HOWL_NODE_BIN"),
      process.env.SIM_NODE_RPC_URL || env("SIM_RPC_URL"),
      join(STATE, "node-data"),
      network.chainId,
      poolAddr,
      startBlock,
      num("SIM_NODE_PORT"),
    );
    if ((await node.health()) !== null)
      throw new Error(`port ${node.port} already serves a node`);
    node.start();
    const nodeT0 = Date.now();
    while ((await node.health()) === null) {
      if (Date.now() - nodeT0 > 60_000)
        throw new Error("node did not start within 60 s");
      await new Promise((r) => setTimeout(r, 200));
    }

    const agents: FujiAgent[] = [];
    const sources: RavenSource[] = [];
    for (const p of ROSTER) {
      const k = keys.agents[p.name];
      if (k === undefined)
        throw new Error(`no key for ${p.name} in the agents file`);
      const signer = new CountingNonceWallet(k.privateKey, provider);
      if (signer.address !== ethers.getAddress(k.address))
        throw new Error(
          `${p.name}: the agents file address does not match its key`,
        );
      const source = new sdk.RavenHowlSource({
        transport: timedTransport(
          sdk.fetchTransport(node.url, { timeoutMs: 120_000 }),
          p.name,
        ),
        wasm,
        field: {
          fromBytes: (b: Uint8Array) => Fr.fromBuffer(Buffer.from(b)),
          toBytes: (f: Fr) => new Uint8Array(f.toBuffer()),
        },
        // one wallet carries its key in every request; the others hold a session
        keyMode: p.name === "ellie" ? "inline" : "session",
      });
      sources.push(source);
      agents.push(
        await FujiAgent.create(
          p.name,
          p.strategy,
          signer,
          darkPool.connect(signer) as DarkPool,
          source,
          chainRootAt,
          domain,
          poolLogs,
          join(STATE, "keys", `${p.name}.json`),
        ),
      );
    }
    const byName = new Map(agents.map((a) => [a.name, a]));

    // ------------------------------------------------------------ public ledger, read fresh at the wave start
    const expectedPublic = new Map<string, Map<string, bigint>>();
    for (const a of agents) {
      const m = new Map<string, bigint>();
      for (const asset of ASSETS)
        m.set(
          asset,
          await withRetry("balance", () => erc(asset).balanceOf(a.address)),
        );
      expectedPublic.set(a.address, m);
    }
    const movePublic = (who: string, asset: string, delta: bigint) => {
      const m = expectedPublic.get(who);
      if (m) m.set(asset, m.get(asset)! + delta);
    };
    const gasAtStart = new Map<string, bigint>();
    for (const a of agents)
      gasAtStart.set(
        a.address,
        await withRetry("native balance", () => provider.getBalance(a.address)),
      );
    const spentBefore = BigInt(run.spentWei);
    const spentNow = async (): Promise<bigint> => {
      let s = spentBefore;
      for (const a of agents)
        s +=
          gasAtStart.get(a.address)! -
          (await withRetry("native balance", () =>
            provider.getBalance(a.address),
          ));
      return s;
    };

    // ------------------------------------------------------------ bookkeeping
    let step = 0;
    let txOk = 0;
    let txRejected = 0;
    let mismatches = 0;
    let cheatsUsed = run.cheatsUsed;
    const kinds: Record<string, Record<string, number>> = {};
    const followLagMs: number[] = [];
    const discoveryMs: number[] = [];
    const readiness: { step: number; status: number }[] = [];
    const lastProofs = new Map<
      string,
      {
        kind: string;
        call: (o?: {
          gasLimit: number;
        }) => Promise<ContractTransactionResponse>;
        staticCall: () => Promise<unknown>;
      }
    >();
    const witnessCursor = new Map<string, number>(
      agents.map((a) => [a.name, 0]),
    );
    const count = (agent: string, kind: string) => {
      kinds[agent] ??= {};
      kinds[agent]![kind] = (kinds[agent]![kind] ?? 0) + 1;
    };

    const nodeRoot = async (leafCount: number): Promise<string | null> => {
      const r = await fetch(`${node.url}/howl/v1/prefixes?since=${leafCount}`);
      if (r.status !== 200) return null;
      const body = new Uint8Array(await r.arrayBuffer());
      return ethers.hexlify(body.subarray(24, 56));
    };
    const waitCaughtUp = async (
      limitMs = NODE_CATCH_UP_MS,
    ): Promise<number> => {
      const t0 = performance.now();
      const want = Number(
        await withRetry("leaf count", () => darkPool.getNextLeafIndex()),
      );
      const head = await poolLogs.refresh();
      let root = await chainRootAt(want);
      for (;;) {
        root ??= await chainRootAt(want);
        const h = await node.health();
        if (h !== null && h.leaves === want && h.block >= head) {
          const served = await nodeRoot(want);
          if (
            served !== null &&
            root !== undefined &&
            BigInt(served) === BigInt(root)
          )
            return performance.now() - t0;
        }
        if (performance.now() - t0 > limitMs)
          throw new Error(
            `node did not catch up within ${limitMs} ms: ${JSON.stringify(h)}, want ${want} leaves at block ${head}, chain root ${root ?? "not yet in the scanned logs"} (logs to ${poolLogs.scannedTo})`,
          );
        await new Promise((r) => setTimeout(r, 500));
      }
    };

    const fmt = (n: FoundNote) =>
      `${n.leafIndex}:${n.commitment}:${n.value}:${n.asset}:${n.spent ? "S" : "U"}:${n.incoming ? "in" : "self"}`;

    const mismatch = (row: Record<string, unknown>) => {
      mismatches += 1;
      jsonl("mismatches.jsonl", { wave: WAVE, step, ...row });
    };

    /** Grade every wallet after a step: Raven's notes against the chain's own logs and balances. */
    let synced = false;
    const verify = async (label: string, extra: Record<string, unknown>) => {
      const lag = await waitCaughtUp(
        synced ? NODE_CATCH_UP_MS : NODE_FIRST_SYNC_MS,
      );
      synced = true;
      followLagMs.push(lag);
      readiness.push({ step, status: await node.ready() });
      const perAgent: Record<string, unknown> = {};
      for (const a of agents) {
        const t0 = performance.now();
        const d = await a.discover();
        const ms = performance.now() - t0;
        discoveryMs.push(ms);
        const raven = a.found();
        const oracle = await a.oracle();
        const r = raven.map(fmt);
        const o = oracle.map(fmt);
        const missing = o.filter((x) => !r.includes(x));
        const extraNotes = r.filter((x) => !o.includes(x));
        if (missing.length + extraNotes.length > 0)
          mismatch({ label, agent: a.name, missing, extra: extraNotes });
        // every Raven-found note's commitment is the chain's leaf at that index
        for (const n of raven)
          if (BigInt(leafAt(n.leafIndex) ?? "0x0") !== BigInt(n.commitment))
            mismatch({ label, agent: a.name, leafNotOnChain: n.leafIndex });
        const newWitness = a.witnesses.slice(witnessCursor.get(a.name)!);
        witnessCursor.set(a.name, a.witnesses.length);
        for (const w of newWitness)
          if (!w.knownRoot || !w.chainRootAtCount)
            mismatch({ label, agent: a.name, witness: w });
        perAgent[a.name] = {
          balances: Object.fromEntries(
            ASSETS.map((x) => [LABEL[x], a.balance(x)]),
          ),
          notes: raven.length,
          unspent: raven.filter((n) => !n.spent).length,
          oracleNotes: oracle.length,
          rejectedRows: d.rejected,
          discoveryMs: Math.round(ms),
          witnesses: newWitness.length,
        };
      }
      // the pool holds exactly the wallets' unspent notes plus unclaimed public memos
      const memoLogs = poolLogs.events("NewPublicMemo");
      const spentMemo = new Set(
        poolLogs.events("PublicMemoSpent").map((l) => String(l.args.memoId)),
      );
      const pool: Record<string, unknown> = {};
      for (const asset of ASSETS) {
        const notes = agents.reduce((s, a) => s + a.balance(asset), 0n);
        const memos = memoLogs
          .filter(
            (l) =>
              !spentMemo.has(String(l.args.memoId)) &&
              ethers.getAddress(l.args.asset) === asset,
          )
          .reduce((s, l) => s + BigInt(l.args.value), 0n);
        const held = await withRetry("pool balance", () =>
          erc(asset).balanceOf(poolAddr),
        );
        if (notes + memos !== held)
          mismatch({ label, asset: LABEL[asset], notes, memos, held });
        pool[LABEL[asset]!] = { held, notes, memos };
        for (const a of agents) {
          const want = expectedPublic.get(a.address)!.get(asset)!;
          const got = await withRetry("balance", () =>
            erc(asset).balanceOf(a.address),
          );
          if (want !== got)
            mismatch({
              label,
              agent: a.name,
              asset: LABEL[asset],
              publicWant: want,
              publicGot: got,
            });
        }
      }
      const h = (await node.health())!;
      jsonl("steps.jsonl", {
        wave: WAVE,
        step,
        at: new Date().toISOString(),
        label,
        ...extra,
        leaves: h.leaves,
        block: h.block,
        sessions: h.sessions,
        followLagMs: Math.round(lag),
        node: node.memory(),
        pool,
        agents: perAgent,
        mismatchesSoFar: mismatches,
      });
      for (const a of agents) a.saveKeys();
      if (mismatches > 0)
        throw new Error(
          `${mismatches} mismatches after "${label}" (see mismatches.jsonl); stopping`,
        );
    };

    /** Refuse to send above the gas price ceiling or past the spend cap. */
    const guard = async () => {
      const fee = await withRetry("fee data", () => provider.getFeeData());
      const price = fee.gasPrice ?? 0n;
      if (price > MAX_GAS_PRICE)
        throw new Error(
          `live gas price ${price} wei is above the ceiling ${MAX_GAS_PRICE}; stopping the wave`,
        );
      const spent = await spentNow();
      if (spent > SPEND_CAP)
        throw new Error(
          `the run has spent ${spent} wei, past the cap ${SPEND_CAP}; stopping`,
        );
    };

    /** One real transaction by `agent`. */
    const tx = async (
      agent: FujiAgent,
      kind: string,
      detail: Record<string, unknown>,
      send: (o?: { gasLimit: number }) => Promise<ContractTransactionResponse>,
      staticCall?: () => Promise<unknown>,
    ) => {
      await guard();
      step += 1;
      const t0 = performance.now();
      const resp = await send();
      const receipt = (await resp.wait())!;
      if (receipt.status !== 1)
        throw new Error(`${agent.name} ${kind}: ${receipt.hash} reverted`);
      txOk += 1;
      count(agent.name, kind);
      if (staticCall)
        lastProofs.set(agent.name, { kind, call: send, staticCall });
      jsonl("transactions.jsonl", {
        wave: WAVE,
        step,
        at: new Date().toISOString(),
        ok: true,
        agent: agent.name,
        strategy: agent.strategy,
        kind,
        ...detail,
        tx: receipt.hash,
        blockNumber: receipt.blockNumber,
        gasUsed: receipt.gasUsed,
        gasPrice: receipt.gasPrice,
        sendMs: Math.round(performance.now() - t0),
      });
      await verify(`${agent.name} ${kind}`, {
        tx: receipt.hash,
        kind,
        agent: agent.name,
      });
    };

    /** An approval: counted per wallet, not graded on its own (the transaction it enables is). */
    const approve = async (
      a: FujiAgent,
      asset: string,
      spender: string,
      value: bigint,
    ) => {
      await guard();
      const r = (await (
        await erc(asset).connect(a.signer).approve(spender, value)
      ).wait())!;
      count(a.name, "approve");
      jsonl("transactions.jsonl", {
        wave: WAVE,
        step,
        at: new Date().toISOString(),
        ok: true,
        agent: a.name,
        kind: "approve",
        asset: LABEL[asset],
        value,
        tx: r.hash,
        gasUsed: r.gasUsed,
        gasPrice: r.gasPrice,
      });
    };

    /** A cheat: the pool must refuse it, on chain, with the named error, and nothing may change. */
    const cheat = async (
      agent: FujiAgent,
      kind: string,
      expected: string,
      call: (overrides: {
        gasLimit: number;
      }) => Promise<ContractTransactionResponse>,
      staticCall: () => Promise<unknown>,
    ) => {
      await guard();
      step += 1;
      cheatsUsed += 1;
      const leavesBefore = await darkPool.getNextLeafIndex();
      let reason = "none";
      try {
        await staticCall();
        reason = "ACCEPTED";
      } catch (e: unknown) {
        const err = e as {
          data?: string;
          error?: { data?: string };
          info?: { error?: { data?: string } };
          shortMessage?: string;
        };
        const data = err?.data ?? err?.error?.data ?? err?.info?.error?.data;
        const verifierError =
          typeof data === "string"
            ? VERIFIER_ERRORS[data.slice(0, 10).toLowerCase()]
            : undefined;
        if (verifierError !== undefined) reason = verifierError;
        else
          try {
            reason =
              darkPool.interface.parseError(data ?? "0x")?.name ?? "unknown";
          } catch {
            try {
              reason =
                adaptor.interface.parseError(data ?? "0x")?.name ?? "unknown";
            } catch {
              reason = err?.shortMessage ?? String(e);
            }
          }
      }
      // and mined: the reverted transaction is on chain and leaves no note behind
      let status = -1;
      let hash = "";
      try {
        const resp = await call({ gasLimit: CHEAT_GAS_LIMIT });
        hash = resp.hash;
        const rr = await provider.waitForTransaction(resp.hash);
        status = rr ? Number(rr.status) : -1;
      } catch (e: unknown) {
        const err = e as { receipt?: { status: number; hash: string } };
        status = err?.receipt ? Number(err.receipt.status) : 0;
        hash = err?.receipt?.hash ?? hash;
      }
      const leavesAfter = await darkPool.getNextLeafIndex();
      const matches =
        expected === "ProofRejected"
          ? PROOF_REJECTED.has(reason)
          : reason === expected;
      const ok =
        matches && status === 0 && leavesAfter === leavesBefore && hash !== "";
      txRejected += 1;
      count(agent.name, `cheat: ${kind}`);
      jsonl("transactions.jsonl", {
        wave: WAVE,
        step,
        at: new Date().toISOString(),
        ok: false,
        agent: agent.name,
        strategy: agent.strategy,
        kind: `cheat: ${kind}`,
        expected,
        reason,
        minedStatus: status,
        tx: hash,
        asExpected: ok,
      });
      if (!ok)
        mismatch({
          label: `cheat ${kind}`,
          agent: agent.name,
          expected,
          reason,
          minedStatus: status,
        });
      await verify(`${agent.name} cheat ${kind}`, {
        cheat: kind,
        reason,
        asExpected: ok,
      });
    };

    const amount = (asset: string, lo: number, hi: number) =>
      BigInt(randInt(lo, hi)) * UNIT[asset]!;
    const minNote = (asset: string) => 2n * UNIT[asset]!;

    // ------------------------------------------------------------ actions
    const deposit = async (a: FujiAgent, asset: string, value: bigint) => {
      const proof = await a.proveDeposit(value, asset);
      await approve(a, asset, poolAddr, value);
      movePublic(a.address, asset, -value);
      await tx(a, "deposit", { asset: LABEL[asset], value }, () =>
        a.darkPool.deposit(proof.proof, proof.publicInputs),
      );
    };
    const withdraw = async (
      a: FujiAgent,
      asset: string,
      to: FujiAgent,
      share: [number, number] = [10, 90],
    ) => {
      const n = a.pick(asset, minNote(asset));
      const value = (n.note.value * BigInt(randInt(share[0], share[1]))) / 100n;
      const proof = await a.proveWithdraw(n, value, to.address);
      movePublic(to.address, asset, value);
      await tx(
        a,
        "withdraw",
        { asset: LABEL[asset], value, from: n.leafIndex, to: to.name },
        (o) => a.darkPool.withdraw(proof.proof, proof.publicInputs, o ?? {}),
        () => a.darkPool.withdraw.staticCall(proof.proof, proof.publicInputs),
      );
      return proof;
    };
    const addressBook = new Map<string, { inPub: Point<bigint> }[]>();
    const transfer = async (
      a: FujiAgent,
      asset: string,
      to: FujiAgent,
      share: [number, number] = [10, 90],
    ) => {
      const n = a.pick(asset, minNote(asset));
      const value = (n.note.value * BigInt(randInt(share[0], share[1]))) / 100n;
      // the recipient hands out a fresh address, or the sender reuses one it was given before
      const book = addressBook.get(`${a.name}->${to.name}`) ?? [];
      const reuse = book.length > 0 && rand() < 0.4;
      const addr = reuse ? pickOne(book) : await to.receiveAddress();
      if (!reuse) addressBook.set(`${a.name}->${to.name}`, [...book, addr]);
      const proof = await a.proveTransfer(n, value, addr.inPub);
      await tx(
        a,
        to === a ? "hop" : "transfer",
        {
          asset: LABEL[asset],
          value,
          from: n.leafIndex,
          to: to.name,
          reusedAddress: reuse,
        },
        (o) =>
          a.darkPool.privateTransfer(proof.proof, proof.publicInputs, o ?? {}),
        () =>
          a.darkPool.privateTransfer.staticCall(
            proof.proof,
            proof.publicInputs,
          ),
      );
    };
    const split = async (a: FujiAgent, asset: string) => {
      const n = a.pick(asset, minNote(asset));
      const first = (n.note.value * BigInt(randInt(20, 80))) / 100n;
      const proof = await a.proveSplit(n, first);
      await tx(
        a,
        "split",
        {
          asset: LABEL[asset],
          from: n.leafIndex,
          value1: first,
          value2: n.note.value - first,
        },
        (o) => a.darkPool.split(proof.proof, proof.publicInputs, o ?? {}),
        () => a.darkPool.split.staticCall(proof.proof, proof.publicInputs),
      );
    };
    const joinNotes = async (a: FujiAgent, asset: string) => {
      const [x, y] = shuffle([...a.unspent(asset)])
        .slice(0, 2)
        .sort((p, q) => p.leafIndex - q.leafIndex);
      const proof = await a.proveJoin(x!, y!);
      await tx(
        a,
        "join",
        { asset: LABEL[asset], from: [x!.leafIndex, y!.leafIndex] },
        (o) => a.darkPool.join(proof.proof, proof.publicInputs, o ?? {}),
        () => a.darkPool.join.staticCall(proof.proof, proof.publicInputs),
      );
    };
    const swap = async (a: FujiAgent, assetIn: string) => {
      const assetOut = assetIn === assetDai ? assetWeth : assetDai;
      const n = a.pick(assetIn, minNote(assetIn));
      const amountIn = (n.note.value * BigInt(randInt(20, 70))) / 100n;
      const owner = await a.publicAddress();
      const salt = BigInt(ethers.hexlify(ethers.randomBytes(16)));
      const deadline =
        BigInt((await provider.getBlock("latest"))!.timestamp) + 600n;
      const intentHash = await hashUniswapIntent(
        {
          type: SwapType.ExactInputSingle,
          assetIn,
          assetOut,
          fee: 3000,
          recipient: { ownerX: owner[0], ownerY: owner[1] },
          amountOutMin: amountIn,
          salt,
        },
        deadline,
      );
      const proof = await a.proveWithdraw(
        n,
        amountIn,
        venue.adaptor,
        intentHash,
      );
      const encoded = ethers.AbiCoder.defaultAbiCoder().encode(
        [
          "tuple(address assetIn,address assetOut,uint24 fee,tuple(uint256 ownerX,uint256 ownerY) recipient,uint256 amountOutMin,uint256 salt)",
        ],
        [[assetIn, assetOut, 3000, [owner[0], owner[1]], amountIn, salt]],
      );
      await tx(
        a,
        "swap",
        {
          assetIn: LABEL[assetIn],
          assetOut: LABEL[assetOut],
          amountIn,
          from: n.leafIndex,
        },
        () =>
          adaptor
            .connect(a.signer)
            .executeSwap(proof.proof, proof.publicInputs, 0, encoded, deadline),
      );
    };
    const publicTransfer = async (
      a: FujiAgent,
      to: FujiAgent,
      asset: string,
      value: bigint,
    ) => {
      const owner = await to.publicAddress();
      const salt = BigInt(ethers.hexlify(ethers.randomBytes(16)));
      await approve(a, asset, poolAddr, value);
      movePublic(a.address, asset, -value);
      await tx(
        a,
        "publicTransfer",
        { asset: LABEL[asset], value, to: to.name },
        () =>
          a.darkPool.publicTransfer(owner[0], owner[1], asset, value, 0, salt),
      );
    };
    const claimAll = async (a: FujiAgent) => {
      const memos = (await a.publicMemos()).filter(
        (m) => m.claimable && !m.spent,
      );
      for (const m of memos) {
        const proof = await a.proveClaim(m);
        await tx(
          a,
          "publicClaim",
          {
            asset: LABEL[ethers.getAddress(m.asset)] ?? m.asset,
            value: m.value,
            memo: m.memoId.toString(),
          },
          (o) =>
            a.darkPool.publicClaim(proof.proof, proof.publicInputs, o ?? {}),
          () =>
            a.darkPool.publicClaim.staticCall(proof.proof, proof.publicInputs),
        );
      }
      return memos.length;
    };

    // ------------------------------------------------------------ the cheater's repertoire, capped across the run
    const cheats = [
      "replayOwn",
      "doubleSpend",
      "phantomNote",
      "tamperValue",
      "tamperRecipient",
      "replayOthersClaim",
    ] as const;
    const doCheat = async (bob: FujiAgent): Promise<boolean> => {
      if (cheatsUsed >= MAX_CHEATS) return false;
      const which = cheats[cheatsUsed % cheats.length]!;
      if (which === "replayOwn") {
        const last = lastProofs.get(bob.name);
        if (!last) return false;
        const expected =
          last.kind === "publicClaim" ? "MemoSpent" : "NullifierAlreadySpent";
        await cheat(
          bob,
          `replay ${last.kind}`,
          expected,
          (o) => last.call(o),
          last.staticCall,
        );
        return true;
      }
      if (which === "doubleSpend") {
        const spent = bob.spentNotes().filter((n) => n.asset === assetDai);
        if (spent.length === 0) return false;
        const n = pickOne(spent);
        const proof = await bob.proveWithdraw(
          n,
          n.note.value / 2n,
          bob.address,
        );
        await cheat(
          bob,
          "double spend",
          "NullifierAlreadySpent",
          (o) => bob.darkPool.withdraw(proof.proof, proof.publicInputs, o),
          () =>
            bob.darkPool.withdraw.staticCall(proof.proof, proof.publicInputs),
        );
        return true;
      }
      if (which === "phantomNote") {
        // a note that was never deposited, proven against a tree only bob has
        const tree = await newSeededTree(network.chainId);
        for (let i = 1; i < Number(await darkPool.getNextLeafIndex()); i++)
          await tree.insert(new Fr(BigInt(i) * 7919n));
        const spend = await userSpendScalar(bob.address);
        const eph = evenYEphemeral(
          BigInt(ethers.hexlify(ethers.randomBytes(8))),
        );
        const fake = await mintSelfNote(
          eph,
          2n * 10n ** 21n,
          spend,
          addressToFr(assetDai),
          domain.compliancePk,
          toFr(0n),
        );
        await tree.insert(fake.commitment);
        const index = tree.nextLeafIndex - 1;
        const changeEph = evenYEphemeral(
          BigInt(ethers.hexlify(ethers.randomBytes(8))),
        );
        const change = await mintSelfNote(
          changeEph,
          10n ** 21n,
          spend,
          addressToFr(assetDai),
          domain.compliancePk,
          packParents([{ leafIndex: index }, { leafIndex: 0 }]),
        );
        const proof = await proveWithdraw({
          withdrawValue: toFr(10n ** 21n),
          recipient: addressToFr(bob.address),
          intentHash: toFr(0n),
          compliancePk: domain.compliancePk,
          oldNote: fake.note,
          spendScalar: spend,
          oldNoteIndex: index,
          oldNotePath: tree.getMerklePath(index),
          changeNote: change.note,
          changeEph,
        });
        await cheat(
          bob,
          "phantom note withdraw",
          "InvalidRoot",
          (o) => bob.darkPool.withdraw(proof.proof, proof.publicInputs, o),
          () =>
            bob.darkPool.withdraw.staticCall(proof.proof, proof.publicInputs),
        );
        return true;
      }
      if (which === "tamperValue" || which === "tamperRecipient") {
        const u = bob
          .unspent(assetDai)
          .filter((n) => n.note.value >= 4n * UNIT[assetDai]!);
        if (u.length === 0) return false;
        const n = u[0]!;
        const proof: ProofData = await bob.proveWithdraw(
          n,
          n.note.value / 4n,
          bob.address,
        );
        const pi = [...proof.publicInputs];
        if (which === "tamperValue")
          pi[0] = ethers.toBeHex(BigInt(pi[0]!) * 4n, 32);
        else pi[1] = ethers.zeroPadValue(byName.get("alice")!.address, 32);
        await cheat(
          bob,
          which === "tamperValue"
            ? "withdraw with inflated value"
            : "withdraw redirected to another recipient",
          "ProofRejected",
          (o) => bob.darkPool.withdraw(proof.proof, pi, o),
          () => bob.darkPool.withdraw.staticCall(proof.proof, pi),
        );
        return true;
      }
      // replay another wallet's public claim
      const theirs = [...lastProofs.entries()].find(
        ([who, p]) => who !== bob.name && p.kind === "publicClaim",
      );
      if (!theirs) return false;
      await cheat(
        bob,
        "replay another wallet's claim",
        "MemoSpent",
        (o) => theirs[1].call(o),
        theirs[1].staticCall,
      );
      return true;
    };

    // ------------------------------------------------------------ habits
    const others = (a: FujiAgent) => agents.filter((x) => x !== a);
    const can = (a: FujiAgent, asset: string, n = 1) =>
      a.unspent(asset).filter((x) => x.note.value >= minNote(asset)).length >=
      n;

    const act = async (a: FujiAgent) => {
      const hasD = can(a, assetDai);
      const hasW = can(a, assetWeth);
      const hasU = can(a, assetUsdc);
      let choice: string;
      switch (a.strategy) {
        case "greedy": // hoards: deposits, consolidates, cashes out to itself, trades
          choice = weighted({
            deposit: hasD ? 2 : 10,
            join: a.unspent(assetDai).length >= 2 ? 4 : 0,
            withdrawSelf: hasD ? 2 : 0,
            split: hasD ? 1 : 0,
            swap: hasD ? 1 : 0,
            claim: 1,
            joinW: a.unspent(assetWeth).length >= 2 ? 2 : 0,
          });
          break;
        case "cheater": // legitimate business, and an attempt to cheat on most turns until the cap
          if (rand() < 0.6 && (await doCheat(a))) return;
          choice = weighted({
            deposit: hasD ? 1 : 10,
            transfer: hasD ? 3 : 0,
            split: hasD ? 2 : 0,
            withdrawSelf: hasD ? 1 : 0,
            claim: 1,
          });
          break;
        case "donor": // gives privately to the others
          choice = weighted({
            deposit: hasD ? 1 : 10,
            transfer: hasD ? 6 : 0,
            split: hasD ? 2 : 0,
            publicTransfer: 1,
            claim: 1,
          });
          break;
        case "philanthropist": // gives to everyone, in private and in public
          choice = weighted({
            deposit: hasD ? 1 : 8,
            transfer: hasD ? 4 : 0,
            withdrawOther: hasD ? 3 : 0,
            publicTransfer: 2,
            claim: 1,
          });
          break;
        case "trader": // swaps both ways, claims the outputs, rearranges notes
          choice = weighted({
            deposit: hasD ? 1 : 8,
            swap: hasD ? 4 : 0,
            swapBack: hasW ? 3 : 0,
            claim: 4,
            split: hasD ? 1 : 0,
            join: a.unspent(assetDai).length >= 2 ? 1 : 0,
            transferW: hasW ? 1 : 0,
          });
          break;
        case "whale": // large deposits, rare and patient moves
          choice = weighted({
            depositLarge: hasD ? 2 : 6,
            depositLargeUsdc: hasU ? 1 : 4,
            splitLarge: hasD ? 2 : 0,
            withdrawPatient: hasD ? 1 : 0,
            transferLarge: hasD ? 1 : 0,
            claim: 1,
          });
          break;
        default: // privacy: small amounts, many hops through its own fresh addresses, splits and joins
          choice = weighted({
            depositSmall: hasD ? 1 : 6,
            hop: hasD ? 5 : 0,
            split: hasD ? 3 : 0,
            join: a.unspent(assetDai).length >= 2 ? 3 : 0,
            withdrawSmall: hasD ? 1 : 0,
            claim: 1,
          });
      }
      switch (choice) {
        case "deposit":
          return deposit(a, assetDai, amount(assetDai, 500, 5000));
        case "depositLarge":
          return deposit(a, assetDai, amount(assetDai, 200_000, 1_000_000));
        case "depositLargeUsdc":
          return deposit(a, assetUsdc, amount(assetUsdc, 200_000, 1_000_000));
        case "depositSmall":
          return deposit(a, assetDai, amount(assetDai, 20, 150));
        case "join":
          return joinNotes(a, assetDai);
        case "joinW":
          return joinNotes(a, assetWeth);
        case "split":
        case "splitLarge":
          return split(a, assetDai);
        case "withdrawSelf":
          return void (await withdraw(a, assetDai, a));
        case "withdrawPatient":
          return void (await withdraw(a, assetDai, a, [5, 20]));
        case "withdrawSmall":
          return void (await withdraw(a, assetDai, a, [5, 30]));
        case "withdrawOther":
          return void (await withdraw(a, assetDai, pickOne(others(a))));
        case "transfer":
          return transfer(a, assetDai, pickOne(others(a)));
        case "transferLarge":
          return transfer(a, assetDai, pickOne(others(a)), [10, 40]);
        case "transferW":
          return transfer(a, assetWeth, pickOne(others(a)));
        case "hop":
          return transfer(a, assetDai, a, [30, 95]);
        case "swap":
          return swap(a, assetDai);
        case "swapBack":
          return swap(a, assetWeth);
        case "publicTransfer":
          return publicTransfer(
            a,
            pickOne(others(a)),
            assetDai,
            amount(assetDai, 100, 1000),
          );
        case "claim":
          if ((await claimAll(a)) === 0)
            return deposit(a, assetDai, amount(assetDai, 500, 5000));
          return;
      }
    };

    // ------------------------------------------------------------ run the wave
    const pauseMs = (p: Persona) =>
      randInt(p.pause[0], p.pause[1]) * 1000 * PACE;
    const t0 = Date.now();
    let failure: unknown = null;
    try {
      await verify(`wave ${WAVE} start`, { wave: WAVE });
      // a wallet with nothing in the pool starts with a deposit
      for (const a of agents)
        if (a.unspent(assetDai).length === 0)
          await deposit(
            a,
            assetDai,
            a.strategy === "whale"
              ? amount(assetDai, 200_000, 1_000_000)
              : amount(assetDai, 500, 5000),
          );

      const due = new Map<string, number>(
        ROSTER.map((p) => [p.name, Date.now() + pauseMs(p) * rand()]),
      );
      let actions = 0;
      while (Date.now() - t0 < WAVE_MS && actions < MAX_ACTIONS) {
        const [name, at] = [...due.entries()].sort((x, y) => x[1] - y[1])[0]!;
        const wait = at - Date.now();
        if (wait > 0) {
          if (Date.now() + wait - t0 >= WAVE_MS) break;
          await new Promise((r) => setTimeout(r, wait));
        }
        const a = byName.get(name)!;
        try {
          await act(a);
        } catch (e: unknown) {
          jsonl("errors.jsonl", {
            wave: WAVE,
            step,
            agent: a.name,
            error: String((e as Error)?.stack ?? e),
          });
          throw e;
        }
        actions += 1;
        due.set(
          name,
          Date.now() + pauseMs(ROSTER.find((p) => p.name === name)!),
        );
      }
      // the last wave claims what is left, so the books close with no memo outstanding
      if (FINAL) for (const a of agents) await claimAll(a);
    } catch (e: unknown) {
      failure = e;
    } finally {
      await node.stop();
      for (const s of sources) s.close();
    }

    // ------------------------------------------------------------ summary
    const q = (xs: number[], p: number) => {
      const s = [...xs].sort((x, y) => x - y);
      return s.length === 0
        ? 0
        : s[Math.min(s.length - 1, Math.floor(p * (s.length - 1)))]!;
    };
    const witnesses = agents.flatMap((a) => a.witnesses);
    const spent = await spentNow();
    const summary = {
      wave: WAVE,
      seed: SEED,
      pace: PACE,
      steps: step,
      transactions: txOk,
      rejected: txRejected,
      byAgent: kinds,
      cheatsUsedInRun: cheatsUsed,
      mismatches,
      failure:
        failure === null
          ? null
          : String((failure as Error)?.message ?? failure),
      plantDropFeedLeaf: PLANT_DROP_LEAF < 0 ? null : PLANT_DROP_LEAF,
      plantHits,
      notesPerAgent: Object.fromEntries(
        agents.map((a) => [a.name, a.found().length]),
      ),
      spendsWithRavenPaths: witnesses.length,
      witnessesAllKnownRoots: witnesses.every(
        (w) => w.knownRoot && w.chainRootAtCount,
      ),
      finalLeaves: Number(
        await withRetry("leaf count", () => darkPool.getNextLeafIndex()),
      ),
      readiness: {
        samples: readiness.length,
        ready200: readiness.filter((r) => r.status === 200).length,
        statuses: [...new Set(readiness.map((r) => r.status))],
      },
      followLagMs: {
        p50: Math.round(q(followLagMs, 0.5)),
        p95: Math.round(q(followLagMs, 0.95)),
        max: Math.round(Math.max(0, ...followLagMs)),
      },
      walletDiscoveryMs: {
        p50: Math.round(q(discoveryMs, 0.5)),
        p95: Math.round(q(discoveryMs, 0.95)),
        max: Math.round(Math.max(0, ...discoveryMs)),
      },
      routes: Object.fromEntries(
        [...new Set(routeSamples.map((r) => `${r.method} ${r.route}`))].map(
          (key) => {
            const xs = routeSamples.filter(
              (r) => `${r.method} ${r.route}` === key,
            );
            const ms = xs.map((r) => r.ms);
            return [
              key,
              {
                n: xs.length,
                p50: +q(ms, 0.5).toFixed(1),
                p95: +q(ms, 0.95).toFixed(1),
                statuses: [...new Set(xs.map((r) => r.status))],
              },
            ];
          },
        ),
      ),
      spentWeiInRun: spent,
      wallSeconds: Math.round((Date.now() - t0) / 1000),
    };
    writeFileSync(join(OUT, "summary.json"), stringify(summary, 2));
    const next: RunState = {
      wavesDone: failure === null ? run.wavesDone + 1 : run.wavesDone,
      cheatsUsed,
      spentWei: spent.toString(),
      transactions: run.transactions + txOk,
      mismatches: run.mismatches + mismatches,
    };
    writeAtomic(RUN_FILE, stringify(next, 2));

    if (failure !== null) throw failure;
    expect(mismatches, "mismatches (see mismatches.jsonl)").to.equal(0);
    expect(txOk).to.be.greaterThan(0);
  });
});
