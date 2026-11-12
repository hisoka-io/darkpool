// Smoke checks on the deployed Fuji pool of the two flows the persona simulation does not run: a Kage swap and a
// FROST t-of-n multisig spend, with a Raven Howl node following Fuji.
//
// Kage: the taker is a Raven-backed wallet. It proves swap_intent on Raven's path at a leaf count it picks and
// attaches that count to the off-chain order as a hint. The maker is a solver registered and staked in the pool's
// KageRegistry: it keeps its own full tree from the pool's logs (it never reads Raven), resolves the intent's root to
// a count from its own index, refuses an order whose hint disagrees, builds its own path at that count, and settles
// through KageSettlement with an EIP-712 approval from its registered signer.
//
// Multisig: discovery runs a harness-side scanner over Raven cells. The coordinator carries (leafIndex, leafCount,
// root) in the signing session and every signer re-folds its own Raven path to that root before it commits. Both note
// families are found (self mints and transfers to the group's receiving addresses), including notes past the first
// window that only the gap-limit growth reaches.
//
// Ported from Raven's adapters/howl-node/e2e RavenKageMultisig for the deployed pool: it attaches to the recorded
// deployment, uses its compliance key and chain id, reads logs in windows the endpoint accepts, and spends the
// agents' pre-funded test tokens instead of minting.
//
// Environment: SIM_OUT_DIR, SIM_RPC_URL, SIM_NODE_RPC_URL (optional), SIM_RECORD, SIM_TOKENS, SIM_AGENTS,
// SIM_NODE_PORT, SIM_NODE_DATA (a node data directory to continue from), SIM_LOG_MAX_BLOCKS, HOWL_NODE_BIN,
// RAVEN_SDK, RAVEN_WASM; optional SIM_KAGE_SWAPS (1: only the older-root swap; default 2), SIM_SKIP_KAGE,
// SIM_SKIP_MULTISIG.
import { expect } from "chai";
import { ethers } from "ethers";
import { spawn, type ChildProcess } from "node:child_process";
import {
  appendFileSync,
  cpSync,
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { createRequire } from "node:module";
import { join } from "node:path";
import {
  Fr,
  toFr,
  addressToFr,
  computePsi,
  deriveCek,
  demDecrypt,
  reconstructCiphertext,
  recoverEvenY,
  isEvenY,
  leaf as computeLeaf,
  packParents,
  PARENTS_HIDDEN,
  LeanIMT,
  publicKey,
  type HowlNoteRecord,
} from "@hisoka/wallets";
import * as frost from "@hisoka/wallets/frost";
import { frostAccountDkg } from "@hisoka/wallets/unsafe-sim";
import { InMemoryEphemeralCounterStore } from "@hisoka/wallets/reference";
import {
  proveDeposit,
  proveSwapIntent,
  proveSwapSettle,
  proveTransfer,
  proveWithdrawMultisig,
  proveSplitMultisig,
  proveJoinMultisig,
  proveTransferMultisig,
  type SwapIntentProof,
} from "@hisoka/prover";
import type { Point } from "@zk-kit/baby-jubjub";
import {
  evenYEphemeral,
  mintIncomingMultisigNote as fixtureIncomingMultisigNote,
  mintIncomingNote as fixtureIncomingNote,
  mintSelfNote as fixtureSelfNote,
  noteToInput,
  userSpendScalar,
} from "../helpers/fixtures";
import { buildMultisigNote as fixtureMultisigNote } from "../helpers/frostMultisig";
import { signSettlement } from "../kage/kageFixtures";
import {
  FujiAgent,
  poolDomain,
  useRavenPorts,
  type FoundNote,
  type RavenPorts,
  type RavenSource,
} from "./fujiAgent";
import { CountingNonceWallet } from "./nonceWallet";
import { PoolLogs, withRetry } from "./poolLogs";
import {
  DarkPool__factory,
  IERC20__factory,
  KageRegistry__factory,
  KageSettlement__factory,
  type DarkPool,
  type IERC20,
} from "../../typechain-types";

const env = (k: string): string => {
  const v = process.env[k];
  if (v === undefined || v === "") throw new Error(`${k} is required`);
  return v;
};
const OUT = env("SIM_OUT_DIR");
const PARAM_SET = process.env.SIM_PARAM_SET ?? "";
const KAGE_SWAPS = Number(process.env.SIM_KAGE_SWAPS ?? "2");
const LEAF_INSERTED = ethers.id("LeafInserted(uint256,bytes32,bytes32)");
const ROOT_SAVED = ethers.id("RootSaved(bytes32)");
const SCAN_WINDOW = 16;
const LOG_MAX_BLOCKS = Number(env("SIM_LOG_MAX_BLOCKS"));
const NODE_FOLLOW_MS = 600_000;

// The deployed pool's compliance key, read from the pool before anything is minted. The fixture helpers default to
// the test key, so every mint here passes this one.
let COMPLIANCE_PK: Point<bigint>;
const mintSelfNote = (
  eph: Parameters<typeof fixtureSelfNote>[0],
  value: bigint,
  spend: Fr,
  asset: Fr,
  parents: Fr = toFr(0n),
) => fixtureSelfNote(eph, value, spend, asset, parents, COMPLIANCE_PK);
const mintIncomingNote = (
  eph: Fr,
  value: bigint,
  inPub: Point<bigint>,
  inKey: Fr,
  asset: Fr,
  parents: Fr = toFr(0n),
) =>
  fixtureIncomingNote(eph, value, inPub, inKey, asset, parents, COMPLIANCE_PK);
const mintIncomingMultisigNote = (
  eph: Fr,
  value: bigint,
  gpk: Point<bigint>,
  v: Fr,
  asset: Fr,
  parents: Fr = toFr(0n),
) =>
  fixtureIncomingMultisigNote(
    eph,
    value,
    gpk,
    v,
    asset,
    parents,
    COMPLIANCE_PK,
  );
const buildMultisigNote = (
  eph: Fr,
  value: bigint,
  owner: Fr,
  asset: Fr,
  parents: Fr,
) => fixtureMultisigNote(eph, value, owner, asset, parents, COMPLIANCE_PK);

const log = (row: Record<string, unknown>) => {
  const line = JSON.stringify(
    { t: new Date().toISOString(), ...row },
    (_, v) => (typeof v === "bigint" ? v.toString() : v),
  );
  appendFileSync(join(OUT, "steps.jsonl"), line + "\n");
  console.log(line);
};
const hex = (v: bigint | Fr) =>
  "0x" +
  (typeof v === "bigint" ? v : v.toBigInt()).toString(16).padStart(64, "0");

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
      ...(PARAM_SET === "" ? [] : ["--param-set", PARAM_SET]),
    ];
    this.proc = spawn(this.bin, args, {
      env: { ...process.env, HOWL_NODE_RPC_URL: this.rpc, RUST_LOG: "info" },
      stdio: ["ignore", "pipe", "pipe"],
    });
    const f = join(OUT, "node.log");
    this.proc.stdout!.on("data", (d) => appendFileSync(f, d));
    this.proc.stderr!.on("data", (d) => appendFileSync(f, d));
  }
  async stop() {
    if (this.proc && this.proc.exitCode === null) {
      const p = this.proc;
      p.kill("SIGINT");
      await new Promise((r) => p.once("exit", r));
    }
    this.proc = null;
  }
  async leaves(): Promise<number | null> {
    try {
      const r = await fetch(`${this.url}/howl/v1/health`);
      if (r.status !== 200) return null;
      const m = /leaves=(\d+)/.exec(await r.text());
      return m ? Number(m[1]) : null;
    } catch {
      return null;
    }
  }
}

/** The solver's own index of the pool: every leaf and root from the chain's logs, never Raven. */
class SolverIndex {
  leaves: string[] = [];
  countOfRoot = new Map<string, number>();
  rootsSaved = new Set<string>();
  constructor(readonly logs: PoolLogs) {}
  async refresh() {
    await this.logs.refresh();
    const ins = this.logs.byTopic(LEAF_INSERTED);
    const saved = this.logs.byTopic(ROOT_SAVED);
    this.leaves = [];
    this.countOfRoot = new Map();
    for (const l of ins) {
      const i = Number(BigInt(l.topics[1]!));
      if (i !== this.leaves.length)
        throw new Error(
          `solver index: leaf ${i} arrived at ${this.leaves.length}`,
        );
      this.leaves.push("0x" + l.data.slice(2, 66));
      // count = leafIndex + 1: the root a LeafInserted carries is the root after that leaf
      this.countOfRoot.set(
        BigInt("0x" + l.data.slice(66, 130)).toString(),
        i + 1,
      );
    }
    this.rootsSaved = new Set(
      saved.map((l) => BigInt(l.topics[1]!).toString()),
    );
    // every insert saves its root once, so the two logs must describe the same set
    if (this.rootsSaved.size !== this.countOfRoot.size)
      throw new Error(
        "solver index: RootSaved and LeafInserted disagree in size",
      );
    for (const r of this.countOfRoot.keys())
      if (!this.rootsSaved.has(r))
        throw new Error(`solver index: root ${r} has no RootSaved`);
  }
  async treeAt(count: number): Promise<LeanIMT> {
    const t = new LeanIMT(32);
    for (let i = 0; i < count; i++)
      await t.insert(new Fr(BigInt(this.leaves[i]!)));
    return t;
  }
  /** The latest leaf holding `commitment`: a persistent chain can hold the same commitment from an earlier run. */
  indexOf(commitment: Fr): number {
    const want = commitment.toBigInt();
    for (let i = this.leaves.length - 1; i >= 0; i--)
      if (BigInt(this.leaves[i]!) === want) return i;
    return -1;
  }
}

interface MakerNote {
  built: Awaited<ReturnType<typeof mintSelfNote>>;
  leafIndex: number;
  spent: boolean;
}

interface Order {
  intent: SwapIntentProof;
  /** The count the taker proved at; a hint the solver checks, never trusts. */
  leafCountHint: number;
}

class KageSolver {
  notes: MakerNote[] = [];
  // a random start per run: the maker's spend key is fixed by its address, so a fixed seed re-mints the same notes
  // on a chain that keeps every earlier run's leaves
  seed = BigInt(ethers.hexlify(ethers.randomBytes(16)));
  /** A fresh even-y ephemeral: evenYEphemeral rolls forward, so neighbouring seeds can land on one scalar. */
  nextEph() {
    const e = evenYEphemeral(this.seed);
    this.seed = e.toBigInt() + 1n;
    return e;
  }
  constructor(
    readonly index: SolverIndex,
    readonly spendScalar: Fr,
  ) {}

  /** The count the intent was proved at, from the solver's own index; refuses a disagreeing hint. */
  resolve(order: Order): number {
    const root = BigInt(order.intent.publicInputs[1]!).toString();
    const count = this.index.countOfRoot.get(root);
    if (count === undefined)
      throw new Error(
        `refused: intent root ${hex(BigInt(root))} is not a root of this pool`,
      );
    if (count !== order.leafCountHint)
      throw new Error(
        `refused: the order says count ${order.leafCountHint}, the intent's root is the root at ${count}`,
      );
    return count;
  }

  async settle(order: Order, toAsset: Fr, timestamp: bigint) {
    await this.index.refresh();
    const count = this.resolve(order);
    const pi = order.intent.publicInputs;
    const expectedReturn = BigInt(pi[7]!);
    const fromAmount = BigInt(pi[6]!);
    const fromAsset = new Fr(BigInt(pi[4]!));
    // the maker's input must already be in the tree the intent was proved against
    const input = this.notes.find(
      (n) =>
        !n.spent &&
        n.leafIndex < count &&
        n.built.note.assetId.equals(toAsset) &&
        n.built.note.value.toBigInt() >= expectedReturn,
    );
    if (input === undefined)
      throw new Error(`no maker note older than count ${count}`);
    const tree = await this.index.treeAt(count);
    if (tree.getRoot().toBigInt() !== BigInt(pi[1]!))
      throw new Error(
        "solver tree at the resolved count does not fold to the intent root",
      );
    const parents = packParents([
      { leafIndex: input.leafIndex },
      { leafIndex: 0 },
    ]);
    const received = await mintSelfNote(
      this.nextEph(),
      fromAmount,
      this.spendScalar,
      fromAsset,
      parents,
    );
    const change = await mintSelfNote(
      this.nextEph(),
      input.built.note.value.toBigInt() - expectedReturn,
      this.spendScalar,
      toAsset,
      parents,
    );
    const t0 = Date.now();
    const settled = await proveSwapSettle({
      compliancePk: COMPLIANCE_PK,
      currentTimestamp: new Fr(timestamp),
      intent: order.intent,
      makerNoteIn: input.built.note,
      makerSpendScalar: this.spendScalar,
      makerIndex: input.leafIndex,
      makerPath: tree.getMerklePath(input.leafIndex),
      makerReceived: received.note,
      makerReceivedEph: received.eph,
      makerChange: change.note,
      makerChangeEph: change.eph,
    });
    return {
      settled,
      input,
      received,
      change,
      count,
      settleMs: Date.now() - t0,
    };
  }
}

const FIELD = {
  fromBytes: (b: Uint8Array) => Fr.fromBuffer(Buffer.from(b)),
  toBytes: (f: Fr) => new Uint8Array(f.toBuffer()),
};

/** A group note as a member's scan reports it. */
interface GroupNote {
  leafIndex: number;
  commitment: Fr;
  value: bigint;
  asset: bigint;
  nullifier: Fr;
  note: any;
  incoming: boolean;
  index: bigint;
}

/**
 * Multisig discovery through the package's MultisigRavenScan feeding Howl's own MultisigScanner, with
 * Howl's key functions as its hooks. `reach` stops tag derivation at that index: the planted control of
 * a scanner whose windows never grow past the first.
 */
class MultisigRavenScanner {
  lastRounds = 0;
  #scan: any = null;

  constructor(
    readonly sdk: any,
    readonly raven: RavenSource,
    readonly v: Fr,
    readonly gpk: Point<bigint>,
    readonly memberIds: bigint[],
    readonly reach = Infinity,
  ) {}

  async #make() {
    const { v, reach } = this;
    const owner = new Fr(await frost.multisigOwner(this.gpk as any));
    const scanner = await frost.MultisigScanner.create({
      v,
      gpk: this.gpk as any,
      compliancePk: COMPLIANCE_PK,
      memberIds: this.memberIds,
      selfWindow: SCAN_WINDOW,
      incomingWindow: SCAN_WINDOW,
    });
    return new this.sdk.MultisigRavenScan({
      source: this.raven,
      field: FIELD,
      scanner,
      memberIds: this.memberIds,
      selfWindow: SCAN_WINDOW,
      incomingWindow: SCAN_WINDOW,
      keys: {
        selfTag: async (memberId: bigint, j: bigint) => {
          if (Number(j) >= reach) return null;
          const { eph, ephPub } = await frost.deriveSelfEph(v, memberId, j);
          return isEvenY(ephPub as any)
            ? { tag: new Fr(ephPub[0]), secret: eph }
            : null;
        },
        incomingAt: async (from: bigint) => {
          const k = await frost.multisigIncomingKeyAt(v, from);
          return Number(k.index) >= reach
            ? { index: k.index, tag: new Fr(0n), secret: null }
            : { index: k.index, tag: new Fr(k.viewPub[0]), secret: k.viewKey };
        },
        open: async (record: HowlNoteRecord, src: any, secret: any) => {
          if (secret === null) return [];
          try {
            const cek =
              src.family === "self"
                ? deriveCek(secret, COMPLIANCE_PK)
                : await frost.memberReadIncoming(
                    record.cekWrap,
                    secret,
                    recoverEvenY(record.ephemeralPkX.toBigInt()) as any,
                  );
            const words = await reconstructCiphertext(record, cek, owner);
            const pt = await demDecrypt(cek, words);
            const commitment = await computeLeaf({
              noteVersion: pt[0],
              assetId: pt[1],
              noteType: pt[2],
              conditionsHash: pt[3],
              value: pt[4].toBigInt(),
              owner: pt[5],
              psi: await computePsi(cek),
              parents: pt[6],
            });
            return [{ words, commitment }];
          } catch {
            return [];
          }
        },
      },
    });
  }

  async scan(): Promise<GroupNote[]> {
    this.#scan ??= await this.#make();
    const r = await this.#scan.scan();
    this.lastRounds = r.rounds;
    return r.found.map((f: any) => ({
      leafIndex: f.leafIndex,
      commitment: f.view.commitment,
      value: f.view.note.value,
      asset: f.view.note.assetId.toBigInt(),
      nullifier: f.view.nullifier,
      note: f.view.note,
      incoming: f.view.isIncoming,
      index: f.source.family === "self" ? f.source.j : f.source.index,
    }));
  }
}

/** The package's session (leaf count, root, notes) and the FROST message the group signs over it. */
interface SigningSession {
  raven: {
    leafCount: number;
    root: Fr;
    notes: { leafIndex: number; leaf: Fr }[];
  };
  nullifiers: bigint[];
  message: bigint;
}

class Signer {
  #nonces: any = null;
  constructor(
    readonly id: bigint,
    readonly share: bigint,
    readonly sdk: any,
    readonly raven: RavenSource,
    readonly scanner: MultisigRavenScanner,
  ) {}

  /** Check the session against this signer's own scan and its own Raven path, then commit. */
  async round1(s: SigningSession) {
    const mine = new Map(
      (await this.scanner.scan()).map((n) => [n.leafIndex, n] as const),
    );
    s.raven.notes.forEach((note, k) => {
      const n = mine.get(note.leafIndex);
      if (n !== undefined && n.nullifier.toBigInt() !== s.nullifiers[k])
        throw new Error(
          `signer ${this.id} refused: the nullifier is not the note's`,
        );
    });
    try {
      await this.sdk.checkSigningSession(
        this.raven,
        FIELD,
        s.raven,
        new Map([...mine].map(([i, n]) => [i, n.commitment])),
      );
    } catch (e) {
      if ((e as Error).name !== "SigningSessionRefused") throw e;
      throw new Error(
        `signer ${this.id} refused (${(e as any).reason}): ${(e as Error).message}`,
      );
    }
    const { nonces, commitment } = await frost.commit(
      frost.bjjCiphersuite,
      this.id,
      this.share,
      crypto.getRandomValues(new Uint8Array(32)),
      crypto.getRandomValues(new Uint8Array(32)),
    );
    this.#nonces = nonces;
    return commitment;
  }

  async round2(s: SigningSession, gpk: Point<bigint>, commitments: any[]) {
    return frost.signShare(
      frost.bjjCiphersuite,
      this.id,
      this.#nonces,
      this.share,
      gpk as any,
      frost.encodeMessage(s.message),
      commitments,
    );
  }
}

/** One FROST signature by `quorum` over the session's message, every signer checking first. */
async function groupSign(
  quorum: Signer[],
  s: SigningSession,
  gpk: Point<bigint>,
  verificationKeys: Map<bigint, any>,
) {
  const commitments = [];
  for (const q of quorum) commitments.push(await q.round1(s));
  const partials = [];
  for (const q of quorum)
    partials.push({
      id: q.id,
      z: await q.round2(s, gpk, commitments),
      publicShare: verificationKeys.get(q.id)!,
    });
  const cs = frost.bjjCiphersuite;
  const msg = frost.encodeMessage(s.message);
  const R = frost.groupCommitment(
    cs,
    commitments,
    await frost.bindingFactors(cs, gpk as any, msg, commitments),
  );
  const sig = await frost.coordinatorAggregate(
    cs,
    R,
    gpk as any,
    msg,
    commitments,
    partials,
    quorum.length,
  );
  expect(await frost.verify(cs, gpk as any, msg, sig)).to.equal(true);
  return sig;
}

describe("Fuji smoke: Kage swap and FROST multisig on the deployed Howl pool", function () {
  this.timeout(0);
  let node: HowlNode;
  let provider: ethers.JsonRpcProvider;
  let chainId: bigint;
  let darkPool: DarkPool;
  let token: IERC20;
  let tokenB: IERC20;
  let poolAddr: string;
  let deployBlock: number;
  let poolLogs: PoolLogs;
  let domain: ReturnType<typeof poolDomain>;
  let record: {
    meta: { chainId: number; startBlock: number };
    contracts: {
      darkPool: string;
      kageRegistry: string;
      kageSettlement: string;
    };
  };
  let wallets: Record<string, CountingNonceWallet>;
  let sdk: any;
  let wasm: any;
  const summary: Record<string, unknown> = {};
  let mismatches = 0;

  const chainLeaves = async () => Number(await darkPool.getNextLeafIndex());
  const followed = async () => {
    const want = await chainLeaves();
    const t0 = Date.now();
    while ((await node.leaves()) !== want) {
      if (Date.now() - t0 > NODE_FOLLOW_MS)
        throw new Error(
          `node did not reach ${want} leaves within ${NODE_FOLLOW_MS} ms`,
        );
      await new Promise((r) => setTimeout(r, 500));
    }
    return want;
  };
  const source = (): RavenSource & { confirmNote: any } =>
    new sdk.RavenHowlSource({
      transport: sdk.fetchTransport(node.url, { timeoutMs: 120_000 }),
      wasm,
      field: {
        fromBytes: (b: Uint8Array) => Fr.fromBuffer(Buffer.from(b)),
        toBytes: (f: Fr) => new Uint8Array(f.toBuffer()),
      },
      keyMode: "session",
    });
  const rootAfter = async (count: number) => {
    await poolLogs.refresh();
    const l = poolLogs
      .byTopic(LEAF_INSERTED)
      .find((x) => Number(BigInt(x.topics[1]!)) === count - 1);
    return l === undefined ? undefined : "0x" + l.data.slice(66, 130);
  };
  const grade = async (who: string, a: FujiAgent) => {
    // the chain side reads the cached pool logs, so they reach the head before either side is read
    await poolLogs.refresh();
    await a.discover();
    const raven = a.found();
    const oracle = await a.oracle();
    const key = (n: FoundNote) =>
      `${n.leafIndex}:${n.commitment}:${n.value}:${n.asset}:${n.spent}`;
    const diff = [
      ...raven
        .filter((n) => !oracle.some((o) => key(o) === key(n)))
        .map((n) => ({ only: "raven", ...n })),
      ...oracle
        .filter((o) => !raven.some((n) => key(o) === key(n)))
        .map((o) => ({ only: "chain", ...o })),
    ];
    mismatches += diff.length;
    log({
      step: "grade",
      who,
      ravenNotes: raven.length,
      chainNotes: oracle.length,
      diff,
    });
    return raven;
  };

  before(async function () {
    rmSync(OUT, { recursive: true, force: true });
    mkdirSync(OUT, { recursive: true });
    const load = createRequire(__filename);
    sdk = load(env("RAVEN_SDK"));
    wasm = load(env("RAVEN_WASM"));
    useRavenPorts(sdk as RavenPorts);
    provider = new ethers.JsonRpcProvider(env("SIM_RPC_URL"), undefined, {
      staticNetwork: true,
      batchMaxCount: 1,
      cacheTimeout: -1,
    });
    chainId = (await withRetry("chain id", () => provider.getNetwork()))
      .chainId;
    record = JSON.parse(readFileSync(env("SIM_RECORD"), "utf8"));
    if (BigInt(record.meta.chainId) !== chainId)
      throw new Error(
        `the record is for chain ${record.meta.chainId}, the endpoint serves ${chainId}`,
      );
    const tokens = JSON.parse(readFileSync(env("SIM_TOKENS"), "utf8")) as {
      tokens: Record<string, { address: string }>;
    };
    if ((statSync(env("SIM_AGENTS")).mode & 0o077) !== 0)
      throw new Error("the agents key file must be mode 600");
    const keys = JSON.parse(readFileSync(env("SIM_AGENTS"), "utf8")) as {
      agents: Record<string, { address: string; privateKey: string }>;
    };
    wallets = Object.fromEntries(
      Object.entries(keys.agents).map(([name, k]) => [
        name,
        new CountingNonceWallet(k.privateKey, provider),
      ]),
    );
    poolAddr = ethers.getAddress(record.contracts.darkPool);
    darkPool = DarkPool__factory.connect(poolAddr, provider);
    const [pkX, pkY, version] = await withRetry("compliance key", () =>
      darkPool.complianceKey(),
    );
    COMPLIANCE_PK = [pkX, pkY];
    deployBlock = record.meta.startBlock;
    domain = poolDomain(COMPLIANCE_PK, Number(version), deployBlock);
    poolLogs = new PoolLogs(
      provider,
      darkPool as unknown as ethers.Contract,
      deployBlock,
      LOG_MAX_BLOCKS,
    );
    token = IERC20__factory.connect(tokens.tokens.mDAI!.address, provider);
    tokenB = IERC20__factory.connect(tokens.tokens.mWETH!.address, provider);
    // continue from an existing node's data, so the node reads only the blocks since
    const dataDir = join(OUT, "node-data");
    if (process.env.SIM_NODE_DATA && existsSync(process.env.SIM_NODE_DATA))
      cpSync(process.env.SIM_NODE_DATA, dataDir, { recursive: true });
    node = new HowlNode(
      env("HOWL_NODE_BIN"),
      process.env.SIM_NODE_RPC_URL || env("SIM_RPC_URL"),
      dataDir,
      chainId,
      poolAddr,
      deployBlock,
      Number(env("SIM_NODE_PORT")),
    );
    if ((await node.leaves()) !== null)
      throw new Error(`port ${node.port} already serves a node`);
    node.start();
    const t0 = Date.now();
    while ((await node.leaves()) === null) {
      if (Date.now() - t0 > 60_000)
        throw new Error("node did not start within 60 s");
      await new Promise((r) => setTimeout(r, 500));
    }
    await followed();
    log({
      step: "setup",
      pool: poolAddr,
      chainId,
      paramSet: PARAM_SET || "default",
    });
  });

  after(async function () {
    await node?.stop();
    summary.mismatches = mismatches;
    writeFileSync(
      join(OUT, "summary.json"),
      JSON.stringify(
        summary,
        (_, v) => (typeof v === "bigint" ? v.toString() : v),
        2,
      ),
    );
  });

  (process.env.SIM_SKIP_KAGE ? it.skip : it)(
    "Kage: Raven-backed taker, solver with its own tree, an older-root intent, a wrong hint refused",
    async function () {
      // the taker's shielded account is its own ("taker"), held by alice's wallet; the maker is charlie's wallet
      const takerSigner = wallets.alice!;
      const makerSigner = wallets.charlie!;
      const assetA = addressToFr(await token.getAddress());
      const assetB = addressToFr(await tokenB.getAddress());
      const taker = await FujiAgent.create(
        "taker",
        "kage",
        takerSigner,
        darkPool.connect(takerSigner) as DarkPool,
        source(),
        rootAfter,
        domain,
        poolLogs,
        join(OUT, "taker-keys.json"),
      );
      const index = new SolverIndex(poolLogs);
      const solver = new KageSolver(
        index,
        await userSpendScalar(makerSigner.address),
      );
      // the maker registers a solver with the pool's KageRegistry at its minimum stake, approving settlements with
      // a fresh signing key that holds no funds
      const registry = KageRegistry__factory.connect(
        record.contracts.kageRegistry,
        makerSigner,
      );
      const settlement = KageSettlement__factory.connect(
        record.contracts.kageSettlement,
        makerSigner,
      );
      const stakeToken = IERC20__factory.connect(
        await registry.stakingToken(),
        makerSigner,
      );
      const minStake = await registry.minStake();
      const hotKey = new ethers.Wallet(ethers.hexlify(ethers.randomBytes(32)));
      await (
        await stakeToken.approve(record.contracts.kageRegistry, minStake)
      ).wait();
      const reg = (await (
        await registry.register(hotKey.address, minStake)
      ).wait())!;
      const registered = reg.logs
        .map((l) => {
          try {
            return registry.interface.parseLog(l);
          } catch {
            return null;
          }
        })
        .find((e) => e?.name === "SolverRegistered");
      if (!registered) throw new Error("register: no SolverRegistered event");
      const solverId = BigInt(registered.args.solverId);
      expect(await registry.settlementSigner(solverId)).to.equal(
        hotKey.address,
      );
      log({
        step: "solver-registered",
        solverId,
        stake: minStake,
        tx: reg.hash,
        signer: hotKey.address,
      });

      const takerDeposit = async (v: bigint) => {
        const p = await taker.proveDeposit(v, await token.getAddress());
        await (await token.connect(takerSigner).approve(poolAddr, v)).wait();
        await (
          await darkPool.connect(takerSigner).deposit(p.proof, p.publicInputs)
        ).wait();
        log({ step: "taker-deposit", value: v });
        await followed();
      };
      const makerDeposit = async (v: bigint) => {
        const built = await mintSelfNote(
          solver.nextEph(),
          v,
          solver.spendScalar,
          assetB,
        );
        const p = await proveDeposit({
          compliancePk: COMPLIANCE_PK,
          note: built.note,
          eph: built.eph,
        });
        await (await tokenB.connect(makerSigner).approve(poolAddr, v)).wait();
        await (
          await darkPool.connect(makerSigner).deposit(p.proof, p.publicInputs)
        ).wait();
        log({ step: "maker-deposit", value: v });
        await index.refresh();
        solver.notes.push({
          built,
          leafIndex: index.indexOf(built.commitment),
          spent: false,
        });
        await followed();
      };

      await takerDeposit(100n);
      await makerDeposit(100n);
      const olderCount = await chainLeaves();
      await makerDeposit(100n);
      await takerDeposit(100n);
      log({ step: "seeded", leaves: await chainLeaves(), olderCount });

      const swaps = KAGE_SWAPS >= 2 ? ["older", "current"] : ["older"];
      for (const which of swaps) {
        await grade("taker", taker);
        const current = await chainLeaves();
        const input = taker
          .unspent(await token.getAddress())
          .find(
            (n) =>
              n.note.value === 100n &&
              (which === "current" || n.leafIndex < olderCount),
          );
        if (input === undefined) throw new Error("taker: no input note");
        const count = which === "older" ? olderCount : current;
        const w = await taker.witnessAt(input, count);
        const [mChange, mReceived] = await taker.clearedSelfEphemerals();
        const parents = packParents([
          { leafIndex: Number(input.leafIndex) },
          { leafIndex: 0 },
        ]);
        const spend = await taker.selfSpendScalar();
        const change = await mintSelfNote(
          mChange.eph as any,
          40n,
          spend,
          assetA,
          parents,
        );
        const received = await mintSelfNote(
          mReceived.eph as any,
          50n,
          spend,
          assetB,
          parents,
        );
        const now = BigInt((await provider.getBlock("latest"))!.timestamp);
        const t0 = Date.now();
        const intent = await proveSwapIntent({
          compliancePk: COMPLIANCE_PK,
          noteIn: noteToInput(input.note),
          spendScalar: input.spendScalar,
          indexIn: Number(input.leafIndex),
          pathIn: w.siblings as Fr[],
          changeNote: change.note,
          changeEph: change.eph,
          receivedNote: received.note,
          receivedEph: received.eph,
          toAsset: assetB,
          fromAmount: new Fr(60n),
          expiry: new Fr(now + 7200n),
        });
        const intentMs = Date.now() - t0;
        expect(BigInt(intent.publicInputs[1]!)).to.equal(w.root.toBigInt());
        // more leaves land between the taker's proof and the settlement
        await makerDeposit(1n);
        const currentRoot = BigInt(await darkPool.getCurrentRoot());
        log({
          step: "intent",
          which,
          inputLeaf: Number(input.leafIndex),
          count,
          ravenBlock: w.block,
          root: hex(w.root),
          olderThanCurrent: w.root.toBigInt() !== currentRoot,
          intentMs,
        });

        // planted control: the same intent with a wrong count hint is refused before any proving
        let refused = "";
        try {
          await index.refresh();
          solver.resolve({ intent, leafCountHint: count + 1 });
        } catch (e) {
          refused = (e as Error).message;
        }
        expect(refused, "a wrong hint must be refused").to.match(/^refused:/);
        log({ step: "plant-wrong-hint", which, hint: count + 1, refused });

        const ts =
          BigInt((await provider.getBlock("latest"))!.timestamp) + 240n;
        const s = await solver.settle(
          { intent, leafCountHint: count },
          assetB,
          ts,
        );
        expect(s.count).to.equal(count);
        expect(s.input.leafIndex).to.be.lessThan(count);
        const before = await chainLeaves();
        log({
          step: "pre-submit",
          which,
          makerInputLeaf: s.input.leafIndex,
          takerNullifierSpent: await darkPool.isNullifierSpent(
            s.settled.publicInputs[3]!,
          ),
          makerNullifierSpent: await darkPool.isNullifierSpent(
            s.settled.publicInputs[4]!,
          ),
        });
        const deadline =
          BigInt((await provider.getBlock("latest"))!.timestamp) + 600n;
        const approval = await signSettlement(hotKey, {
          chainId,
          verifyingContract: record.contracts.kageSettlement,
          pool: poolAddr,
          solverId,
          deadline,
          publicInputs: s.settled.publicInputs,
        });
        const rc = await (
          await settlement.settleSwap(
            solverId,
            deadline,
            approval,
            s.settled.proof,
            s.settled.publicInputs,
          )
        ).wait();
        s.input.spent = true;
        await followed();
        await index.refresh();
        const makerFound = [s.received, s.change].map((n) => ({
          leafIndex: index.indexOf(n.commitment),
          value: n.note.value.toBigInt(),
        }));
        for (const n of [s.received, s.change])
          solver.notes.push({
            built: n,
            leafIndex: index.indexOf(n.commitment),
            spent: false,
          });
        const makerSpent = await darkPool.isNullifierSpent(
          s.settled.publicInputs[4]!,
        );
        expect(makerFound.map((x) => x.leafIndex)).to.deep.equal([
          before + 2,
          before + 3,
        ]);
        expect(makerSpent).to.equal(true);

        const found = await grade("taker", taker);
        const takerFound = [change, received].map((n) => {
          const f = found.find((x) => x.commitment === n.commitment.toString());
          return f === undefined
            ? null
            : { leafIndex: f.leafIndex, value: f.value, spent: f.spent };
        });
        expect(takerFound.map((x) => x?.leafIndex)).to.deep.equal([
          before,
          before + 1,
        ]);
        expect(
          found.find((x) => x.leafIndex === Number(input.leafIndex))?.spent,
        ).to.equal(true);
        log({
          step: "settled",
          which,
          tx: rc!.hash,
          gas: rc!.gasUsed,
          resolvedCount: s.count,
          makerInputLeaf: s.input.leafIndex,
          settleMs: s.settleMs,
          takerFound,
          makerFound,
          makerSpent,
        });
        summary[`kage_${which}`] = {
          count,
          olderThanCurrent: w.root.toBigInt() !== currentRoot,
          resolvedCount: s.count,
          makerInputLeaf: s.input.leafIndex,
          takerFound,
          makerFound,
          wrongHintRefused: refused,
          intentMs,
          settleMs: s.settleMs,
        };
      }
      summary.takerWitnesses = taker.witnesses;
      expect(
        taker.witnesses.every((x) => x.knownRoot && x.chainRootAtCount),
      ).to.equal(true);
      expect(mismatches).to.equal(0);
    },
  );

  (process.env.SIM_SKIP_MULTISIG ? it.skip : it)(
    "Multisig: a 2-of-3 FROST group finds its notes through Raven (self and incoming, with lookahead growth) and spends one; a signer with a mismatched root refuses",
    async function () {
      // david's wallet sends every transaction (it holds the test tokens); ellie's address receives the withdrawal
      const depositor = wallets.david!;
      const recipient = wallets.ellie!;
      const asset = addressToFr(await token.getAddress());
      const account = await frostAccountDkg(3, 2, 0x534d4f4b45n);
      const v = new Fr(account.viewKey);
      const members = [...account.shares.keys()].sort((a, b) =>
        a < b ? -1 : 1,
      );
      const counters = new InMemoryEphemeralCounterStore();
      const signerOf = new Map<bigint, Signer>();
      for (const id of members) {
        const raven = source();
        signerOf.set(
          id,
          new Signer(
            id,
            account.shares.get(id)!,
            sdk,
            raven,
            new MultisigRavenScanner(sdk, raven, v, account.gpk, members),
          ),
        );
      }
      const coordinator = signerOf.get(members[0]!)!;

      const mint = await frost.multisigDepositEph(
        v,
        members[0]!,
        counters,
        account.gpk as any,
      );
      const ms = await buildMultisigNote(
        mint.eph,
        100n,
        account.owner,
        asset,
        toFr(0n),
      );
      const dp = await proveDeposit({
        compliancePk: COMPLIANCE_PK,
        note: ms.noteInput,
        eph: mint.eph,
      });
      await (await token.connect(depositor).approve(poolAddr, 100n)).wait();
      await (
        await darkPool.connect(depositor).deposit(dp.proof, dp.publicInputs)
      ).wait();
      // one more leaf, so an older known root exists for the planted session
      const filler = await mintSelfNote(
        evenYEphemeral(777n),
        1n,
        await userSpendScalar(depositor.address),
        asset,
      );
      const fp = await proveDeposit({
        compliancePk: COMPLIANCE_PK,
        note: filler.note,
        eph: filler.eph,
      });
      await (await token.connect(depositor).approve(poolAddr, 1n)).wait();
      await (
        await darkPool.connect(depositor).deposit(fp.proof, fp.publicInputs)
      ).wait();
      await followed();

      const perMember: Record<string, unknown> = {};
      for (const [id, s] of signerOf) {
        const f = await s.scanner.scan();
        perMember[String(id)] = f.map((n) => ({
          leafIndex: n.leafIndex,
          value: n.value,
        }));
        expect(f.map((n) => n.commitment.toBigInt())).to.deep.equal([
          ms.commitment.toBigInt(),
        ]);
      }
      log({ step: "multisig-found", members: perMember });
      const note = (await coordinator.scanner.scan())[0]!;

      const opened = await sdk.openSigningSession(coordinator.raven, [
        note.leafIndex,
      ]);
      const w = opened.witnesses[0];
      // The DKG is fresh each run, so the even-y indices move. The change goes to the member's HIGHEST
      // even-y index inside the first window: the later growth check needs a match as far out as it gets.
      let changeJ = -1n;
      for (let j = BigInt(SCAN_WINDOW) - 1n; j >= 0n && changeJ < 0n; j--)
        if (
          isEvenY((await frost.deriveSelfEph(v, members[0]!, j)).ephPub as any)
        )
          changeJ = j;
      let changeMint = await frost.multisigDepositEph(
        v,
        members[0]!,
        counters,
        account.gpk as any,
      );
      expect(changeMint.j < changeJ, "a later even-y index exists").to.equal(
        true,
      );
      while (changeMint.j < changeJ)
        changeMint = await frost.multisigDepositEph(
          v,
          members[0]!,
          counters,
          account.gpk as any,
        );
      const change = await buildMultisigNote(
        changeMint.eph,
        60n,
        account.owner,
        asset,
        packParents([{ leafIndex: note.leafIndex }, { leafIndex: 0 }]),
      );
      const withdrawArgs = (root: bigint) => ({
        root,
        nullifier: note.nullifier.toBigInt(),
        changeLeaf: change.commitment.toBigInt(),
        publicOut: 40n,
        asset: asset.toBigInt(),
        recipient: addressToFr(recipient.address).toBigInt(),
        intentHash: 0n,
      });
      expect(await darkPool.isKnownRoot(hex(w.root))).to.equal(true);
      const session: SigningSession = {
        raven: opened.session,
        nullifiers: [note.nullifier.toBigInt()],
        message: await frost.msgWithdraw(withdrawArgs(w.root.toBigInt())),
      };
      const quorum = [members[0]!, members[2]!];

      // planted control: a session whose root is another known root of the pool, not the root at its count
      const otherRoot = BigInt((await rootAfter(w.leafCount - 1))!);
      expect(await darkPool.isKnownRoot(hex(otherRoot))).to.equal(true);
      const planted: SigningSession = {
        raven: { ...session.raven, root: new Fr(otherRoot) },
        nullifiers: session.nullifiers,
        message: await frost.msgWithdraw(withdrawArgs(otherRoot)),
      };
      let refusal = "";
      try {
        await signerOf.get(quorum[1]!)!.round1(planted);
      } catch (e) {
        refusal = (e as Error).message;
      }
      expect(refusal).to.match(/refused \(root\): the path of leaf/);
      log({ step: "plant-mismatched-root", signer: quorum[1], refusal });

      const sig = await groupSign(
        quorum.map((id) => signerOf.get(id)!),
        session,
        account.gpk,
        account.verificationKeys,
      );

      const proof = await proveWithdrawMultisig({
        withdrawValue: toFr(40n),
        recipient: addressToFr(recipient.address),
        intentHash: toFr(0n),
        compliancePk: COMPLIANCE_PK,
        gpk: account.gpk,
        frostR: sig.R as any,
        frostZ: toFr(sig.z),
        oldNote: noteToInput(note.note),
        oldNoteIndex: note.leafIndex,
        oldNotePath: w.siblings as Fr[],
        changeNote: change.noteInput,
        changeEph: changeMint.eph,
      });
      const balBefore = await token.balanceOf(recipient.address);
      const rc = await (
        await darkPool
          .connect(depositor)
          .withdrawMultisig(proof.proof, proof.publicInputs)
      ).wait();
      await followed();
      const paid = (await token.balanceOf(recipient.address)) - balBefore;
      const spent = await darkPool.isNullifierSpent(hex(note.nullifier));
      expect(paid).to.equal(40n);
      expect(spent).to.equal(true);

      const after: Record<string, unknown> = {};
      for (const [id, s] of signerOf) {
        const f = await s.scanner.scan();
        const live = [];
        for (const n of f)
          if (!(await darkPool.isNullifierSpent(hex(n.nullifier))))
            live.push(n);
        after[String(id)] = live.map((n) => ({
          leafIndex: n.leafIndex,
          value: n.value,
        }));
        expect(live.map((n) => n.commitment.toBigInt())).to.deep.equal([
          change.commitment.toBigInt(),
        ]);
      }
      log({
        step: "multisig-spent",
        tx: rc!.hash,
        gas: rc!.gasUsed,
        quorum,
        leafIndex: note.leafIndex,
        leafCount: session.raven.leafCount,
        root: hex(session.raven.root),
        paid,
        spent,
        unspentAfter: after,
      });
      summary.multisig = {
        t: 2,
        n: 3,
        quorum,
        found: perMember,
        session: {
          leafIndex: note.leafIndex,
          leafCount: session.raven.leafCount,
          root: hex(session.raven.root),
        },
        plantedRefusal: refusal,
        paid,
        spent,
        unspentAfter: after,
      };

      // Incoming family and lookahead growth. Two transfers to the group's receiving addresses: one inside
      // the first window, one past it but inside the window a match at the first one opens. One more self
      // note lands past the first self window, inside the window the change note's match opens.
      // Planted control: the same scanner with growth off finds neither far note.
      const W = BigInt(SCAN_WINDOW);
      // near = the highest canonical address inside the first window; far = the next one after it
      let near = await frost.multisigIncomingKeyAt(v, 0n);
      for (let i = W - 1n; i > 0n; i--) {
        const k = await frost.multisigIncomingKeyAt(v, i);
        if (k.index === i) {
          near = k;
          break;
        }
      }
      const far = await frost.multisigIncomingKeyAt(v, W);
      expect(near.index < W, "near address inside the first window").to.equal(
        true,
      );
      expect(
        far.index >= W && far.index <= near.index + W,
        `far address ${far.index}: past the first window, inside the grown one`,
      ).to.equal(true);
      const spendScalar = await userSpendScalar(depositor.address);
      const sendToGroup = async (
        seed: bigint,
        addr: { viewKey: Fr; viewPub: Point<bigint> },
        value: bigint,
      ) => {
        const src = await mintSelfNote(
          evenYEphemeral(seed),
          value + 5n,
          spendScalar,
          asset,
        );
        const srcIndex = await chainLeaves();
        const sp = await proveDeposit({
          compliancePk: COMPLIANCE_PK,
          note: src.note,
          eph: src.eph,
        });
        await (
          await token.connect(depositor).approve(poolAddr, value + 5n)
        ).wait();
        await (
          await darkPool.connect(depositor).deposit(sp.proof, sp.publicInputs)
        ).wait();
        await followed();
        // a witness without a count is at the newest VERIFIED count, so the sender syncs first
        expect((await coordinator.raven.sync()).leafCount).to.equal(
          srcIndex + 1,
        );
        const sw = await coordinator.raven.merkleWitness(srcIndex);
        expect(sw.leaf.toBigInt()).to.equal(src.commitment.toBigInt());
        const memo = await mintIncomingMultisigNote(
          evenYEphemeral(seed + 1000n),
          value,
          account.gpk,
          addr.viewKey,
          asset,
          PARENTS_HIDDEN,
        );
        const back = await mintSelfNote(
          evenYEphemeral(seed + 2000n),
          5n,
          spendScalar,
          asset,
          packParents([{ leafIndex: srcIndex }, { leafIndex: 0 }]),
        );
        const tp = await proveTransfer({
          compliancePk: COMPLIANCE_PK,
          recipientMultisig: { gpk: account.gpk, viewPub: addr.viewPub },
          oldNote: src.note,
          spendScalar,
          oldNoteIndex: srcIndex,
          oldNotePath: sw.siblings as Fr[],
          memoNote: memo.note,
          memoEph: memo.eph,
          changeNote: back.note,
          changeEph: back.eph,
        });
        const memoIndex = await chainLeaves();
        await (
          await darkPool
            .connect(depositor)
            .privateTransfer(tp.proof, tp.publicInputs)
        ).wait();
        return { commitment: memo.commitment.toBigInt(), leafIndex: memoIndex };
      };
      const nearNote = await sendToGroup(9100n, near, 10n);
      const farNote = await sendToGroup(9400n, far, 11n);

      let selfFar = await frost.multisigDepositEph(
        v,
        members[0]!,
        counters,
        account.gpk as any,
      );
      while (selfFar.j < W)
        selfFar = await frost.multisigDepositEph(
          v,
          members[0]!,
          counters,
          account.gpk as any,
        );
      expect(
        selfFar.j <= changeJ + W,
        `self j ${selfFar.j}: past the first window, inside the one change j ${changeJ} opens`,
      ).to.equal(true);
      const sf = await buildMultisigNote(
        selfFar.eph,
        7n,
        account.owner,
        asset,
        toFr(0n),
      );
      const sfp = await proveDeposit({
        compliancePk: COMPLIANCE_PK,
        note: sf.noteInput,
        eph: selfFar.eph,
      });
      await (await token.connect(depositor).approve(poolAddr, 7n)).wait();
      await (
        await darkPool.connect(depositor).deposit(sfp.proof, sfp.publicInputs)
      ).wait();
      await followed();

      const want = [
        change.commitment.toBigInt(),
        nearNote.commitment,
        farNote.commitment,
        sf.commitment.toBigInt(),
      ].sort();
      const grown: Record<string, unknown> = {};
      for (const [id, s] of signerOf) {
        const f = await s.scanner.scan();
        const live = [];
        for (const n of f)
          if (!(await darkPool.isNullifierSpent(hex(n.nullifier))))
            live.push(n);
        expect(live.map((n) => n.commitment.toBigInt()).sort()).to.deep.equal(
          want,
        );
        const inc = live.filter((n) => n.incoming);
        expect(inc.map((n) => n.index).sort()).to.deep.equal(
          [near.index, far.index].sort(),
        );
        expect(s.scanner.lastRounds).to.be.greaterThan(1);
        grown[String(id)] = {
          rounds: s.scanner.lastRounds,
          notes: live.map((n) => ({
            leafIndex: n.leafIndex,
            value: n.value,
            family: n.incoming ? "incoming" : "self",
            index: n.index,
          })),
        };
      }
      const fixed = new MultisigRavenScanner(
        sdk,
        source(),
        v,
        account.gpk,
        members,
        SCAN_WINDOW,
      );
      const fixedFound = (await fixed.scan()).map((n) =>
        n.commitment.toBigInt(),
      );
      expect(fixedFound).to.include(nearNote.commitment);
      expect(fixedFound).to.not.include(farNote.commitment);
      expect(fixedFound).to.not.include(sf.commitment.toBigInt());
      log({
        step: "multisig-incoming-and-growth",
        near: { index: near.index, leaf: nearNote.leafIndex },
        far: { index: far.index, leaf: farNote.leafIndex },
        selfFar: { j: selfFar.j, changeJ },
        perMember: grown,
        plantFixedWindowMisses: {
          far: !fixedFound.includes(farNote.commitment),
          selfFar: !fixedFound.includes(sf.commitment.toBigInt()),
        },
      });
      summary.multisigIncoming = {
        nearIndex: near.index,
        farIndex: far.index,
        selfFarJ: selfFar.j,
        changeJ,
        perMember: grown,
        fixedWindowFound: fixedFound.length,
      };

      // Spends of found notes, each through a session at one count that every signer checks against its
      // own scan and path: the incoming near note split in two, the far incoming note joined with the far
      // self note, and the change transferred to an outside recipient with change back to the group.
      const spenders = [signerOf.get(members[1]!)!, signerOf.get(members[2]!)!];
      const mintOut = () =>
        frost.multisigDepositEph(v, members[0]!, counters, account.gpk as any);
      const parentsOf = (...ix: number[]) =>
        packParents(
          ix.length === 2
            ? [{ leafIndex: ix[0]! }, { leafIndex: ix[1]! }]
            : [{ leafIndex: ix[0]! }, { leafIndex: 0 }],
        );
      const byLeaf = async (leafIndex: number) =>
        (await coordinator.scanner.scan()).find(
          (n) => n.leafIndex === leafIndex,
        )!;
      const openSession = async (
        notes: GroupNote[],
        message: (root: bigint) => Promise<bigint>,
      ) => {
        await coordinator.raven.sync();
        const o = await sdk.openSigningSession(
          coordinator.raven,
          notes.map((n) => n.leafIndex),
        );
        expect(await darkPool.isKnownRoot(hex(o.session.root))).to.equal(true);
        const session: SigningSession = {
          raven: o.session,
          nullifiers: notes.map((n) => n.nullifier.toBigInt()),
          message: await message(o.session.root.toBigInt()),
        };
        return {
          session,
          paths: o.witnesses.map((x: any) => x.siblings as Fr[]),
        };
      };
      const spends: Record<string, unknown>[] = [];

      const inNear = await byLeaf(nearNote.leafIndex);
      expect(inNear.incoming).to.equal(true);
      const [e1, e2] = [await mintOut(), await mintOut()];
      const out1 = await buildMultisigNote(
        e1.eph,
        4n,
        account.owner,
        asset,
        parentsOf(inNear.leafIndex),
      );
      const out2 = await buildMultisigNote(
        e2.eph,
        6n,
        account.owner,
        asset,
        parentsOf(inNear.leafIndex),
      );
      const split = await openSession([inNear], (root) =>
        frost.msgSplit({
          root,
          nullifier: inNear.nullifier.toBigInt(),
          out1Leaf: out1.commitment.toBigInt(),
          out2Leaf: out2.commitment.toBigInt(),
          asset: asset.toBigInt(),
        }),
      );
      const sigSplit = await groupSign(
        spenders,
        split.session,
        account.gpk,
        account.verificationKeys,
      );
      const splitProof = await proveSplitMultisig({
        compliancePk: COMPLIANCE_PK,
        gpk: account.gpk,
        frostR: sigSplit.R as any,
        frostZ: toFr(sigSplit.z),
        noteIn: noteToInput(inNear.note),
        indexIn: inNear.leafIndex,
        pathIn: split.paths[0]!,
        noteOut1: out1.noteInput,
        eph1: e1.eph,
        noteOut2: out2.noteInput,
        eph2: e2.eph,
      });
      await (
        await darkPool
          .connect(depositor)
          .splitMultisig(splitProof.proof, splitProof.publicInputs)
      ).wait();
      await followed();
      expect(await darkPool.isNullifierSpent(hex(inNear.nullifier))).to.equal(
        true,
      );
      spends.push({
        kind: "split",
        input: { leaf: inNear.leafIndex, family: "incoming" },
        leafCount: split.session.raven.leafCount,
      });

      const inFar = await byLeaf(farNote.leafIndex);
      const selfFarNote = (await coordinator.scanner.scan()).find(
        (n) => n.commitment.toBigInt() === sf.commitment.toBigInt(),
      )!;
      expect([inFar.incoming, selfFarNote.incoming]).to.deep.equal([
        true,
        false,
      ]);
      const eJoin = await mintOut();
      const joined = await buildMultisigNote(
        eJoin.eph,
        inFar.value + selfFarNote.value,
        account.owner,
        asset,
        parentsOf(inFar.leafIndex, selfFarNote.leafIndex),
      );
      const join = await openSession([inFar, selfFarNote], (root) =>
        frost.msgJoin({
          root,
          nullifierA: inFar.nullifier.toBigInt(),
          nullifierB: selfFarNote.nullifier.toBigInt(),
          outLeaf: joined.commitment.toBigInt(),
          asset: asset.toBigInt(),
        }),
      );
      const sigA = await groupSign(
        spenders,
        join.session,
        account.gpk,
        account.verificationKeys,
      );
      const sigB = await groupSign(
        spenders,
        join.session,
        account.gpk,
        account.verificationKeys,
      );
      const joinProof = await proveJoinMultisig({
        compliancePk: COMPLIANCE_PK,
        gpkA: account.gpk,
        frostRA: sigA.R as any,
        frostZA: toFr(sigA.z),
        noteA: noteToInput(inFar.note),
        indexA: inFar.leafIndex,
        pathA: join.paths[0]!,
        gpkB: account.gpk,
        frostRB: sigB.R as any,
        frostZB: toFr(sigB.z),
        noteB: noteToInput(selfFarNote.note),
        indexB: selfFarNote.leafIndex,
        pathB: join.paths[1]!,
        noteOut: joined.noteInput,
        ephOut: eJoin.eph,
      });
      await (
        await darkPool
          .connect(depositor)
          .joinMultisig(joinProof.proof, joinProof.publicInputs)
      ).wait();
      await followed();
      expect(await darkPool.isNullifierSpent(hex(inFar.nullifier))).to.equal(
        true,
      );
      expect(
        await darkPool.isNullifierSpent(hex(selfFarNote.nullifier)),
      ).to.equal(true);
      spends.push({
        kind: "join",
        inputs: [
          { leaf: inFar.leafIndex, family: "incoming" },
          { leaf: selfFarNote.leafIndex, family: "self" },
        ],
        leafCount: join.session.raven.leafCount,
      });

      const changeNote = await byLeaf(
        (await coordinator.scanner.scan()).find(
          (n) => n.commitment.toBigInt() === change.commitment.toBigInt(),
        )!.leafIndex,
      );
      const bobInKey = evenYEphemeral(5560n);
      const bobInPub = publicKey(bobInKey);
      const memo = await mintIncomingNote(
        evenYEphemeral(0x9912n),
        25n,
        bobInPub,
        bobInKey,
        asset,
        PARENTS_HIDDEN,
      );
      const eBack = await mintOut();
      const back = await buildMultisigNote(
        eBack.eph,
        changeNote.value - 25n,
        account.owner,
        asset,
        parentsOf(changeNote.leafIndex),
      );
      const transfer = await openSession([changeNote], (root) =>
        frost.msgTransfer({
          root,
          nullifier: changeNote.nullifier.toBigInt(),
          memoLeaf: memo.commitment.toBigInt(),
          memoTag: bobInPub[0],
          changeLeaf: back.commitment.toBigInt(),
          asset: asset.toBigInt(),
        }),
      );
      const sigT = await groupSign(
        spenders,
        transfer.session,
        account.gpk,
        account.verificationKeys,
      );
      const transferProof = await proveTransferMultisig({
        compliancePk: COMPLIANCE_PK,
        gpk: account.gpk,
        frostR: sigT.R as any,
        frostZ: toFr(sigT.z),
        recipientInPub: bobInPub,
        oldNote: noteToInput(changeNote.note),
        oldNoteIndex: changeNote.leafIndex,
        oldNotePath: transfer.paths[0]!,
        memoNote: memo.note,
        memoEph: memo.eph,
        changeNote: back.noteInput,
        changeEph: eBack.eph,
      });
      await (
        await darkPool
          .connect(depositor)
          .transferMultisig(transferProof.proof, transferProof.publicInputs)
      ).wait();
      await followed();
      expect(
        await darkPool.isNullifierSpent(hex(changeNote.nullifier)),
      ).to.equal(true);
      spends.push({
        kind: "transfer",
        input: { leaf: changeNote.leafIndex, family: "self" },
        leafCount: transfer.session.raven.leafCount,
      });

      const afterSpends = [out1, out2, joined, back]
        .map((n) => n.commitment.toBigInt())
        .sort();
      const held: Record<string, unknown> = {};
      for (const [id, s] of signerOf) {
        const live = [];
        for (const n of await s.scanner.scan())
          if (!(await darkPool.isNullifierSpent(hex(n.nullifier))))
            live.push(n);
        expect(
          live.map((n) => n.commitment.toBigInt()).sort(),
          `member ${id}`,
        ).to.deep.equal(afterSpends);
        held[String(id)] = live.map((n) => ({
          leafIndex: n.leafIndex,
          value: n.value,
        }));
      }
      log({ step: "multisig-spends", spends, unspentAfter: held });
      summary.multisigSpends = { spends, unspentAfter: held };
      void ms.tag;
    },
  );
});
