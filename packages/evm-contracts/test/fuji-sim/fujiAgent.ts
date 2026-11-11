// A wallet that finds its notes and its Merkle paths through a Raven Howl node, and nothing else.
// The chain is used only to send transactions and for the reads Raven does not serve (spent set,
// isKnownRoot). An independent ScanEngine over the chain's own logs grades it, every step.
//
// Ported from Raven's adapters/howl-node/e2e harness for a deployed pool: the compliance key and the
// self-mint domain come from the deployment, key counters survive a restart, and the chain scans read
// the pool's logs through PoolLogs in windows a public endpoint accepts.
import { existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { ethers } from "ethers";
import {
  DarkAccount,
  PersistentEphemeralCounterStore,
  type CounterSnapshot,
  type CompleteComplianceHistory,
  Fr,
  toFr,
  addressToFr,
  completeComplianceHistory,
  computeNullifier,
  computePsi,
  deriveCek,
  unwrapCek,
  recoverEvenY,
  discoveryTag,
  isEvenY,
  publicKey,
  pubkeyOwner,
  leaf as computeLeaf,
  SelfMintPreflight,
  buildPublicClaim,
  type HowlNoteRecord,
  type DiscoverySource,
  type OccurrenceRequest,
  type SelfMintAuthorization,
} from "@hisoka/wallets";
import {
  assembleDeposit,
  assembleWithdraw,
  assembleTransfer,
  assembleSplit,
  assembleJoin,
} from "@hisoka/wallets/tx";
import type { AssemblyContext, MerkleWitnessSource } from "@hisoka/wallets/tx";
import {
  KeyRepository,
  InMemoryEphemeralCounterStore,
  UtxoRepository,
  ScanEngine,
  PublicMemoScanner,
  type KeyRepoState,
  type WalletNote,
  type DiscoveredPublicMemo,
} from "@hisoka/wallets/reference";
import {
  proveDeposit,
  proveWithdraw,
  proveTransfer,
  proveSplit,
  proveJoin,
  provePublicClaim,
  type ProofData,
} from "@hisoka/prover";
import { syncViaDiscovery, type TagCandidate } from "@hisoka/howl-e2e";
import type { Point } from "@zk-kit/baby-jubjub";
import { noteToInput } from "../helpers/fixtures";
import { withRetry, type PoolLogs } from "./poolLogs";
import type { DarkPool } from "../../typechain-types";

const NOTE_TYPE_STANDARD = 0n;
const ASSET_MODULUS = 1n << 160n;
const SELF_LOOKAHEAD = 10;
const INCOMING_LOOKAHEAD = 5;

/** The deployment the wallets mint against: its compliance key, and the self-mint domain anchor. */
export interface PoolDomain {
  readonly compliancePk: Point<bigint>;
  readonly complianceVersion: number;
  readonly history: CompleteComplianceHistory;
  /** The pool's start block, as Howl's wallet runtime sets it. */
  readonly deploymentAnchor: bigint;
  readonly startBlock: number;
}

export function poolDomain(
  compliancePk: Point<bigint>,
  complianceVersion: number,
  startBlock: number,
): PoolDomain {
  if (complianceVersion !== 1)
    throw new Error(
      `the pool is at compliance version ${complianceVersion}; this harness models no rotation history`,
    );
  return {
    compliancePk,
    complianceVersion,
    history: completeComplianceHistory({
      genesisPk: compliancePk,
      rotations: [],
      currentPk: compliancePk,
      currentVersion: complianceVersion,
    }),
    deploymentAnchor: BigInt(startBlock),
    startBlock,
  };
}

/** A wallet's key state on disk, so a later wave never reissues an ephemeral or an address it already used. */
interface SavedKeys {
  counters: CounterSnapshot;
  keys: KeyRepoState;
  publicIssued: number;
}

function writeAtomic(file: string, body: string): void {
  writeFileSync(`${file}.tmp`, body, { mode: 0o600 });
  renameSync(`${file}.tmp`, file);
}

class FileCounters {
  snapshot: CounterSnapshot;
  constructor(
    initial: CounterSnapshot,
    readonly flush: () => void,
  ) {
    this.snapshot = { ...initial };
  }
  read(): CounterSnapshot {
    return this.snapshot;
  }
  async reserve(scope: string, span: number): Promise<number> {
    const base = this.snapshot[scope] ?? 0;
    this.snapshot = { ...this.snapshot, [scope]: base + span };
    this.flush();
    return base;
  }
}

/** The parts of the Raven client this harness uses. */
export interface RavenSource {
  sync(): Promise<{
    leafCount: number;
    block: number;
    rowsAdded: number;
    rewoundTo?: number;
  }>;
  probeFirst(
    tags: readonly Fr[],
  ): Promise<{ tag: Fr; record: HowlNoteRecord; occurrenceCount: number }[]>;
  fetchOccurrences(
    requests: readonly OccurrenceRequest[],
  ): Promise<(HowlNoteRecord | null)[]>;
  fetchLeafBlock(blockIndex: number): Promise<Fr[]>;
  merkleWitness(
    leafIndex: number,
    leafCount?: number,
  ): Promise<{
    leafIndex: number;
    leafCount: number;
    block: number;
    siblings: Fr[];
    root: Fr;
    leaf: Fr;
  }>;
  readonly state: { leafCount: number; block: number };
  close(): void;
}

/** Howl's wallet ports as the Raven client package exports them. */
export interface RavenPorts {
  discoverySource(raven: RavenSource): DiscoverySource;
  witnessSource(options: {
    source: RavenSource;
    field: { fromBytes(b: Uint8Array): Fr; toBytes(f: Fr): Uint8Array };
    leafIndexOf(commitment: Fr): number | undefined;
    isKnownRoot(root: Fr): Promise<boolean>;
    observe?(
      witness: {
        leafIndex: number;
        leafCount: number;
        block: number;
        root: Fr;
      },
      knownRoot: boolean,
    ): Promise<void>;
  }): MerkleWitnessSource;
}

let ports: RavenPorts | undefined;

/** The package the suite loaded; every agent takes Howl's ports from it. */
export function useRavenPorts(sdk: RavenPorts): void {
  ports = sdk;
}

function ravenPorts(): RavenPorts {
  if (ports === undefined)
    throw new Error("useRavenPorts(sdk) was not called before the agents ran");
  return ports;
}

/**
 * Howl's DiscoverySource over the Raven client, as shipped: a tag with no feed match gets the
 * client's padded miss record, which both Howl's scanner and its self-mint preflight accept.
 */
export function discoveryView(raven: RavenSource): DiscoverySource {
  return ravenPorts().discoverySource(raven);
}

const FR_FIELD = {
  fromBytes: (b: Uint8Array) => Fr.fromBuffer(Buffer.from(b)),
  toBytes: (f: Fr) => new Uint8Array(f.toBuffer()),
};

export interface WitnessRecord {
  leafIndex: number;
  leafCount: number;
  block: number;
  root: string;
  knownRoot: boolean;
  chainRootAtCount: boolean;
}

export interface FoundNote {
  leafIndex: number;
  commitment: string;
  value: bigint;
  asset: string;
  spent: boolean;
  incoming: boolean;
}

export interface ReceiveAddress {
  inKey: Fr;
  inPub: Point<bigint>;
  index: number;
}

export type ChainRootAt = (leafCount: number) => Promise<string | undefined>;

export class FujiAgent {
  account!: DarkAccount;
  keyRepo!: KeyRepository;
  chainId = 0n;
  /** Notes found through Raven at the last discovery, keyed by leaf index. */
  notes = new Map<number, WalletNote & { asset: string }>();
  readonly issued: ReceiveAddress[] = [];
  readonly witnesses: WitnessRecord[] = [];
  #selfCache = new Map<number, { eph: Fr; tag: Fr } | null>();
  #inCache = new Map<number, { inKey: Fr; inPub: Point<bigint> } | null>();
  // a spent nullifier never becomes unspent, so only unspent ones are read again
  #spent = new Set<string>();
  #counters!: FileCounters;

  private constructor(
    readonly name: string,
    readonly strategy: string,
    readonly signer: ethers.Signer & { address: string },
    readonly darkPool: DarkPool,
    readonly raven: RavenSource,
    readonly chainRootAt: ChainRootAt,
    readonly domain: PoolDomain,
    readonly poolLogs: PoolLogs,
    readonly keyFile: string,
  ) {}

  static async create(
    name: string,
    strategy: string,
    signer: ethers.Signer & { address: string },
    darkPool: DarkPool,
    raven: RavenSource,
    chainRootAt: ChainRootAt,
    domain: PoolDomain,
    poolLogs: PoolLogs,
    keyFile: string,
  ): Promise<FujiAgent> {
    const a = new FujiAgent(
      name,
      strategy,
      signer,
      darkPool,
      raven,
      chainRootAt,
      domain,
      poolLogs,
      keyFile,
    );
    const signature = await signer.signMessage(`Hisoka Test Login ${name}`);
    a.account = await DarkAccount.fromSignature(signature);
    a.chainId = (await signer.provider!.getNetwork()).chainId;
    const saved: SavedKeys | null = existsSync(keyFile)
      ? (JSON.parse(readFileSync(keyFile, "utf8")) as SavedKeys)
      : null;
    a.#counters = new FileCounters(saved?.counters ?? {}, () => a.saveKeys());
    a.keyRepo = new KeyRepository(
      a.account,
      new PersistentEphemeralCounterStore(a.#counters),
    );
    if (saved !== null) {
      await a.keyRepo.restore(saved.keys);
      a.publicIssued = saved.publicIssued;
    }
    a.saveKeys();
    return a;
  }

  saveKeys(): void {
    if (this.keyRepo === undefined) return;
    const saved: SavedKeys = {
      counters: this.#counters.read(),
      keys: this.keyRepo.getState(),
      publicIssued: this.publicIssued,
    };
    writeAtomic(this.keyFile, JSON.stringify(saved));
  }

  get address(): string {
    return this.signer.address;
  }

  async receiveAddress(): Promise<ReceiveAddress> {
    const addr = await this.keyRepo.nextIncomingAddress();
    const r = { inKey: addr.inKey, inPub: addr.inPub, index: addr.index };
    this.issued.push(r);
    this.saveKeys();
    return r;
  }

  async #self(index: number) {
    if (!this.#selfCache.has(index)) {
      const eph = await this.account.getSelfEphemeral(BigInt(index));
      const pub = publicKey(eph);
      this.#selfCache.set(
        index,
        isEvenY(pub) ? { eph, tag: new Fr(pub[0]) } : null,
      );
    }
    return this.#selfCache.get(index)!;
  }

  async #incoming(index: number) {
    if (!this.#inCache.has(index)) {
      const inKey = await this.account.getIncomingKey(BigInt(index));
      const inPub = publicKey(inKey);
      this.#inCache.set(index, isEvenY(inPub) ? { inKey, inPub } : null);
    }
    return this.#inCache.get(index)!;
  }

  /**
   * Find every note this wallet owns through Raven: Howl's own two-round discovery client over
   * the Raven source, with the wallet's tags from its key schedule. Spent status comes from the
   * pool (the spent set is not Raven's).
   */
  async discover(): Promise<{
    found: number;
    rejected: number;
    truncated: number;
  }> {
    const state = this.keyRepo.getState();
    const selfOwner = await pubkeyOwner(await this.account.getSelfSpendPub());
    const ceks = new Map<string, Fr>();
    const spendFor = new Map<
      string,
      { scalar: Fr; incoming: boolean; index: number }
    >();
    const candidates: TagCandidate[] = [];
    for (let i = 0; i < state.selfMintCounter + SELF_LOOKAHEAD; i++) {
      const s = await this.#self(i);
      if (s === null) continue;
      const key = s.tag.toString();
      spendFor.set(key, {
        scalar: await this.account.getSelfSpendKey(),
        incoming: false,
        index: i,
      });
      candidates.push({
        tag: s.tag,
        ownerCommitment: selfOwner,
        cekFor: async (record) => {
          const cek = deriveCek(s.eph, this.domain.compliancePk);
          ceks.set(`${key}:${record.leafIndex}`, cek);
          return cek;
        },
      });
    }
    for (let i = 0; i < state.incomingIssueCounter + INCOMING_LOOKAHEAD; i++) {
      const s = await this.#incoming(i);
      if (s === null) continue;
      const tag = discoveryTag(s.inPub);
      const key = tag.toString();
      spendFor.set(key, { scalar: s.inKey, incoming: true, index: i });
      candidates.push({
        tag,
        ownerCommitment: await pubkeyOwner(s.inPub),
        cekFor: async (record) => {
          const cek = await unwrapCek(
            record.cekWrap,
            s.inKey,
            recoverEvenY(record.ephemeralPkX.toBigInt()),
          );
          ceks.set(`${key}:${record.leafIndex}`, cek);
          return cek;
        },
      });
    }

    const result = await syncViaDiscovery(
      discoveryView(this.raven),
      candidates,
    );
    const next = new Map<number, WalletNote & { asset: string }>();
    for (const n of result.notes) {
      const key = n.tag.toString();
      const cek = ceks.get(`${key}:${n.leafIndex}`);
      const owner = spendFor.get(key);
      if (cek === undefined || owner === undefined)
        throw new Error(`${this.name}: no key for found note ${n.leafIndex}`);
      const p = n.plaintext;
      const psi = await computePsi(cek);
      const note = {
        noteVersion: p[0],
        assetId: p[1],
        noteType: p[2],
        conditionsHash: p[3],
        value: p[4].toBigInt(),
        owner: p[5],
        psi,
        parents: p[6],
      };
      // the same rules Howl's NoteProcessor applies before it counts a note
      if (note.noteType.toBigInt() !== NOTE_TYPE_STANDARD) continue;
      if (note.assetId.toBigInt() >= ASSET_MODULUS) continue;
      if (!note.owner.equals(await pubkeyOwner(publicKey(owner.scalar))))
        continue;
      const commitment = await computeLeaf(note);
      const nullifier = await computeNullifier(
        psi,
        new Fr(BigInt(n.leafIndex)),
      );
      const nf = nullifier.toString();
      const spent =
        this.#spent.has(nf) ||
        (await withRetry(`isNullifierSpent ${n.leafIndex}`, () =>
          this.darkPool.isNullifierSpent(nf),
        ));
      if (spent) this.#spent.add(nf);
      next.set(n.leafIndex, {
        note,
        commitment,
        leafIndex: n.leafIndex,
        nullifier,
        spendScalar: owner.scalar,
        isIncoming: owner.incoming,
        derivationIndex: owner.index,
        spent,
        asset: ethers.getAddress(ethers.toBeHex(note.assetId.toBigInt(), 20)),
      });
    }
    this.notes = next;
    return {
      found: next.size,
      rejected: result.rejected,
      truncated: result.truncatedTags.length,
    };
  }

  found(): FoundNote[] {
    return [...this.notes.values()]
      .map((n) => ({
        leafIndex: n.leafIndex,
        commitment: n.commitment.toString(),
        value: n.note.value,
        asset: n.asset,
        spent: n.spent,
        incoming: n.isIncoming,
      }))
      .sort((a, b) => a.leafIndex - b.leafIndex);
  }

  balance(asset: string): bigint {
    let total = 0n;
    for (const n of this.notes.values())
      if (!n.spent && n.asset === ethers.getAddress(asset))
        total += n.note.value;
    return total;
  }

  unspent(asset: string): (WalletNote & { asset: string })[] {
    return [...this.notes.values()]
      .filter((n) => !n.spent && n.asset === ethers.getAddress(asset))
      .sort((a, b) => a.leafIndex - b.leafIndex);
  }

  spentNotes(): (WalletNote & { asset: string })[] {
    return [...this.notes.values()].filter((n) => n.spent);
  }

  /** The chain's own view of this wallet, from every note event the pool emitted. */
  async oracle(): Promise<FoundNote[]> {
    const signature = await this.signer.signMessage(
      `Hisoka Test Login ${this.name}`,
    );
    const account = await DarkAccount.fromSignature(signature);
    const keys = new KeyRepository(
      account,
      new InMemoryEphemeralCounterStore(),
    );
    const utxo = new UtxoRepository();
    const scan = new ScanEngine(
      this.poolLogs.view(),
      keys,
      utxo,
      this.domain.compliancePk,
      undefined,
      20,
      this.domain.startBlock,
    );
    await scan.sync(this.domain.startBlock);
    return utxo
      .getAllNotes()
      .map((n) => ({
        leafIndex: Number(n.leafIndex),
        commitment: n.commitment.toString(),
        value: n.note.value,
        asset: ethers.getAddress(ethers.toBeHex(n.note.assetId.toBigInt(), 20)),
        spent: n.spent,
        incoming: n.isIncoming,
      }))
      .sort((a, b) => a.leafIndex - b.leafIndex);
  }

  /** Merkle paths from Raven only, checked against the pool before a proof is built on them. */
  witnessSource(): MerkleWitnessSource {
    return ravenPorts().witnessSource({
      source: this.raven,
      field: FR_FIELD,
      leafIndexOf: (commitment) => {
        const owned = [...this.notes.values()].find((n) =>
          n.commitment.equals(commitment),
        );
        return owned === undefined ? undefined : Number(owned.leafIndex);
      },
      isKnownRoot: (root) => this.darkPool.isKnownRoot(root.toString()),
      observe: async (w, knownRoot) => {
        const root = w.root.toString();
        const chainRoot = await this.chainRootAt(w.leafCount);
        this.witnesses.push({
          leafIndex: w.leafIndex,
          leafCount: w.leafCount,
          block: w.block,
          root,
          knownRoot,
          chainRootAtCount:
            chainRoot !== undefined && BigInt(chainRoot) === BigInt(root),
        });
      },
    });
  }

  ctx(): AssemblyContext {
    return {
      compliancePk: this.domain.compliancePk,
      complianceVersion: this.domain.complianceVersion,
      complianceHistory: this.domain.history,
      chainId: this.chainId,
      poolAddress: this.darkPool.target.toString(),
      deploymentAnchor: this.domain.deploymentAnchor,
      merkle: this.witnessSource(),
    };
  }

  async #selfMints(count: 1 | 2): Promise<readonly SelfMintAuthorization[]> {
    const preflight = new SelfMintPreflight({
      allocator: { next: () => this.keyRepo.nextSelfEphemeral() },
      discovery: discoveryView(this.raven),
      history: this.domain.history,
      ownerCommitment: await pubkeyOwner(await this.keyRepo.getSelfSpendPub()),
      domain: {
        chainId: this.chainId,
        poolAddress: this.darkPool.target.toString(),
        deploymentAnchor: this.domain.deploymentAnchor,
      },
    });
    return count === 1 ? preflight.take(1) : preflight.take(2);
  }

  /**
   * Two self ephemerals that Howl's self-mint preflight cleared over Raven, for outputs minted by a
   * circuit with no Howl assembler (Kage's swap_intent). The authorization handles are opaque and
   * Howl exports no way to consume them, so the allocator is wrapped and a run that skipped any
   * candidate is refused instead of guessed at.
   */
  async clearedSelfEphemerals(): Promise<
    [{ eph: Fr; index: number }, { eph: Fr; index: number }]
  > {
    const issued: { eph: Fr; index: number }[] = [];
    const preflight = new SelfMintPreflight({
      allocator: {
        next: async () => {
          const c = await this.keyRepo.nextSelfEphemeral();
          issued.push({ eph: c.eph, index: c.index });
          return c;
        },
      },
      discovery: discoveryView(this.raven),
      history: this.domain.history,
      ownerCommitment: await pubkeyOwner(await this.keyRepo.getSelfSpendPub()),
      domain: {
        chainId: this.chainId,
        poolAddress: this.darkPool.target.toString(),
        deploymentAnchor: this.domain.deploymentAnchor,
      },
    });
    await preflight.take(2);
    if (issued.length !== 2)
      throw new Error(
        `${this.name}: preflight skipped ${issued.length - 2} candidates; refusing to guess which were cleared`,
      );
    return [issued[0]!, issued[1]!];
  }

  /** Raven's path for an owned note at a count the wallet picks, checked like witnessFor. */
  async witnessAt(n: WalletNote, leafCount: number) {
    const w = await this.raven.merkleWitness(Number(n.leafIndex), leafCount);
    if (!w.leaf.equals(n.commitment))
      throw new Error(
        `${this.name}: Raven's leaf ${n.leafIndex} is not the note`,
      );
    const root = w.root.toString();
    const knownRoot = await this.darkPool.isKnownRoot(root);
    const chainRoot = await this.chainRootAt(w.leafCount);
    this.witnesses.push({
      leafIndex: w.leafIndex,
      leafCount: w.leafCount,
      block: w.block,
      root,
      knownRoot,
      chainRootAtCount:
        chainRoot !== undefined && BigInt(chainRoot) === BigInt(root),
    });
    if (!knownRoot)
      throw new Error(
        `${this.name}: Raven's root at ${leafCount} is not known`,
      );
    return w;
  }

  async selfSpendScalar(): Promise<Fr> {
    return this.account.getSelfSpendKey();
  }

  #input(n: WalletNote) {
    return {
      note: noteToInput(n.note),
      leaf: n.commitment,
      leafIndex: Number(n.leafIndex),
      spendScalar: n.spendScalar,
    };
  }

  pick(asset: string, min: bigint): WalletNote & { asset: string } {
    const n = this.unspent(asset).find((x) => x.note.value >= min);
    if (n === undefined)
      throw new Error(
        `${this.name}: no unspent note of ${asset} holding ${min}`,
      );
    return n;
  }

  // ---- proofs (built only from Raven-found notes and Raven paths) ----

  async proveDeposit(amount: bigint, asset: string): Promise<ProofData> {
    const [selfMint] = await this.#selfMints(1);
    const assembled = await assembleDeposit(this.ctx(), {
      value: amount,
      assetId: addressToFr(asset),
      spendScalar: await this.account.getSelfSpendKey(),
      selfMint: selfMint!,
    });
    return proveDeposit(assembled.inputs);
  }

  async proveWithdraw(
    input: WalletNote,
    amount: bigint,
    recipient: string,
    intentHash: Fr = toFr(0n),
  ): Promise<ProofData> {
    const [changeMint] = await this.#selfMints(1);
    const assembled = await assembleWithdraw(this.ctx(), {
      input: this.#input(input),
      value: amount,
      recipient: addressToFr(recipient),
      selfSpendScalar: await this.account.getSelfSpendKey(),
      changeMint: changeMint!,
      intentHash,
    });
    return proveWithdraw(assembled.inputs);
  }

  async proveTransfer(
    input: WalletNote,
    amount: bigint,
    to: Point<bigint>,
  ): Promise<ProofData> {
    let memoEph = new Fr(BigInt(ethers.hexlify(ethers.randomBytes(16))));
    while (!isEvenY(publicKey(memoEph)))
      memoEph = new Fr(BigInt(ethers.hexlify(ethers.randomBytes(16))));
    const [changeMint] = await this.#selfMints(1);
    const assembled = await assembleTransfer(this.ctx(), {
      input: this.#input(input),
      value: amount,
      recipientInPub: to,
      selfSpendScalar: await this.account.getSelfSpendKey(),
      memoEph,
      changeMint: changeMint!,
    });
    return proveTransfer(assembled.inputs);
  }

  async proveSplit(input: WalletNote, amountA: bigint): Promise<ProofData> {
    const selfMints = await this.#selfMints(2);
    const assembled = await assembleSplit(this.ctx(), {
      input: this.#input(input),
      value1: amountA,
      selfSpendScalar: await this.account.getSelfSpendKey(),
      selfMints: selfMints as readonly [
        SelfMintAuthorization,
        SelfMintAuthorization,
      ],
    });
    return proveSplit(assembled.inputs);
  }

  async proveJoin(a: WalletNote, b: WalletNote): Promise<ProofData> {
    const [selfMint] = await this.#selfMints(1);
    const assembled = await assembleJoin(this.ctx(), {
      inputA: this.#input(a),
      inputB: this.#input(b),
      selfSpendScalar: await this.account.getSelfSpendKey(),
      selfMint: selfMint!,
    });
    return proveJoin(assembled.inputs);
  }

  /** A public receiving address for an incoming public memo (a swap output or a public transfer). */
  async publicAddress(): Promise<Point<bigint>> {
    const pub = await this.account.getPublicIncomingPub(
      BigInt(this.publicIssued++),
    );
    this.saveKeys();
    return pub;
  }
  publicIssued = 0;

  /** Public memos addressed to this wallet, found as Howl finds them today: from the pool's logs. */
  async publicMemos(): Promise<DiscoveredPublicMemo[]> {
    const scanner = new PublicMemoScanner(
      this.poolLogs.view(),
      await this.account.getViewKey(),
    );
    return scanner.scan(this.domain.startBlock);
  }

  async proveClaim(memo: DiscoveredPublicMemo): Promise<ProofData> {
    const [selfMint] = await this.#selfMints(1);
    const assembled = await buildPublicClaim({
      memo,
      viewKey: await this.account.getViewKey(),
      ownerIndex: memo.ownerIndex,
      compliancePk: this.domain.compliancePk,
      complianceVersion: this.domain.complianceVersion,
      complianceHistory: this.domain.history,
      chainId: this.chainId,
      poolAddress: this.darkPool.target.toString(),
      deploymentAnchor: this.domain.deploymentAnchor,
      keys: this.keyRepo,
      selfMint: selfMint!,
      currentTimestamp: Number(
        (await this.signer.provider!.getBlock("latest"))!.timestamp,
      ),
    });
    return provePublicClaim(assembled.inputs);
  }
}
