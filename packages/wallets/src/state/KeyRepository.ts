import { Fr } from "@aztec/foundation/fields";
import { Point } from "@zk-kit/baby-jubjub";
import { DarkAccount } from "../keys/DarkAccount.js";
import { isEvenY, publicKey } from "../note/keys.js";
import {
  IKeyRepository,
  IncomingAddress,
  KeyRepoState,
  SelfEphemeral,
} from "../repositories.js";
import {
  EphemeralCounterStore,
  SealedEphemeralCounterStore,
} from "./EphemeralCounterStore.js";

const DEFAULT_LOOKAHEAD_WINDOW = 20;
// Tags are injective only for even-y points, so mint/issue roll to the next even-y index; this bound
// only guards a non-terminating loop.
const MAX_INDEX_ROLL = 256;
// A corrupt persisted counter must never force an unbounded key-registration loop on restore.
const MAX_KEY_INDEX = 1_000_000;

const SELF_EPH_SCOPE = "self";
// Pre-persist the whole even-y roll in one durable reserve; a crash then skips at most this many indices, which
// the scan lookahead absorbs. Reusing an index is catastrophic (two-time-pad); skipping is free.
const SELF_EPH_ROLL_MARGIN = MAX_INDEX_ROLL;

function clampIndex(value: number, floor: number): number {
  if (!Number.isFinite(value)) return floor;
  return Math.min(Math.max(Math.floor(value), floor), MAX_KEY_INDEX);
}

export class KeyRepository implements IKeyRepository {
  #selfMintCounter = 0;
  #selfScanIndex = 0;
  #incomingIssueCounter = 0;
  #incomingScanIndex = 0;
  #highestMatchedSelf = -1;
  #highestMatchedIncoming = -1;

  #selfMap = new Map<string, { eph: Fr; index: number }>();
  #incomingMap = new Map<string, { inKey: Fr; index: number }>();

  // Serializes the durable counters so two concurrent mints/issues can never reserve the same index.
  #lock: Promise<unknown> = Promise.resolve();

  // counter defaults to a fail-closed sealed store: minting refuses unless a durable EphemeralCounterStore (or an
  // explicit InMemoryEphemeralCounterStore for tests) is provided, so a self-eph index can never be silently
  // reused from a non-durable counter.
  constructor(
    private readonly account: DarkAccount,
    private readonly counter: EphemeralCounterStore = new SealedEphemeralCounterStore(),
  ) {}

  public get selfScanIndex(): number {
    return this.#selfScanIndex;
  }
  public get incomingScanIndex(): number {
    return this.#incomingScanIndex;
  }

  public getSelfSpendScalar(): Promise<Fr> {
    return this.account.getSelfSpendKey();
  }
  public getSelfSpendPub(): Promise<Point<bigint>> {
    return this.account.getSelfSpendPub();
  }

  public nextSelfEphemeral(): Promise<SelfEphemeral> {
    return this.#withLock(async () => {
      // The durable reserve is the persist-before-use barrier: the index range is flushed before any eph is
      // derived, so a crash mid-mint can never reissue an index (worst case it skips the unused roll tail).
      const res = await this.counter.reserve(
        SELF_EPH_SCOPE,
        SELF_EPH_ROLL_MARGIN,
      );
      for (let index = res.base; index < res.base + res.span; index++) {
        const eph = await this.account.getSelfEphemeral(BigInt(index));
        const ephPub = publicKey(eph);
        if (!isEvenY(ephPub)) continue;
        await res.commit(index);
        this.#selfMintCounter = Math.max(this.#selfMintCounter, index + 1);
        this.#selfMap.set(tagKey(ephPub[0]), { eph, index });
        if (this.#selfScanIndex < index + 1) this.#selfScanIndex = index + 1;
        return { eph, ephPub, index };
      }
      await res.release();
      throw new Error(
        `no even-y self ephemeral within ${res.span} indices from ${res.base}`,
      );
    });
  }

  public nextIncomingAddress(): Promise<IncomingAddress> {
    return this.#withLock(async () => {
      const start = this.#incomingIssueCounter;
      for (let index = start; index < start + MAX_INDEX_ROLL; index++) {
        const inKey = await this.account.getIncomingKey(BigInt(index));
        const inPub = publicKey(inKey);
        if (!isEvenY(inPub)) continue;
        this.#incomingIssueCounter = index + 1;
        this.#incomingMap.set(tagKey(inPub[0]), { inKey, index });
        if (this.#incomingScanIndex < index + 1)
          this.#incomingScanIndex = index + 1;
        return { inKey, inPub, index };
      }
      throw new Error(
        `no even-y incoming address within ${MAX_INDEX_ROLL} indices from ${start}`,
      );
    });
  }

  public async ensureSelfLookahead(window: number): Promise<boolean> {
    const target = Math.max(
      this.#selfScanIndex,
      this.#highestMatchedSelf + 1 + window,
    );
    let advanced = false;
    while (this.#selfScanIndex < target) {
      await this.#registerSelf(this.#selfScanIndex++);
      advanced = true;
    }
    return advanced;
  }

  public async ensureIncomingLookahead(window: number): Promise<boolean> {
    const target = Math.max(
      this.#incomingScanIndex,
      this.#highestMatchedIncoming + 1 + window,
    );
    let advanced = false;
    while (this.#incomingScanIndex < target) {
      await this.#registerIncoming(this.#incomingScanIndex++);
      advanced = true;
    }
    return advanced;
  }

  public matchSelfTag(tag: bigint | string): { eph: Fr; index: number } | null {
    const match = this.#selfMap.get(tagKey(BigInt(tag))) ?? null;
    if (match && match.index > this.#highestMatchedSelf) {
      this.#highestMatchedSelf = match.index;
    }
    return match;
  }

  public matchIncomingTag(
    tag: bigint | string,
  ): { inKey: Fr; index: number } | null {
    const match = this.#incomingMap.get(tagKey(BigInt(tag))) ?? null;
    if (match && match.index > this.#highestMatchedIncoming) {
      this.#highestMatchedIncoming = match.index;
    }
    return match;
  }

  public recordIncomingMatch(index: number): void {
    if (index > this.#highestMatchedIncoming) {
      this.#highestMatchedIncoming = index;
    }
  }

  public getState(): KeyRepoState {
    return {
      selfMintCounter: this.#selfMintCounter,
      selfScanIndex: this.#selfScanIndex,
      incomingIssueCounter: this.#incomingIssueCounter,
      incomingScanIndex: this.#incomingScanIndex,
      highestMatchedSelf: this.#highestMatchedSelf,
      highestMatchedIncoming: this.#highestMatchedIncoming,
    };
  }

  public async restore(state: KeyRepoState): Promise<void> {
    this.#selfMintCounter = Math.max(
      this.#selfMintCounter,
      clampIndex(state.selfMintCounter, 0),
    );
    // Reconcile the durable counter up to the restored high-water so a reserve() can never hand out an index
    // below an already-issued one (the store is the authority; a snapshot only advances it, never rewinds).
    const selfHighWater = await this.counter.highWater(SELF_EPH_SCOPE);
    if (selfHighWater < this.#selfMintCounter) {
      await this.counter.reserve(
        SELF_EPH_SCOPE,
        this.#selfMintCounter - selfHighWater,
      );
    }
    this.#incomingIssueCounter = Math.max(
      this.#incomingIssueCounter,
      clampIndex(state.incomingIssueCounter, 0),
    );
    this.#highestMatchedSelf = Math.max(
      this.#highestMatchedSelf,
      clampIndex(state.highestMatchedSelf, -1),
    );
    this.#highestMatchedIncoming = Math.max(
      this.#highestMatchedIncoming,
      clampIndex(state.highestMatchedIncoming, -1),
    );

    const selfTarget = Math.max(
      clampIndex(state.selfScanIndex, 0),
      this.#selfMintCounter,
    );
    while (this.#selfScanIndex < selfTarget) {
      await this.#registerSelf(this.#selfScanIndex++);
    }
    const incomingTarget = Math.max(
      clampIndex(state.incomingScanIndex, 0),
      this.#incomingIssueCounter,
    );
    while (this.#incomingScanIndex < incomingTarget) {
      await this.#registerIncoming(this.#incomingScanIndex++);
    }

    await this.ensureSelfLookahead(DEFAULT_LOOKAHEAD_WINDOW);
    await this.ensureIncomingLookahead(DEFAULT_LOOKAHEAD_WINDOW);
  }

  async #registerSelf(index: number): Promise<void> {
    const eph = await this.account.getSelfEphemeral(BigInt(index));
    const ephPub = publicKey(eph);
    if (!isEvenY(ephPub)) return;
    const key = tagKey(ephPub[0]);
    if (!this.#selfMap.has(key)) this.#selfMap.set(key, { eph, index });
  }

  async #registerIncoming(index: number): Promise<void> {
    const inKey = await this.account.getIncomingKey(BigInt(index));
    const inPub = publicKey(inKey);
    if (!isEvenY(inPub)) return;
    const key = tagKey(inPub[0]);
    if (!this.#incomingMap.has(key))
      this.#incomingMap.set(key, { inKey, index });
  }

  #withLock<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.#lock.then(fn, fn);
    this.#lock = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }
}

function tagKey(x: bigint): string {
  return new Fr(x).toString();
}
