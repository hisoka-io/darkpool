import { CryptoBackend } from "../crypto/backend.js";
import { selectBackend } from "../crypto/select.js";
import { openCell, sealCell } from "../crypto/aead.js";
import { PssKeys } from "../crypto/keys.js";
import { buildPutRequest } from "../crypto/sign.js";
import {
  InstallGuard,
  InstallIdentity,
  StampedPayload,
  WriteMode,
  newInstallId,
} from "../state/takeover.js";
import { VersionFloor } from "../state/floor.js";
import { MergeInput, mergeStatePayloads } from "../state/merge.js";
import {
  decodeStatePayload,
  emptyStatePayload,
  serializeStatePayload,
} from "../state/payload.js";
import { PssStateError } from "../state/errors.js";
import { PssStore, installKey, payloadKey } from "../state/store.js";
import { Collection } from "../wire/collection.js";
import { fromBase64, toHexRaw, utf8 } from "../wire/codec.js";
import { PssError } from "../wire/errors.js";
import { ParsedStatePayload } from "../wire/payload.js";
import { parseGetBlobResponse } from "../wire/types.js";
import { PssSyncConfig } from "./config.js";
import { PssTransport } from "./transport.js";
import { SpentOracle, pruneSpentNotes } from "./spentOracle.js";

const MS_PER_SECOND = 1000;
const STATE: Collection = "state";

export interface Degradation {
  readonly operation: string;
  readonly message: string;
}

export interface SyncState {
  readonly mode: WriteMode;
  readonly heldBy: InstallIdentity | null;
  /** PSS being unreachable, slow or hostile is a state the wallet reports, never an error it throws. */
  readonly degraded: Degradation | null;
  /** A 404 arriving against a non-zero floor: the blob is missing rather than absent. */
  readonly blobMissing: boolean;
  readonly pendingWrite: boolean;
}

export interface StateSyncDeps {
  readonly store: PssStore;
  readonly floor: VersionFloor;
  readonly transport: PssTransport;
  readonly oracle: SpentOracle;
  /** Omit to let the package probe the platform: WebCrypto where Ed25519 is available, noble elsewhere. */
  readonly backend?: CryptoBackend;
  readonly keys: PssKeys;
  readonly config: PssSyncConfig;
  readonly platform: string;
  readonly now: () => number;
  /** Supplied only on the create path; the server demands one for an account it has never seen. */
  readonly invite?: string;
}

type PullOutcome =
  | { readonly kind: "absent" }
  | { readonly kind: "missing"; readonly floor: number }
  | { readonly kind: "present"; readonly payload: ParsedStatePayload };

function isConflict(error: unknown): boolean {
  return error instanceof PssError && error.failure.code === "version_conflict";
}

function describe(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Owns one store, one version floor, one install guard, one transport and one spent-note oracle, and
 * keeps the local state and the remote blob in agreement. There is exactly one VersionFloor per account
 * here because the floor's lock serialises a single instance only: the debounce, the periodic flush and
 * the conflict retry are three writers that must share it or they can drive the floor backwards.
 */
export class StateSync {
  readonly #deps: StateSyncDeps;
  readonly #guard: InstallGuard;
  readonly #backend: CryptoBackend;
  readonly #accountPath: string;

  #local: ParsedStatePayload;
  #remote: ParsedStatePayload | null = null;
  #storedVersion = 0;
  #syncState: SyncState;
  #debounceTimer: ReturnType<typeof setTimeout> | null = null;
  #flushTimer: ReturnType<typeof setInterval> | null = null;
  #inFlight: Promise<void> = Promise.resolve();

  private constructor(
    deps: StateSyncDeps,
    guard: InstallGuard,
    backend: CryptoBackend,
    local: ParsedStatePayload,
  ) {
    this.#deps = deps;
    this.#guard = guard;
    this.#backend = backend;
    this.#accountPath = toHexRaw(deps.keys.accountId);
    this.#local = local;
    this.#syncState = {
      mode: "writer",
      heldBy: null,
      degraded: null,
      blobMissing: false,
      pendingWrite: false,
    };
  }

  /**
   * A reinstall must mint a new installId and a warm start must not, or every launch looks like a new
   * device and the takeover prompt never stops firing.
   */
  static async open(deps: StateSyncDeps): Promise<StateSync> {
    const backend = deps.backend ?? (await selectBackend());
    const account = toHexRaw(deps.keys.accountId);
    const storedInstall = await deps.store.get(installKey(account));
    const installId = storedInstall ?? newInstallId(backend);
    if (storedInstall === null) {
      await deps.store.set(installKey(account), installId);
    }
    const identity: InstallIdentity = {
      installId,
      platform: deps.platform,
    };
    const guard = new InstallGuard(identity, deps.floor);

    const cached = await deps.store.get(payloadKey(account, STATE));
    const local =
      cached === null
        ? emptyStatePayload(
            installId,
            deps.platform,
            Math.floor(deps.now() / MS_PER_SECOND),
          )
        : decodeStatePayload(cached);
    return new StateSync(deps, guard, backend, local);
  }

  get state(): SyncState {
    return this.#syncState;
  }

  get identity(): InstallIdentity {
    return this.#guard.identity;
  }

  /** Local storage is authoritative and this never touches the network. */
  current(): ParsedStatePayload {
    return this.#local;
  }

  start(): void {
    if (this.#flushTimer !== null) return;
    this.#flushTimer = setInterval(() => {
      this.#schedule(0);
    }, this.#deps.config.flushIntervalMs);
    this.#flushTimer.unref?.();
  }

  /** Clears timers and resolves. It deliberately does not write: see `update`. */
  stop(): Promise<void> {
    if (this.#flushTimer !== null) {
      clearInterval(this.#flushTimer);
      this.#flushTimer = null;
    }
    if (this.#debounceTimer !== null) {
      clearTimeout(this.#debounceTimer);
      this.#debounceTimer = null;
    }
    return this.#inFlight;
  }

  /**
   * Local storage first, then a debounced background write. Nothing waits on the network, and nothing
   * flushes on unmount: local storage already holds the data, so an exit-time write would add no
   * durability and would tell the server exactly when the wallet was closed.
   */
  async update(
    change: (current: ParsedStatePayload) => ParsedStatePayload,
  ): Promise<void> {
    this.#local = change(this.#local);
    await this.#persistLocal();
    this.#syncState = { ...this.#syncState, pendingWrite: true };
    this.#schedule(this.#deps.config.debounceMs);
  }

  /**
   * Runs the pending write now rather than waiting for the debounce, and resolves once it has finished.
   * It queues the push directly rather than through a zero delay timer, because a timer would leave the
   * returned promise describing the previous write instead of this one.
   */
  flushNow(): Promise<void> {
    if (this.#debounceTimer !== null) {
      clearTimeout(this.#debounceTimer);
      this.#debounceTimer = null;
    }
    this.#inFlight = this.#inFlight.then(
      () => this.#pushGuarded(),
      () => this.#pushGuarded(),
    );
    return this.#inFlight;
  }

  async pull(): Promise<PullOutcome> {
    const answer = await this.#deps.transport.getBlob(this.#accountPath, STATE);
    // Re-parsed here rather than trusted from the transport. The GET response carries no signature, so
    // the transport is not a trust boundary and a hand-written one must not be able to widen what the
    // loop will look at.
    const remote = answer === null ? null : parseGetBlobResponse(answer);
    if (remote === null) {
      const floor = await this.#deps.floor.current(STATE);
      // A 404 is "fresh account" only when this install has never seen a version. With a non-zero floor
      // the blob is missing rather than absent, and promoting to writer here would let a server that
      // dropped or is hiding the blob hand a second device the writer role.
      if (floor === 0) {
        this.#remote = null;
        this.#storedVersion = 0;
        this.#syncState = { ...this.#syncState, blobMissing: false };
        return { kind: "absent" };
      }
      this.#syncState = { ...this.#syncState, blobMissing: true };
      return { kind: "missing", floor };
    }

    // Authenticate before raising the floor. The version is bound into the AEAD's associated data, so
    // opening at the claimed version is what proves the claim. Raising the floor first would let one
    // hostile response carrying an invented version wedge the account permanently, because the floor
    // never comes back down and every honest version below it would then read as a rollback.
    const plaintext = await openCell(
      this.#backend,
      this.#deps.keys.cellKey[STATE],
      { collection: STATE, version: remote.version },
      {
        nonce: fromBase64(remote.nonce, "nonce"),
        ciphertext: fromBase64(remote.ciphertext, "ciphertext"),
      },
    );
    await this.#deps.floor.accept(STATE, remote.version);
    const payload = decodeStatePayload(new TextDecoder().decode(plaintext));
    this.#remote = payload;
    this.#storedVersion = remote.version;
    // Merged on every read, not only on conflict. Without this the next write uploads whatever this
    // install happens to hold and drops everything the other device wrote, which is precisely the
    // handover the takeover flow exists to make safe.
    this.#local = this.#mergeWithRemote(payload);
    await this.#persistLocal();
    this.#syncState = { ...this.#syncState, blobMissing: false };
    this.#applyTakeoverDecision();
    return { kind: "present", payload };
  }

  /**
   * Takeover is never automatic. This runs behind an explicit user confirmation and bootstraps the
   * chain floor before this install becomes the writer, so anything the previous device minted and did
   * not sync is still respected.
   */
  async confirmTakeover(
    chainFloors: Readonly<Record<Collection, number>>,
  ): Promise<void> {
    if (this.#remote === null) {
      throw new PssStateError(
        "takeover needs a remote payload naming the install that currently holds the account",
      );
    }
    await this.#guard.confirmTakeover(this.#remote.known, chainFloors);
    this.#applyTakeoverDecision();
  }

  /**
   * Drops notes the chain shows spent, over the whole merged note set rather than a range above the
   * checkpoint, and advances the checkpoint.
   *
   * The embedder owes the range, because this package has no chain of its own. On every load, sweep
   * from the pool's deployment block to the head BEFORE spending any note from `current()`: a
   * `fromBlock` above the stored checkpoint is rejected, since the result certifies every block up to
   * `toBlock`. `toBlock` is not clamped for finality, so on a reorg-prone chain pass
   * `head - finalityDepth` and drop `removed` logs inside the log source.
   */
  async pruneSpent(fromBlock: number, toBlock: number): Promise<number> {
    const result = await pruneSpentNotes(
      this.#local,
      this.#deps.oracle,
      fromBlock,
      toBlock,
    );
    this.#local = result.payload;
    await this.#persistLocal();
    return result.dropped.length;
  }

  #applyTakeoverDecision(): void {
    const decision = this.#guard.evaluate(this.#remote?.known ?? null);
    this.#syncState = {
      ...this.#syncState,
      mode: decision.mode,
      heldBy: decision.heldBy,
    };
  }

  #persistLocal(): Promise<void> {
    return this.#deps.store.set(
      payloadKey(toHexRaw(this.#deps.keys.accountId), STATE),
      serializeStatePayload(this.#local),
    );
  }

  #schedule(delayMs: number): void {
    if (this.#debounceTimer !== null) clearTimeout(this.#debounceTimer);
    this.#debounceTimer = setTimeout(() => {
      this.#debounceTimer = null;
      this.#inFlight = this.#inFlight.then(
        () => this.#pushGuarded(),
        () => this.#pushGuarded(),
      );
    }, delayMs);
    this.#debounceTimer.unref?.();
  }

  // Every PSS failure is caught here and becomes state. Nothing rethrows into a caller, so no PSS
  // outage can block a spend and no rejection escapes unhandled.
  async #pushGuarded(): Promise<void> {
    try {
      await this.#push();
      this.#syncState = {
        ...this.#syncState,
        degraded: null,
        pendingWrite: false,
      };
    } catch (error) {
      // No sleep schedule: the periodic flush is the retry cadence, and it already exceeds any backoff
      // step this loop would have used, so a schedule here would retry sooner rather than later.
      this.#syncState = {
        ...this.#syncState,
        degraded: { operation: "push", message: describe(error) },
      };
    }
  }

  async #push(): Promise<void> {
    if (this.#syncState.mode !== "writer") {
      throw new PssStateError(
        `this install is read-only: the account is active on ` +
          `${this.#syncState.heldBy?.platform ?? "another device"}`,
      );
    }
    const stamped = this.#stampCurrent();
    try {
      await this.#writeOnce(
        stamped,
        this.#storedVersion + 1,
        this.#storedVersion,
      );
      this.#storedVersion += 1;
      await this.#acceptOwnWrite(this.#storedVersion);
      return;
    } catch (error) {
      if (!isConflict(error) || this.#deps.config.conflictRetries < 1) {
        throw error;
      }
    }

    // Re-read, merge, retry once, then back off. The retry goes back through the same seal-sign-send
    // path, so the bumped version is the version the ciphertext was sealed under; reusing the previous
    // seal would produce a request the server accepts and the owner can never open.
    const outcome = await this.pull();
    const base =
      outcome.kind === "present"
        ? this.#mergeWithRemote(outcome.payload)
        : this.#local;
    this.#local = base;
    await this.#persistLocal();
    const next = this.#nextWrite(outcome);
    await this.#writeOnce(this.#stampCurrent(), next.version, next.prevVersion);
    this.#storedVersion = next.version;
    await this.#acceptOwnWrite(next.version);
  }

  /**
   * Raises the durable floor to a version this install just wrote and the server accepted. The client
   * authored that version, so the claim is authenticated at the source and needs no ciphertext to prove
   * it. Without this the floor moves only on a read, so a wallet that writes and is then served an
   * older version accepts the rollback, which is the protection users are told they have.
   */
  async #acceptOwnWrite(version: number): Promise<void> {
    // Raise-only, never refuse. `accept` throws on a lower version because an OFFERED lower version is
    // a rollback attempt; a version this install just wrote is not, so if the floor already sits higher
    // (a takeover bootstrap seeds it from a caller-supplied number) the right answer is to leave it.
    await this.#deps.floor.bootstrap(STATE, version);
  }

  // A missing blob recreates above the floor, never at version 1: writing below the floor is accepted
  // by the server and then trips the rollback guard on the next read, wedging the account.
  #nextWrite(outcome: PullOutcome): {
    version: number;
    prevVersion: number;
  } {
    if (outcome.kind === "missing") {
      return { version: outcome.floor + 1, prevVersion: 0 };
    }
    if (outcome.kind === "absent") return { version: 1, prevVersion: 0 };
    return {
      version: this.#storedVersion + 1,
      prevVersion: this.#storedVersion,
    };
  }

  #mergeWithRemote(remote: ParsedStatePayload): ParsedStatePayload {
    const inputs: readonly MergeInput[] = [
      { payload: this.#local, noteListComplete: true },
      { payload: remote, noteListComplete: true },
    ];
    return mergeStatePayloads(inputs);
  }

  #stampCurrent(): StampedPayload {
    return this.#guard.stamp(
      this.#local,
      this.#remote?.known ?? null,
      Math.floor(this.#deps.now() / MS_PER_SECOND),
    );
  }

  // Seal, sign and send in one path so a retry cannot reuse a stale piece. The nonce comes from
  // sealCell's CSPRNG draw on every call and is never carried across attempts.
  async #writeOnce(
    payload: StampedPayload,
    version: number,
    prevVersion: number,
  ): Promise<void> {
    const bytes = utf8(serializeStatePayload(payload));
    const sealed = await sealCell(
      this.#backend,
      this.#deps.keys.cellKey[STATE],
      { collection: STATE, version },
      bytes,
    );
    const body = await buildPutRequest(this.#backend, this.#deps.keys, {
      collection: STATE,
      version,
      prevVersion,
      nonce: sealed.nonce,
      ciphertext: sealed.ciphertext,
      timestamp: Math.floor(this.#deps.now() / MS_PER_SECOND),
      ...(this.#deps.invite === undefined || prevVersion !== 0
        ? {}
        : { invite: this.#deps.invite }),
    });
    await this.#deps.transport.putBlob(this.#accountPath, STATE, body);
  }
}
