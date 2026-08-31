import { Fr } from "@aztec/foundation/fields";
import { Point } from "@zk-kit/baby-jubjub";
import type { DerivedEph } from "../types/ephemeral.js";
import { claimDerivedSelfMintCandidate } from "../types/ephemeral.js";
import { demDecrypt } from "../crypto/dem.js";
import { deriveCek } from "../crypto/kem.js";
import { computePsi } from "../note/nullifier.js";
import { leaf as computeLeaf } from "../note/note.js";
import {
  assertCompleteComplianceHistory,
  type CompleteComplianceHistory,
} from "../note/complianceKeys.js";
import { publicKey } from "../note/keys.js";
import { commitmentPrefixMatches } from "./codec.js";
import { reconstructCiphertext } from "./reconstruct.js";
import {
  COMMITMENT_PREFIX_BYTES,
  CIPHERTEXT_KEPT_INDICES,
  HOWL_NOTE_LAYOUT_VERSION,
  RECORD_KIND_INCOMING,
  RECORD_KIND_SELF,
  type DiscoverySource,
  type FirstOccurrence,
  type HowlNoteRecord,
  type SelfMintDomain,
} from "./types.js";

export const PREFLIGHT_COLLISION_BATCH_SIZE = 5;
export const MAX_PREFLIGHT_CANDIDATES = 256;

export interface SelfMintCandidate {
  readonly eph: DerivedEph;
  readonly ephPub: Point<bigint>;
  readonly tag: Fr;
  readonly index: number;
}

export interface AuthorizedSelfMintCandidate extends SelfMintCandidate {
  readonly tag: Fr;
}

/** Opaque one-shot authority. Candidate fields live only in module-private runtime state. */
export abstract class SelfMintAuthorization {
  declare private readonly authorizationBrand: void;
  protected constructor() {}
}

class IssuedSelfMintAuthorization extends SelfMintAuthorization {
  constructor() {
    super();
  }
}

/** Exact owner and current compliance state certified by a Raven preflight. */
export interface SelfMintContext {
  readonly ownerCommitment: Fr;
  readonly compliancePk: Point<bigint>;
  readonly complianceVersion: number;
  readonly complianceHistory: CompleteComplianceHistory;
  readonly chainId: bigint;
  readonly poolAddress: string;
  readonly deploymentAnchor: bigint;
}

interface AuthorizationState {
  readonly candidate: {
    readonly eph: bigint;
    readonly ephPub: readonly [bigint, bigint];
    readonly tag: bigint;
    readonly index: number;
  };
  readonly context: {
    readonly ownerCommitment: bigint;
    readonly compliancePk: readonly [bigint, bigint];
    readonly complianceVersion: number;
    readonly complianceHistory: string;
    readonly chainId: bigint;
    readonly poolAddress: string;
    readonly deploymentAnchor: bigint;
  };
  consumed: boolean;
}

const authorizationStates = new WeakMap<object, AuthorizationState>();

export interface SelfMintAllocator<T extends SelfMintCandidate> {
  next(): Promise<T>;
}

export type SelfMintPreflightFailure =
  | "INVALID_COUNT"
  | "DISCOVERY_UNAVAILABLE"
  | "DISCOVERY_PROTOCOL"
  | "CANDIDATE_OWNER_MISMATCH"
  | "CANDIDATE_PROVENANCE_MISMATCH"
  | "CANDIDATE_ALREADY_CLAIMED"
  | "CANDIDATES_EXHAUSTED";

export class SelfMintPreflightError extends Error {
  constructor(
    readonly reason: SelfMintPreflightFailure,
    message: string,
    cause?: unknown,
  ) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = "SelfMintPreflightError";
  }
}

export type SelfMintAuthorizationFailure =
  | "UNKNOWN_AUTHORIZATION"
  | "AUTHORIZATION_CONSUMED"
  | "DUPLICATE_AUTHORIZATION"
  | "CONTEXT_MISMATCH";

export class SelfMintAuthorizationError extends Error {
  constructor(
    readonly reason: SelfMintAuthorizationFailure,
    message: string,
  ) {
    super(message);
    this.name = "SelfMintAuthorizationError";
  }
}

function historyIdentity(history: CompleteComplianceHistory): string {
  assertCompleteComplianceHistory(history);
  return history.ring.epochs
    .map(
      (epoch) =>
        `${epoch.version}:${epoch.pk[0]}:${epoch.pk[1]}:${epoch.fromBlock ?? ""}`,
    )
    .join("|");
}

function sameContext(
  certified: AuthorizationState["context"],
  expected: SelfMintContext,
): boolean {
  if (
    !(expected.ownerCommitment instanceof Fr) ||
    !Array.isArray(expected.compliancePk) ||
    expected.compliancePk.length !== 2 ||
    typeof expected.compliancePk[0] !== "bigint" ||
    typeof expected.compliancePk[1] !== "bigint" ||
    typeof expected.chainId !== "bigint" ||
    typeof expected.poolAddress !== "string" ||
    typeof expected.deploymentAnchor !== "bigint"
  ) {
    return false;
  }
  return (
    certified.ownerCommitment === expected.ownerCommitment.toBigInt() &&
    certified.compliancePk[0] === expected.compliancePk[0] &&
    certified.compliancePk[1] === expected.compliancePk[1] &&
    certified.complianceVersion === expected.complianceVersion &&
    certified.complianceHistory ===
      historyIdentity(expected.complianceHistory) &&
    certified.chainId === expected.chainId &&
    certified.poolAddress === expected.poolAddress.toLowerCase() &&
    certified.deploymentAnchor === expected.deploymentAnchor
  );
}

function freezeCandidate(
  candidate: AuthorizedSelfMintCandidate,
): Readonly<AuthorizedSelfMintCandidate> {
  return Object.freeze({
    eph: new Fr(candidate.eph.toBigInt()) as DerivedEph,
    ephPub: Object.freeze([
      candidate.ephPub[0],
      candidate.ephPub[1],
    ]) as Point<bigint>,
    tag: new Fr(candidate.tag.toBigInt()),
    index: candidate.index,
  });
}

function issueAuthorization(
  candidate: AuthorizedSelfMintCandidate,
  context: SelfMintContext,
): SelfMintAuthorization {
  const handle: SelfMintAuthorization = new IssuedSelfMintAuthorization();
  Object.freeze(handle);
  authorizationStates.set(handle, {
    candidate: Object.freeze({
      eph: candidate.eph.toBigInt(),
      ephPub: Object.freeze([
        candidate.ephPub[0],
        candidate.ephPub[1],
      ]) as readonly [bigint, bigint],
      tag: candidate.tag.toBigInt(),
      index: candidate.index,
    }),
    context: Object.freeze({
      ownerCommitment: context.ownerCommitment.toBigInt(),
      compliancePk: Object.freeze([
        context.compliancePk[0],
        context.compliancePk[1],
      ]) as readonly [bigint, bigint],
      complianceVersion: context.complianceVersion,
      complianceHistory: historyIdentity(context.complianceHistory),
      chainId: context.chainId,
      poolAddress: context.poolAddress.toLowerCase(),
      deploymentAnchor: context.deploymentAnchor,
    }),
    consumed: false,
  });
  return handle;
}

/** Internal assembly seam. Intentionally excluded from every package barrel. */
export function consumeSelfMints(
  handles: readonly unknown[],
  expectedContext: SelfMintContext,
): readonly Readonly<AuthorizedSelfMintCandidate>[] {
  if (handles.length !== 1 && handles.length !== 2) {
    throw new SelfMintAuthorizationError(
      "UNKNOWN_AUTHORIZATION",
      `self-mint authorization consumption requires one or two handles, got ${handles.length}`,
    );
  }
  const unique = new Set(handles);
  if (unique.size !== handles.length) {
    throw new SelfMintAuthorizationError(
      "DUPLICATE_AUTHORIZATION",
      "duplicate self-mint authorization handle in one atomic consumption",
    );
  }
  const states: AuthorizationState[] = [];
  for (const handle of handles) {
    if (typeof handle !== "object" || handle === null) {
      throw new SelfMintAuthorizationError(
        "UNKNOWN_AUTHORIZATION",
        "self-mint authorization is unknown or was copied from a real handle",
      );
    }
    const state = authorizationStates.get(handle);
    if (state === undefined) {
      throw new SelfMintAuthorizationError(
        "UNKNOWN_AUTHORIZATION",
        "self-mint authorization is unknown or was copied from a real handle",
      );
    }
    if (state.consumed) {
      throw new SelfMintAuthorizationError(
        "AUTHORIZATION_CONSUMED",
        "self-mint authorization was already consumed by an assembly",
      );
    }
    if (!sameContext(state.context, expectedContext)) {
      throw new SelfMintAuthorizationError(
        "CONTEXT_MISMATCH",
        "self-mint authorization context does not match the owner, compliance history, or pool deployment",
      );
    }
    states.push(state);
  }
  if (
    states.length === 2 &&
    (states[0].candidate.eph === states[1].candidate.eph ||
      states[0].candidate.tag === states[1].candidate.tag)
  ) {
    throw new SelfMintAuthorizationError(
      "DUPLICATE_AUTHORIZATION",
      "distinct self-mint authorization handles resolve to the same candidate",
    );
  }
  for (const state of states) state.consumed = true;
  return states.map((state) =>
    freezeCandidate({
      eph: new Fr(state.candidate.eph) as DerivedEph,
      ephPub: [state.candidate.ephPub[0], state.candidate.ephPub[1]],
      tag: new Fr(state.candidate.tag),
      index: state.candidate.index,
    }),
  );
}

function validatedRecord(raw: unknown): HowlNoteRecord {
  if (raw === null) {
    throw new SelfMintPreflightError(
      "DISCOVERY_PROTOCOL",
      "self-mint discovery returned a null record instead of a padded Howl cell",
    );
  }
  if (typeof raw !== "object" || Array.isArray(raw)) {
    throw new SelfMintPreflightError(
      "DISCOVERY_PROTOCOL",
      "self-mint discovery record is not an object",
    );
  }
  const record = raw as Record<string, unknown>;
  if (
    record.layoutVersion !== HOWL_NOTE_LAYOUT_VERSION ||
    (record.recordKind !== RECORD_KIND_SELF &&
      record.recordKind !== RECORD_KIND_INCOMING) ||
    !Number.isInteger(record.leafIndex) ||
    (record.leafIndex as number) < 0 ||
    (record.leafIndex as number) > 0xffffffff ||
    !(record.commitmentPrefix instanceof Uint8Array) ||
    record.commitmentPrefix.length !== COMMITMENT_PREFIX_BYTES ||
    !(record.ephemeralPkX instanceof Fr) ||
    !(record.cekWrap instanceof Fr) ||
    !Array.isArray(record.ciphertextKept) ||
    record.ciphertextKept.length !== CIPHERTEXT_KEPT_INDICES.length ||
    !record.ciphertextKept.every((word) => word instanceof Fr)
  ) {
    throw new SelfMintPreflightError(
      "DISCOVERY_PROTOCOL",
      "self-mint discovery returned a malformed Howl note record",
    );
  }
  return raw as HowlNoteRecord;
}

export async function opensExistingSelfRecord(
  candidate: SelfMintCandidate,
  record: HowlNoteRecord | null,
  history: CompleteComplianceHistory,
  ownerCommitment: Fr,
): Promise<boolean> {
  assertCompleteComplianceHistory(history);
  if (record === null || record.recordKind !== RECORD_KIND_SELF) return false;

  for (const epoch of history.ring.candidatesFor()) {
    try {
      const cek = deriveCek(candidate.eph, epoch.pk);
      const ciphertext = await reconstructCiphertext(
        record,
        cek,
        ownerCommitment,
      );
      const plaintext = await demDecrypt(cek, ciphertext);
      const commitment = await computeLeaf({
        noteVersion: plaintext[0],
        assetId: plaintext[1],
        noteType: plaintext[2],
        conditionsHash: plaintext[3],
        value: plaintext[4].toBigInt(),
        owner: plaintext[5],
        psi: await computePsi(cek),
        parents: plaintext[6],
      });
      if (commitmentPrefixMatches(record, commitment)) return true;
    } catch {
      continue;
    }
  }
  return false;
}

/** Uses trusted Raven/history/domain inputs to issue owner-bound, one-shot assembly authority. */
export class SelfMintPreflight<T extends SelfMintCandidate> {
  readonly #allocator: SelfMintAllocator<T>;
  readonly #discovery: DiscoverySource;
  readonly #history: CompleteComplianceHistory;
  readonly #context: SelfMintContext;
  readonly #ready: Readonly<AuthorizedSelfMintCandidate>[] = [];
  #takeTail: Promise<void> = Promise.resolve();

  constructor(deps: {
    readonly allocator: SelfMintAllocator<T>;
    readonly discovery: DiscoverySource;
    readonly history: CompleteComplianceHistory;
    readonly ownerCommitment: Fr;
    readonly domain: SelfMintDomain;
  }) {
    assertCompleteComplianceHistory(deps.history);
    if (typeof deps.domain !== "object" || deps.domain === null) {
      throw new SelfMintPreflightError(
        "DISCOVERY_PROTOCOL",
        "self-mint preflight requires a chain, pool, and deployment domain",
      );
    }
    if (
      typeof deps.domain.chainId !== "bigint" ||
      typeof deps.domain.deploymentAnchor !== "bigint" ||
      deps.domain.chainId < 0n ||
      deps.domain.deploymentAnchor < 0n
    ) {
      throw new SelfMintPreflightError(
        "DISCOVERY_PROTOCOL",
        "self-mint chainId and deploymentAnchor must be non-negative",
      );
    }
    if (
      typeof deps.domain.poolAddress !== "string" ||
      !/^0x[0-9a-fA-F]{40}$/.test(deps.domain.poolAddress)
    ) {
      throw new SelfMintPreflightError(
        "DISCOVERY_PROTOCOL",
        `self-mint poolAddress is not a 20-byte hex address: ${deps.domain.poolAddress}`,
      );
    }
    this.#allocator = deps.allocator;
    this.#discovery = deps.discovery;
    this.#history = deps.history;
    this.#context = Object.freeze({
      ownerCommitment: new Fr(deps.ownerCommitment.toBigInt()),
      compliancePk: Object.freeze([
        deps.history.currentPk[0],
        deps.history.currentPk[1],
      ]) as Point<bigint>,
      complianceVersion: deps.history.currentVersion,
      complianceHistory: deps.history,
      chainId: deps.domain.chainId,
      poolAddress: deps.domain.poolAddress.toLowerCase(),
      deploymentAnchor: deps.domain.deploymentAnchor,
    });
  }

  take(count: 1): Promise<readonly [SelfMintAuthorization]>;
  take(
    count: 2,
  ): Promise<readonly [SelfMintAuthorization, SelfMintAuthorization]>;
  take(count: 1 | 2): Promise<readonly SelfMintAuthorization[]> {
    const execute = (): Promise<readonly SelfMintAuthorization[]> =>
      this.#take(count);
    const run = this.#takeTail.then(execute, execute);
    this.#takeTail = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  async #take(count: 1 | 2): Promise<readonly SelfMintAuthorization[]> {
    if (count !== 1 && count !== 2) {
      throw new SelfMintPreflightError(
        "INVALID_COUNT",
        `self-mint preflight requires one or two outputs, got ${count}`,
      );
    }

    let tested = 0;
    if (this.#ready.length < count) {
      const initial = await this.#allocate(count - this.#ready.length);
      tested += initial.length;
      await this.#classify(initial);
    }
    while (this.#ready.length < count) {
      const remaining = MAX_PREFLIGHT_CANDIDATES - tested;
      if (remaining === 0) {
        throw new SelfMintPreflightError(
          "CANDIDATES_EXHAUSTED",
          `self-mint preflight found no free tag after ${MAX_PREFLIGHT_CANDIDATES} candidates`,
        );
      }
      const batch = await this.#allocate(
        Math.min(PREFLIGHT_COLLISION_BATCH_SIZE, remaining),
      );
      tested += batch.length;
      await this.#classify(batch);
    }
    return this.#ready
      .splice(0, count)
      .map((candidate) => issueAuthorization(candidate, this.#context));
  }

  async #allocate(
    count: number,
  ): Promise<readonly Readonly<AuthorizedSelfMintCandidate>[]> {
    const allocated: Readonly<AuthorizedSelfMintCandidate>[] = [];
    for (let index = 0; index < count; index++) {
      const candidate = await this.#allocator.next();
      const claim = claimDerivedSelfMintCandidate(
        candidate,
        this.#context.ownerCommitment.toBigInt(),
      );
      switch (claim) {
        case "UNKNOWN":
          throw new SelfMintPreflightError(
            "DISCOVERY_PROTOCOL",
            "self-mint allocator returned a candidate without durable derivation provenance",
          );
        case "OWNER_MISMATCH":
          throw new SelfMintPreflightError(
            "CANDIDATE_OWNER_MISMATCH",
            "self-mint candidate was derived for a different wallet or multisig owner",
          );
        case "PROVENANCE_MISMATCH":
          throw new SelfMintPreflightError(
            "CANDIDATE_PROVENANCE_MISMATCH",
            "self-mint candidate fields changed after durable derivation",
          );
        case "ALREADY_CLAIMED":
          throw new SelfMintPreflightError(
            "CANDIDATE_ALREADY_CLAIMED",
            "self-mint candidate was already claimed by another preflight",
          );
        case "CLAIMED":
          break;
      }
      if (
        !(candidate.eph instanceof Fr) ||
        !(candidate.tag instanceof Fr) ||
        !Array.isArray(candidate.ephPub) ||
        candidate.ephPub.length !== 2 ||
        typeof candidate.ephPub[0] !== "bigint" ||
        typeof candidate.ephPub[1] !== "bigint"
      ) {
        throw new SelfMintPreflightError(
          "DISCOVERY_PROTOCOL",
          "self-mint allocator returned malformed derived candidate fields",
        );
      }
      const eph = new Fr(candidate.eph.toBigInt()) as DerivedEph;
      const ephPub = publicKey(eph);
      if (
        candidate.ephPub[0] !== ephPub[0] ||
        candidate.ephPub[1] !== ephPub[1] ||
        !candidate.tag.equals(new Fr(ephPub[0])) ||
        !Number.isSafeInteger(candidate.index) ||
        candidate.index < 0
      ) {
        throw new SelfMintPreflightError(
          "DISCOVERY_PROTOCOL",
          "self-mint allocator returned inconsistent scalar, public point, tag, or index fields",
        );
      }
      allocated.push(
        freezeCandidate({
          eph,
          ephPub,
          tag: new Fr(ephPub[0]),
          index: candidate.index,
        }),
      );
    }
    return allocated;
  }

  async #classify(
    candidates: readonly Readonly<AuthorizedSelfMintCandidate>[],
  ): Promise<void> {
    const requestedTags = candidates.map((candidate) =>
      candidate.tag.toBigInt(),
    );
    let rawResponse: unknown;
    try {
      rawResponse = await this.#discovery.probeFirst(
        requestedTags.map((tag) => new Fr(tag)),
      );
    } catch (error) {
      throw new SelfMintPreflightError(
        "DISCOVERY_UNAVAILABLE",
        `self-mint preflight could not query discovery for ${candidates.length} candidate tags`,
        error,
      );
    }
    if (!Array.isArray(rawResponse)) {
      throw new SelfMintPreflightError(
        "DISCOVERY_PROTOCOL",
        "self-mint discovery response is not an array",
      );
    }
    if (rawResponse.length !== candidates.length) {
      throw new SelfMintPreflightError(
        "DISCOVERY_PROTOCOL",
        `self-mint discovery returned ${rawResponse.length} rows for ${candidates.length} candidate tags`,
      );
    }

    const requested = new Map(
      candidates.map((candidate, index) => [
        new Fr(requestedTags[index]).toString(),
        candidate,
      ]),
    );
    if (requested.size !== candidates.length) {
      throw new SelfMintPreflightError(
        "DISCOVERY_PROTOCOL",
        "self-mint allocator returned duplicate candidate tags in one batch",
      );
    }
    const returned = new Map<string, FirstOccurrence>();
    for (const rawEntry of rawResponse) {
      if (
        typeof rawEntry !== "object" ||
        rawEntry === null ||
        Array.isArray(rawEntry)
      ) {
        throw new SelfMintPreflightError(
          "DISCOVERY_PROTOCOL",
          "self-mint discovery returned a non-object entry",
        );
      }
      const entry = rawEntry as Record<string, unknown>;
      if (
        !(entry.tag instanceof Fr) ||
        !Number.isSafeInteger(entry.occurrenceCount) ||
        (entry.occurrenceCount as number) < 0
      ) {
        throw new SelfMintPreflightError(
          "DISCOVERY_PROTOCOL",
          "self-mint discovery returned a malformed entry",
        );
      }
      const key = entry.tag.toString();
      if (!requested.has(key) || returned.has(key)) {
        throw new SelfMintPreflightError(
          "DISCOVERY_PROTOCOL",
          `self-mint discovery returned an unknown or duplicate tag ${key}`,
        );
      }
      returned.set(key, {
        tag: entry.tag,
        record: validatedRecord(entry.record),
        occurrenceCount: entry.occurrenceCount as number,
      });
    }

    for (const candidate of candidates) {
      const entry = returned.get(candidate.tag.toString());
      if (entry === undefined) {
        throw new SelfMintPreflightError(
          "DISCOVERY_PROTOCOL",
          `self-mint discovery omitted candidate tag ${candidate.tag.toString()}`,
        );
      }
      const occupied = await opensExistingSelfRecord(
        candidate,
        entry.record,
        this.#history,
        this.#context.ownerCommitment,
      );
      if (!occupied) this.#ready.push(freezeCandidate(candidate));
    }
  }
}
