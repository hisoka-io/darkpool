import { Fr } from "@aztec/foundation/fields";
import {
  isEvenY,
  publicKey,
  pubkeyOwner,
  type CompleteComplianceHistory,
  type IDarkAccount,
} from "@hisoka/wallets";
import type { BlockId } from "../chain/rpc.js";
import { WalletRuntimeError } from "../errors.js";
import type { StoredNote } from "../store/noteStore.js";
import {
  openRecord,
  verifyAgainstTree,
  type LeafVerification,
  type OpenCandidate,
  type OpenedNote,
} from "./open.js";
import type { DiscoveryHead, DiscoveryPort, TagMatches } from "./ports.js";

/** Tags derived per window past the highest index known to be used, and the extension past each match. */
export const DISCOVERY_LOOKAHEAD = 20;
/** Discovery derives one key per index, so the window is bounded. */
export const MAX_DISCOVERY_INDEX = 1_000_000;

export interface TagCandidate {
  readonly tag: Fr;
  readonly candidate: OpenCandidate;
}

export interface DiscoveredNote extends OpenedNote {
  readonly verification: LeafVerification;
  /** Inclusion block when the adapter reports it, else the head of the sync that found the note. */
  readonly block: BlockId;
}

export interface UnopenableRow {
  readonly leafIndex: number;
  readonly tag: Fr;
  readonly versionsTried: readonly number[];
}

export interface DiscoveryResult {
  readonly head: DiscoveryHead;
  readonly notes: readonly DiscoveredNote[];
  /** Self rows under our tags that no compliance epoch opens. Reported, never counted. */
  readonly unopenable: readonly UnopenableRow[];
  /** Rows whose opening passed but whose tree leaf differs. Dropped. */
  readonly phantoms: readonly number[];
}

function protocol(rule: string, tag: Fr, why: string): never {
  throw new WalletRuntimeError(
    "DISCOVERY_PROTOCOL",
    `discovery broke rule ${rule} for tag ${tag.toString()}: ${why}`,
    { rule, tag: tag.toString() },
  );
}

/** The port contract every adapter must meet; checked on every answer, since no adapter is trusted. */
export function checkMatches(
  tags: readonly Fr[],
  matches: readonly TagMatches[],
  cap: number,
): void {
  if (matches.length !== tags.length) {
    throw new WalletRuntimeError(
      "DISCOVERY_PROTOCOL",
      `discovery answered ${matches.length} entries for ${tags.length} tags`,
      { rule: "1", tag: "" },
    );
  }
  matches.forEach((m, i) => {
    const asked = tags[i];
    if (asked === undefined || !m.tag.equals(asked)) {
      protocol(
        "1",
        m.tag,
        `entry ${i} is not the tag asked for at that position`,
      );
    }
    if (m.positions.length > cap) {
      throw new WalletRuntimeError(
        "DISCOVERY_OCCURRENCE_CAP",
        `tag ${m.tag.toString()} matches ${m.positions.length} positions, above the cap of ${cap}`,
        {
          tag: m.tag.toString(),
          count: String(m.positions.length),
          cap: String(cap),
        },
      );
    }
    if (
      m.records.length !== m.positions.length ||
      m.blocks.length !== m.positions.length
    ) {
      protocol("1", m.tag, "positions, records and blocks differ in length");
    }
    let previous = 0;
    m.positions.forEach((position, j) => {
      if (!Number.isSafeInteger(position) || position <= previous) {
        protocol("1", m.tag, `position ${position} is 0 or not ascending`);
      }
      previous = position;
      if (m.records[j]?.leafIndex !== position) {
        protocol(
          "1",
          m.tag,
          `record ${j} is for another leaf than ${position}`,
        );
      }
    });
  });
}

/**
 * Finds every note under `candidates`. Every matched position is opened (not only the first, which can be a
 * coincidental prefix row), every opened note is compared with the verified tree leaf, and a tag above the
 * occurrence cap fails loud rather than truncating.
 */
export async function discoverNotes(
  port: DiscoveryPort,
  head: DiscoveryHead,
  candidates: readonly TagCandidate[],
  history: CompleteComplianceHistory,
  cap: number,
): Promise<DiscoveryResult> {
  const tags = candidates.map((c) => c.tag);
  const matches = await port.match(tags);
  checkMatches(tags, matches, cap);

  const notes: DiscoveredNote[] = [];
  const unopenable: UnopenableRow[] = [];
  const phantoms: number[] = [];
  const seen = new Set<string>();
  for (const [i, m] of matches.entries()) {
    const candidate = candidates[i];
    if (candidate === undefined) continue;
    for (const [j, record] of m.records.entries()) {
      const block = m.blocks[j] ?? null;
      const outcome = await openRecord(record, candidate.candidate, history, {
        ...(block === null ? {} : { block: block.number }),
      });
      if (outcome.kind === "miss") continue;
      if (outcome.kind === "unopenable") {
        unopenable.push({
          leafIndex: record.leafIndex,
          tag: m.tag,
          versionsTried: outcome.versionsTried,
        });
        continue;
      }
      const key = `${outcome.note.leafIndex}:${outcome.note.commitment.toString()}`;
      if (seen.has(key)) continue;
      seen.add(key);
      let verification: LeafVerification;
      try {
        verification = await verifyAgainstTree(
          port,
          outcome.note.leafIndex,
          outcome.note.commitment,
        );
      } catch (e) {
        if (e instanceof WalletRuntimeError && e.code === "LEAF_MISMATCH") {
          phantoms.push(outcome.note.leafIndex);
          continue;
        }
        throw e;
      }
      notes.push({
        ...outcome.note,
        verification,
        block: block ?? { number: head.block.number, hash: head.block.hash },
      });
    }
  }
  return { head, notes, unopenable, phantoms };
}

/** Self and incoming tag candidates for the indices `[from, to)`, even-y keys only. */
export async function walletCandidates(
  account: Pick<
    IDarkAccount,
    "getSelfEphemeral" | "getSelfSpendPub" | "getIncomingKey"
  >,
  family: "self" | "incoming",
  from: number,
  to: number,
): Promise<TagCandidate[]> {
  const out: TagCandidate[] = [];
  const selfOwner =
    family === "self"
      ? await pubkeyOwner(await account.getSelfSpendPub())
      : null;
  for (let index = from; index < to; index++) {
    if (family === "self" && selfOwner !== null) {
      const eph = await account.getSelfEphemeral(BigInt(index));
      const pub = publicKey(eph);
      if (!isEvenY(pub)) continue;
      out.push({
        tag: new Fr(pub[0]),
        candidate: { kind: "self", eph, index, ownerCommitment: selfOwner },
      });
    } else {
      const inKey = await account.getIncomingKey(BigInt(index));
      const pub = publicKey(inKey);
      if (!isEvenY(pub)) continue;
      out.push({
        tag: new Fr(pub[0]),
        candidate: {
          kind: "incoming",
          inKey,
          index,
          ownerCommitment: await pubkeyOwner(pub),
        },
      });
    }
  }
  return out;
}

/**
 * Discovery over the self and incoming families with a gap limit: each family is scanned in windows of
 * `DISCOVERY_LOOKAHEAD` past the highest index known used (`highWater`), and every match extends the window
 * past itself, so a note at index `highWater + 30` is still found when one lands in between.
 */
export async function discoverWallet(
  port: DiscoveryPort,
  head: DiscoveryHead,
  account: Pick<
    IDarkAccount,
    "getSelfEphemeral" | "getSelfSpendPub" | "getIncomingKey"
  >,
  history: CompleteComplianceHistory,
  highWater: { readonly self: number; readonly incoming: number },
  cap: number,
): Promise<DiscoveryResult> {
  const notes: DiscoveredNote[] = [];
  const unopenable: UnopenableRow[] = [];
  const phantoms: number[] = [];
  for (const family of ["self", "incoming"] as const) {
    let from = 0;
    let to = Math.min(
      MAX_DISCOVERY_INDEX,
      highWater[family] + DISCOVERY_LOOKAHEAD,
    );
    while (from < to) {
      const candidates = await walletCandidates(account, family, from, to);
      const found = await discoverNotes(port, head, candidates, history, cap);
      notes.push(...found.notes);
      unopenable.push(...found.unopenable);
      phantoms.push(...found.phantoms);
      const indexOf = new Map(
        candidates.map((c) => [c.tag.toString(), c.candidate.index]),
      );
      const used = [
        ...found.notes.map((n) => n.derivationIndex),
        ...found.unopenable.map((u) => indexOf.get(u.tag.toString()) ?? -1),
      ];
      const highest = used.length === 0 ? -1 : Math.max(...used);
      from = to;
      to = Math.min(
        MAX_DISCOVERY_INDEX,
        Math.max(to, highest + 1 + DISCOVERY_LOOKAHEAD),
      );
    }
  }
  return { head, notes, unopenable, phantoms };
}

/** A discovered note as the note store keeps it: unspent and not yet mirrored to PSS. */
export function storedFrom(found: DiscoveredNote): StoredNote {
  return {
    leafIndex: found.leafIndex,
    commitment: found.commitment,
    note: found.note,
    nullifier: found.nullifier,
    origin: found.origin,
    derivationIndex: found.derivationIndex,
    complianceVersion: found.complianceVersion,
    block: found.block,
    verification: found.verification,
    spent: null,
    mirrored: false,
  };
}
