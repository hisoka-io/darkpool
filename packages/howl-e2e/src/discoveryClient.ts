import { Fr } from "@aztec/foundation/fields";
import {
  commitmentPrefixMatches,
  computePsi,
  MAX_OCCURRENCES_PER_TAG,
  demDecrypt,
  leaf as computeLeaf,
  reconstructCiphertext,
  type DiscoverySource,
  type HowlNoteRecord,
  type OccurrenceRequest,
} from "@hisoka/wallets";

// Round 1 probes occurrence 0 for every candidate tag and learns each tag's count; round 2 fetches the
// remainder in one padded batch. Two round trips regardless of history depth, which is the product claim.

export interface TagCandidate {
  readonly tag: Fr;
  /** The CEK for a row under this tag. Self rows derive it; incoming rows unwrap it from the row. */
  readonly cekFor: (record: HowlNoteRecord) => Promise<Fr>;
  /** The owner commitment this wallet would put in the note, recomputed locally and never fetched. */
  readonly ownerCommitment: Fr;
}

export interface DiscoveredNote {
  readonly tag: Fr;
  readonly leafIndex: number;
  readonly plaintext: readonly Fr[];
}

export interface SyncResult {
  readonly notes: readonly DiscoveredNote[];
  /** Rows that came back but failed the local prefix check: probe misses and other people's notes. */
  readonly rejected: number;
  /** Surfaced, not thrown: throwing lets one hostile count wedge the sync, silence loses owned notes. */
  readonly truncatedTags: readonly string[];
}

/**
 * The acceptance rule is the LEAF and is deliberately not caller-supplied: the obvious weaker check is
 * TAUTOLOGICAL, because `reconstructCiphertext` builds ciphertext word 5 from the expected owner, so
 * decrypting returns that owner for any row under any key. Only the recomputed commitment can fail.
 */
async function open(
  candidate: TagCandidate,
  record: HowlNoteRecord,
): Promise<DiscoveredNote | null> {
  try {
    const cek = await candidate.cekFor(record);
    const ciphertext = await reconstructCiphertext(
      record,
      cek,
      candidate.ownerCommitment,
    );
    const plaintext = await demDecrypt(cek, ciphertext);
    const psi = await computePsi(cek);
    const recomputed = await computeLeaf({
      noteVersion: plaintext[0],
      assetId: plaintext[1],
      noteType: plaintext[2],
      conditionsHash: plaintext[3],
      value: plaintext[4].toBigInt(),
      owner: plaintext[5],
      psi,
      parents: plaintext[6],
    });
    if (!commitmentPrefixMatches(record, recomputed)) return null;
    return { tag: candidate.tag, leafIndex: record.leafIndex, plaintext };
  } catch {
    // A row we cannot open is a miss, not an error: a cuckoo probe returns a row either way.
    return null;
  }
}

export async function syncViaDiscovery(
  source: DiscoverySource,
  candidates: readonly TagCandidate[],
): Promise<SyncResult> {
  const byTag = new Map(candidates.map((c) => [c.tag.toString(), c]));
  const notes: DiscoveredNote[] = [];
  const accepted = new Set<string>();
  const truncatedTags: string[] = [];
  let rejected = 0;

  const accept = (opened: DiscoveredNote | null): void => {
    if (opened === null) {
      rejected += 1;
      return;
    }
    const key = `${opened.tag.toString()}:${opened.leafIndex}`;
    if (accepted.has(key)) {
      rejected += 1;
      return;
    }
    accepted.add(key);
    notes.push(opened);
  };

  // ROUND 1: occurrence 0 for every candidate, plus the count that makes round 2 exact.
  const first = await source.probeFirst(candidates.map((c) => c.tag));
  const follow: OccurrenceRequest[] = [];

  for (const entry of first) {
    const candidate = byTag.get(entry.tag.toString());
    if (candidate === undefined) continue;
    if (entry.record !== null) {
      const opened = await open(candidate, entry.record);
      accept(opened);
    }
    const advertised = entry.occurrenceCount;
    const bounded = Math.min(advertised, MAX_OCCURRENCES_PER_TAG);
    if (advertised > bounded) truncatedTags.push(entry.tag.toString());
    for (let occ = 1; occ < bounded; occ++) {
      follow.push({ tag: entry.tag, occurrence: occ });
    }
  }

  // ROUND 2. Results bind POSITIONALLY, which is the real contract: Raven keeps slots in request order and
  // the client holds per-slot decode state, so a reordered response does not decode. A LENGTH mismatch is
  // what that does not survive, since it would pair a record with the wrong tag.
  const rest = await source.fetchOccurrences(follow);
  if (rest.length !== follow.length) {
    throw new Error(
      `discovery round 2 returned ${rest.length} rows for ${follow.length} requests`,
    );
  }
  for (let i = 0; i < rest.length; i++) {
    const record = rest[i];
    if (record === null) continue;
    const candidate = byTag.get(follow[i].tag.toString());
    if (candidate === undefined) continue;
    const opened = await open(candidate, record);
    accept(opened);
  }

  return { notes, rejected, truncatedTags };
}

/** Local false-hit rejection. A probe returns a row on a miss, so the prefix is checked before the leaf. */
export function prefixAccepts(record: HowlNoteRecord, commitment: Fr): boolean {
  return commitmentPrefixMatches(record, commitment);
}
