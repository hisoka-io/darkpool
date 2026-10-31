import { Fr } from "@aztec/foundation/fields";
import {
  CIPHERTEXT_KEPT_INDICES,
  COMMITMENT_PREFIX_BYTES,
  HOWL_NOTE_LAYOUT_VERSION,
  RECORD_KIND_SELF,
  type DiscoverySource,
  type FirstOccurrence,
  type HowlNoteRecord,
  type OccurrenceRequest,
} from "@hisoka/wallets";
import { WalletRuntimeError } from "../errors.js";
import { checkMatches } from "./sync.js";
import type { DiscoveryHead, DiscoveryPort, TagMatches } from "./ports.js";

/** What a padded probe returns on a miss: a well-formed row that opens as nothing. */
function paddedMiss(): HowlNoteRecord {
  return {
    layoutVersion: HOWL_NOTE_LAYOUT_VERSION,
    recordKind: RECORD_KIND_SELF,
    leafIndex: 0,
    commitmentPrefix: new Uint8Array(COMMITMENT_PREFIX_BYTES),
    ephemeralPkX: Fr.ZERO,
    cekWrap: Fr.ZERO,
    ciphertextKept: CIPHERTEXT_KEPT_INDICES.map(() => Fr.ZERO),
  };
}

/**
 * The wallets `DiscoverySource` that self-mint preflight and counter reconcile take, served from a
 * `DiscoveryPort`. Each probe syncs the port to `latest` first and reports the FULL matched count, so
 * `occurrenceCount` sees unconfirmed notes and every coincidental prefix match: under the skip rule any
 * candidate with a match is burned, and only a zero-match candidate is free. A sync that rewound is handed
 * to `onRewind` before the probe is answered; it may throw to stop the caller.
 */
export function discoverySourceOver(
  port: DiscoveryPort,
  cap: number,
  onRewind: (head: DiscoveryHead & { readonly rewoundTo: number }) => void,
): DiscoverySource {
  let last = new Map<string, TagMatches>();
  return {
    async probeFirst(tags): Promise<readonly FirstOccurrence[]> {
      const head = await port.sync();
      if (head.rewoundTo !== undefined) {
        onRewind({ ...head, rewoundTo: head.rewoundTo });
      }
      const matches = await port.match(tags);
      checkMatches(tags, matches, cap);
      last = new Map(matches.map((m) => [m.tag.toString(), m]));
      return matches.map((m) => ({
        tag: m.tag,
        record: m.records[0] ?? paddedMiss(),
        occurrenceCount: m.positions.length,
      }));
    },
    async fetchOccurrences(
      requests: readonly OccurrenceRequest[],
    ): Promise<readonly (HowlNoteRecord | null)[]> {
      return requests.map(
        (r) => last.get(r.tag.toString())?.records[r.occurrence] ?? null,
      );
    },
    fetchLeafBlock(blockIndex: number): Promise<readonly Fr[]> {
      return Promise.reject(
        new WalletRuntimeError(
          "DISCOVERY_UNAVAILABLE",
          `leaf block ${blockIndex} is not served through the preflight view; spend paths come from the WitnessPort`,
          { adapter: "discoverySourceOver", operation: "fetchLeafBlock" },
        ),
      );
    },
  };
}
