export interface PssSyncConfig {
  /** Quiet period after the last local change before a background write is attempted. */
  readonly debounceMs: number;
  /** Periodic write while the wallet is open, independent of the debounce. */
  readonly flushIntervalMs: number;
  readonly requestTimeoutMs: number;
  /** Retries after a version conflict, per collection, per attempt. One, then back off. */
  readonly conflictRetries: number;
  readonly backoffMs: readonly number[];
  /** Block span per log query when sweeping spent nullifiers. */
  readonly spentScanChunkBlocks: number;
}

export const DEFAULT_SYNC_CONFIG: PssSyncConfig = {
  debounceMs: 5_000,
  flushIntervalMs: 300_000,
  requestTimeoutMs: 15_000,
  conflictRetries: 1,
  backoffMs: [1_000, 5_000, 30_000],
  spentScanChunkBlocks: 2_000,
};
