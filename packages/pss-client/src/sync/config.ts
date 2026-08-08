export interface PssSyncConfig {
  /** Quiet period after the last local change before a background write is attempted. */
  readonly debounceMs: number;
  /** Periodic write while the wallet is open, independent of the debounce. */
  readonly flushIntervalMs: number;
  readonly requestTimeoutMs: number;
  /**
   * Retries after a version conflict. Consumed as a gate rather than a count: at `< 1` the retry is
   * skipped entirely, and any value at or above 1 performs exactly one retry. After that the write is
   * reported as degraded and the periodic flush is the retry cadence.
   */
  readonly conflictRetries: number;
  /** Block span per log query when sweeping spent nullifiers. */
  readonly spentScanChunkBlocks: number;
}

export const DEFAULT_SYNC_CONFIG: PssSyncConfig = {
  debounceMs: 5_000,
  flushIntervalMs: 300_000,
  requestTimeoutMs: 15_000,
  conflictRetries: 1,
  spentScanChunkBlocks: 2_000,
};
