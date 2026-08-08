const MS_PER_HOUR = 3_600_000;

export interface RateLimiterOptions {
  readonly writesPerHour: number;
  readonly burst: number;
  readonly maxTrackedAccounts: number;
  readonly now: () => number;
}

export interface RateLimiter {
  take(key: string): boolean;
  sweepIdle(): number;
  size(): number;
}

interface Bucket {
  tokens: number;
  at: number;
}

// In process and nowhere else. A persisted counter would be a durable (account, activity) record, which
// is the correlation data the storage design exists to avoid producing.
//
// The map is capped because an accountId costs an attacker one keypair: it is SHA256 of a public key
// they choose, with no registration step, so every signature-valid request can name a fresh account.
// Eviction is least-recently-used and carries no timestamp off this process, so bounding memory does
// not reintroduce the (accountId, instant) record the design forbids. Eviction does hand an evicted
// account a fresh full burst, so it is a limit on memory rather than on throughput; that costs nothing,
// because an attacker who can evict entries can mint new account ids instead and buy the same writes
// without the detour.
class TokenBucketLimiter implements RateLimiter {
  readonly #buckets = new Map<string, Bucket>();
  readonly #refillPerMs: number;
  readonly #burst: number;
  readonly #capacity: number;
  readonly #now: () => number;

  constructor(options: RateLimiterOptions) {
    if (
      !Number.isInteger(options.maxTrackedAccounts) ||
      options.maxTrackedAccounts < 1
    ) {
      throw new Error(
        `PSS rate limiter: maxTrackedAccounts must be a positive integer, got ${options.maxTrackedAccounts}`,
      );
    }
    this.#refillPerMs = options.writesPerHour / MS_PER_HOUR;
    this.#burst = options.burst;
    this.#capacity = options.maxTrackedAccounts;
    this.#now = options.now;
  }

  take(key: string): boolean {
    const at = this.#now();
    const existing = this.#buckets.get(key);
    const bucket = existing ?? { tokens: this.#burst, at };
    this.#refill(bucket, at);
    const allowed = bucket.tokens >= 1;
    if (allowed) bucket.tokens -= 1;
    // Re-inserting moves the key to the end of the Map's insertion order, which is what makes the
    // first key returned by keys() the least recently used one.
    if (existing !== undefined) this.#buckets.delete(key);
    this.#buckets.set(key, bucket);
    this.#evictOverflow();
    return allowed;
  }

  sweepIdle(): number {
    const at = this.#now();
    let dropped = 0;
    for (const [key, bucket] of this.#buckets) {
      this.#refill(bucket, at);
      if (bucket.tokens >= this.#burst) {
        this.#buckets.delete(key);
        dropped += 1;
      }
    }
    return dropped;
  }

  size(): number {
    return this.#buckets.size;
  }

  #evictOverflow(): void {
    while (this.#buckets.size > this.#capacity) {
      const oldest = this.#buckets.keys().next();
      if (oldest.done === true) return;
      this.#buckets.delete(oldest.value);
    }
  }

  #refill(bucket: Bucket, at: number): void {
    const elapsed = Math.max(0, at - bucket.at);
    bucket.tokens = Math.min(
      this.#burst,
      bucket.tokens + elapsed * this.#refillPerMs,
    );
    bucket.at = at;
  }
}

export function createRateLimiter(options: RateLimiterOptions): RateLimiter {
  return new TokenBucketLimiter(options);
}
