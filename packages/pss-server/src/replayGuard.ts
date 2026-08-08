export interface ReplayGuardOptions {
  readonly windowSeconds: number;
  readonly capacity: number;
  readonly now: () => number;
}

export interface ReplayGuard {
  seen(signature: string): boolean;
  record(signature: string, nowSeconds: number): void;
  size(): number;
}

const MS_PER_SECOND = 1000;

// A signed request stays valid for the whole skew window, so without this a captured body can be sent
// again inside it. That matters most on DELETE, where the nonce exists precisely to make each request
// distinct and does nothing unless something remembers it: replaying a captured delete after the owner
// has written again erases the newer state. It also closes the PUT case, where a replay is otherwise
// refused only because the stored version already advanced, which stops being true once the account has
// been deleted.
//
// Keyed by the signature because it is unique per distinct signed request and is already authenticated
// by the time it is recorded. Entries live in process and expire with the window, so no request leaves
// a durable (account, instant) trace. Only a request that changed state is recorded: a signature is
// free to mint, so a request naming an account with no rows must cost no entry, or the map fills from
// nothing and evicts real entries inside the skew window. A legitimate retry after a version conflict
// carries a new version and therefore a new signature.
class WindowedReplayGuard implements ReplayGuard {
  readonly #seenAt = new Map<string, number>();
  readonly #windowSeconds: number;
  readonly #capacity: number;
  readonly #now: () => number;

  constructor(options: ReplayGuardOptions) {
    this.#windowSeconds = options.windowSeconds;
    this.#capacity = options.capacity;
    this.#now = options.now;
  }

  seen(signature: string): boolean {
    const at = this.#seenAt.get(signature);
    if (at === undefined) return false;
    if (this.#expired(at)) {
      this.#seenAt.delete(signature);
      return false;
    }
    return true;
  }

  record(signature: string, nowSeconds: number): void {
    this.#prune();
    this.#seenAt.set(signature, nowSeconds);
    while (this.#seenAt.size > this.#capacity) {
      const oldest = this.#seenAt.keys().next();
      if (oldest.done === true) return;
      this.#seenAt.delete(oldest.value);
    }
  }

  size(): number {
    return this.#seenAt.size;
  }

  #expired(at: number): boolean {
    return Math.floor(this.#now() / MS_PER_SECOND) - at > this.#windowSeconds;
  }

  #prune(): void {
    for (const [signature, at] of this.#seenAt) {
      if (!this.#expired(at)) break;
      this.#seenAt.delete(signature);
    }
  }
}

export function createReplayGuard(options: ReplayGuardOptions): ReplayGuard {
  return new WindowedReplayGuard(options);
}
