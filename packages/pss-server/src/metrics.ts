export const ROUTE_NAMES = [
  "blob_get",
  "blob_put",
  "account_delete",
  "other",
] as const;

export type RouteName = (typeof ROUTE_NAMES)[number];

export interface RequestCounters {
  record(route: RouteName, status: number): void;
  snapshot(): Readonly<Record<string, number>>;
}

const STATUS_CLASS_DIVISOR = 100;

// Coarse buckets are the whole point: a key is a route and a status class, never an account and never
// an instant, so no access record can be joined against a chain event.
class BucketedCounters implements RequestCounters {
  readonly #counts = new Map<string, number>();

  record(route: RouteName, status: number): void {
    const bucket = `${route}.${Math.floor(status / STATUS_CLASS_DIVISOR)}xx`;
    this.#counts.set(bucket, (this.#counts.get(bucket) ?? 0) + 1);
  }

  snapshot(): Readonly<Record<string, number>> {
    return Object.fromEntries([...this.#counts].sort());
  }
}

export function createCounters(): RequestCounters {
  return new BucketedCounters();
}
