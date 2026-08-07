import { describe, expect, it } from "vitest";
import { WRITES_PER_HOUR, WRITE_BURST } from "@hisoka/pss-client/wire";
import { type RateLimiter, createRateLimiter } from "../rateLimit.js";

const MS_PER_HOUR = 3_600_000;
const REFILL_MS = MS_PER_HOUR / WRITES_PER_HOUR;
const TRACKED_ACCOUNT_CAP = 1000;

function limiter(): { limiter: RateLimiter; advance: (ms: number) => void } {
  let now = 0;
  return {
    limiter: createRateLimiter({
      writesPerHour: WRITES_PER_HOUR,
      burst: WRITE_BURST,
      maxTrackedAccounts: TRACKED_ACCOUNT_CAP,
      now: () => now,
    }),
    advance: (ms) => {
      now += ms;
    },
  };
}

describe("write rate limit", () => {
  it("allows the burst and then refuses", () => {
    const { limiter: limit } = limiter();
    for (let i = 0; i < WRITE_BURST; i++) {
      expect(limit.take("account")).toBe(true);
    }
    expect(limit.take("account")).toBe(false);
  });

  it("grants a token only once it has been earned", () => {
    const { limiter: limit, advance } = limiter();
    for (let i = 0; i < WRITE_BURST; i++) limit.take("account");
    advance(REFILL_MS - 1);
    expect(limit.take("account")).toBe(false);
    advance(1);
    expect(limit.take("account")).toBe(true);
    expect(limit.take("account")).toBe(false);
  });

  it("never refills past the burst", () => {
    const { limiter: limit, advance } = limiter();
    limit.take("account");
    advance(MS_PER_HOUR * 10);
    for (let i = 0; i < WRITE_BURST; i++) {
      expect(limit.take("account")).toBe(true);
    }
    expect(limit.take("account")).toBe(false);
  });

  it("counts each account separately", () => {
    const { limiter: limit } = limiter();
    for (let i = 0; i < WRITE_BURST; i++) limit.take("first");
    expect(limit.take("first")).toBe(false);
    expect(limit.take("second")).toBe(true);
  });

  it("drops a fully refilled bucket and keeps a spent one", () => {
    const { limiter: limit, advance } = limiter();
    limit.take("idle");
    for (let i = 0; i < WRITE_BURST; i++) limit.take("busy");
    expect(limit.size()).toBe(2);

    advance(REFILL_MS);
    expect(limit.sweepIdle()).toBe(1);
    expect(limit.size()).toBe(1);

    advance(MS_PER_HOUR);
    expect(limit.sweepIdle()).toBe(1);
    expect(limit.size()).toBe(0);
  });
});
