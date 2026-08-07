import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";
import {
  GCM_NONCE_BYTES,
  PSS_STATUS,
  deletePreimage,
  toBase64,
} from "@hisoka/pss-client/wire";
import { createReplayGuard } from "../replayGuard.js";
import { createRateLimiter } from "../rateLimit.js";
import {
  type Harness,
  type TestAccount,
  insertInvite,
  newAccount,
  signedPut,
  startHarness,
} from "./harness.js";

function blobPath(who: TestAccount, collection: string): string {
  return `/v1/blob/${who.path}/${collection}`;
}

const INVITE = "invite-code-replay";
const SKEW_SECONDS = 300;

function signedDelete(
  account: TestAccount,
  timestamp: number,
): { body: string } {
  const nonce = Uint8Array.from(randomBytes(GCM_NONCE_BYTES));
  const preimage = deletePreimage({
    accountId: account.accountId,
    nonce,
    timestamp,
  });
  return {
    body: JSON.stringify({
      authPk: toBase64(account.authPk),
      sig: toBase64(account.sign(preimage)),
      timestamp,
      nonce: toBase64(nonce),
    }),
  };
}

describe("replay guard unit", () => {
  it("remembers a signature only for the window", () => {
    let nowMs = 1_000_000;
    const guard = createReplayGuard({
      windowSeconds: 10,
      capacity: 100,
      now: () => nowMs,
    });
    expect(guard.seen("aa")).toBe(false);
    guard.record("aa", Math.floor(nowMs / 1000));
    expect(guard.seen("aa")).toBe(true);
    nowMs += 11_000;
    expect(guard.seen("aa")).toBe(false);
  });

  it("stays bounded by capacity", () => {
    const guard = createReplayGuard({
      windowSeconds: 10_000,
      capacity: 8,
      now: () => 0,
    });
    for (let i = 0; i < 200; i++) guard.record(`sig-${i}`, 0);
    expect(guard.size()).toBeLessThanOrEqual(8);
  });
});

describe("rate limiter bound", () => {
  it("does not grow with the number of accounts that ever sent a request", () => {
    const limiter = createRateLimiter({
      writesPerHour: 60,
      burst: 10,
      maxTrackedAccounts: 64,
      now: () => 0,
    });
    for (let i = 0; i < 5000; i++) limiter.take(`account-${i}`);
    expect(limiter.size()).toBeLessThanOrEqual(64);
  });

  it("still limits an account it is actively tracking", () => {
    const limiter = createRateLimiter({
      writesPerHour: 60,
      burst: 3,
      maxTrackedAccounts: 64,
      now: () => 0,
    });
    expect([1, 2, 3].map(() => limiter.take("a"))).toEqual([true, true, true]);
    expect(limiter.take("a")).toBe(false);
  });
});

describe("replay over HTTP", () => {
  let harness: Harness;
  let account: TestAccount;

  beforeEach(async () => {
    harness = await startHarness();
    account = newAccount();
    insertInvite(harness.db, INVITE);
  });
  afterEach(async () => {
    await harness.stop();
  });

  async function create(): Promise<void> {
    const reply = await harness.send(
      "PUT",
      blobPath(account, "state"),
      JSON.stringify(
        signedPut(account, "state", harness.seconds(), { invite: INVITE }),
      ),
    );
    expect(reply.status).toBe(PSS_STATUS.ok);
  }

  it("refuses a captured DELETE replayed after the owner writes again", async () => {
    await create();
    const captured = signedDelete(account, harness.seconds());

    const first = await harness.send(
      "DELETE",
      `/v1/blob/${account.path}`,
      captured.body,
    );
    expect(first.status).toBe(PSS_STATUS.ok);
    expect(harness.store.get(account.accountId, "state")).toBeNull();

    // The owner comes back and writes new state well inside the skew window.
    insertInvite(harness.db, `${INVITE}-2`);
    const rewrite = await harness.send(
      "PUT",
      blobPath(account, "state"),
      JSON.stringify(
        signedPut(account, "state", harness.seconds(), {
          invite: `${INVITE}-2`,
          ciphertext: Uint8Array.of(9, 9, 9, 9),
        }),
      ),
    );
    expect(rewrite.status).toBe(PSS_STATUS.ok);

    const replayed = await harness.send(
      "DELETE",
      `/v1/blob/${account.path}`,
      captured.body,
    );
    expect(replayed.status).toBe(PSS_STATUS.unauthorized);
    expect(harness.store.get(account.accountId, "state")).not.toBeNull();
  });

  it("lets the owner delete again with a fresh nonce", async () => {
    await create();
    const first = await harness.send(
      "DELETE",
      `/v1/blob/${account.path}`,
      signedDelete(account, harness.seconds()).body,
    );
    expect(first.status).toBe(PSS_STATUS.ok);
    const second = await harness.send(
      "DELETE",
      `/v1/blob/${account.path}`,
      signedDelete(account, harness.seconds()).body,
    );
    expect(second.status).toBe(PSS_STATUS.ok);
  });

  it("refuses a captured PUT replayed to resurrect a deleted account", async () => {
    const body = JSON.stringify(
      signedPut(account, "state", harness.seconds(), { invite: INVITE }),
    );
    expect(
      (await harness.send("PUT", blobPath(account, "state"), body)).status,
    ).toBe(PSS_STATUS.ok);

    expect(
      (
        await harness.send(
          "DELETE",
          `/v1/blob/${account.path}`,
          signedDelete(account, harness.seconds()).body,
        )
      ).status,
    ).toBe(PSS_STATUS.ok);
    expect(harness.store.get(account.accountId, "state")).toBeNull();

    const resurrect = await harness.send(
      "PUT",
      blobPath(account, "state"),
      body,
    );
    expect(resurrect.status).not.toBe(PSS_STATUS.ok);
    expect(harness.store.get(account.accountId, "state")).toBeNull();
  });

  it("forgets a signature once the window has passed", async () => {
    await create();
    const captured = signedDelete(account, harness.seconds());
    expect(
      (await harness.send("DELETE", `/v1/blob/${account.path}`, captured.body))
        .status,
    ).toBe(PSS_STATUS.ok);

    harness.advance(SKEW_SECONDS * 3 * 1000);
    // The guard has forgotten it, but the timestamp is now outside the skew window, so the request is
    // still refused. The two defences are independent and the outer one is what bounds the cache.
    const late = await harness.send(
      "DELETE",
      `/v1/blob/${account.path}`,
      captured.body,
    );
    expect(late.status).toBe(PSS_STATUS.unauthorized);
  });
});

describe("delete body size", () => {
  let harness: Harness;
  let account: TestAccount;

  beforeEach(async () => {
    harness = await startHarness();
    account = newAccount();
  });
  afterEach(async () => {
    await harness.stop();
  });

  it("accepts a legal delete that is not compactly serialised", async () => {
    const nonce = Uint8Array.from(randomBytes(GCM_NONCE_BYTES));
    const timestamp = harness.seconds();
    const preimage = deletePreimage({
      accountId: account.accountId,
      nonce,
      timestamp,
    });
    const pretty = JSON.stringify(
      {
        authPk: toBase64(account.authPk),
        sig: toBase64(account.sign(preimage)),
        timestamp,
        nonce: toBase64(nonce),
      },
      null,
      2,
    );
    const reply = await harness.send(
      "DELETE",
      `/v1/blob/${account.path}`,
      pretty,
    );
    expect(reply).toEqual({ status: PSS_STATUS.ok, body: "" });
  });

  it("answers an oversized delete body with 413", async () => {
    const padded = JSON.stringify({
      authPk: toBase64(account.authPk),
      sig: toBase64(account.sign(Uint8Array.of(1))),
      timestamp: harness.seconds(),
      nonce: toBase64(Uint8Array.from(randomBytes(GCM_NONCE_BYTES))),
      filler: "x".repeat(4096),
    });
    const reply = await harness.send(
      "DELETE",
      `/v1/blob/${account.path}`,
      padded,
    );
    expect(reply).toEqual({
      status: PSS_STATUS.payload_too_large,
      body: "",
    });
  });
});

describe("method not allowed", () => {
  let harness: Harness;

  beforeEach(async () => {
    harness = await startHarness();
  });
  afterEach(async () => {
    await harness.stop();
  });

  it("counts a delete route and an unrouted path in their own buckets", async () => {
    const account = newAccount();
    await harness.send(
      "DELETE",
      `/v1/blob/${account.path}`,
      JSON.stringify({
        authPk: toBase64(account.authPk),
        sig: toBase64(account.sign(Uint8Array.of(1, 2, 3))),
        timestamp: harness.seconds(),
        nonce: toBase64(Uint8Array.from(randomBytes(GCM_NONCE_BYTES))),
      }),
    );
    await harness.send("GET", "/not-a-route");
    const snapshot = harness.counters.snapshot();
    expect(Object.keys(snapshot)).toEqual(
      expect.arrayContaining(["account_delete.4xx", "other.4xx"]),
    );
    for (const key of Object.keys(snapshot)) {
      expect(key).not.toMatch(/[0-9a-f]{16}/);
    }
  });
});
