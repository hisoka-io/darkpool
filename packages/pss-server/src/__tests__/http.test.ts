import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";
import {
  type DeleteAccountRequest,
  GCM_NONCE_BYTES,
  MAX_CIPHERTEXT_BYTES,
  PSS_STATUS,
  TIMESTAMP_SKEW_SECONDS,
  WRITE_BURST,
  deletePreimage,
  fromBase64,
  toBase64,
} from "@hisoka/pss-client/wire";
import {
  type Harness,
  type TestAccount,
  insertInvite,
  newAccount,
  rawRequest,
  signedPut,
  startHarness,
} from "./harness.js";

const INVITE = "invite-one";
const MS_PER_SECOND = 1000;

let harness: Harness;
let account: TestAccount;

function blobPath(who: TestAccount, collection: string): string {
  return `/v1/blob/${who.path}/${collection}`;
}

function put(
  who: TestAccount,
  collection: "state" | "labels",
  options: Parameters<typeof signedPut>[3] = {},
): Promise<{ status: number; body: string }> {
  const body = signedPut(who, collection, harness.seconds(), options);
  return harness.send("PUT", blobPath(who, collection), JSON.stringify(body));
}

async function create(
  who: TestAccount,
  collection: "state" | "labels" = "state",
): Promise<void> {
  insertInvite(harness.db, `${INVITE}-${collection}-${who.path.slice(0, 8)}`);
  const reply = await put(who, collection, {
    invite: `${INVITE}-${collection}-${who.path.slice(0, 8)}`,
  });
  expect(reply.status).toBe(PSS_STATUS.ok);
}

function signedDelete(
  who: TestAccount,
  options: { readonly timestamp?: number; readonly signAs?: TestAccount } = {},
): string {
  const nonce = Uint8Array.from(randomBytes(GCM_NONCE_BYTES));
  const timestamp = options.timestamp ?? harness.seconds();
  const signer = options.signAs ?? who;
  const request: DeleteAccountRequest = {
    authPk: toBase64(signer.authPk),
    sig: toBase64(
      signer.sign(
        deletePreimage({ accountId: who.accountId, nonce, timestamp }),
      ),
    ),
    timestamp,
    nonce: toBase64(nonce),
  };
  return JSON.stringify(request);
}

beforeEach(async () => {
  harness = await startHarness();
  account = newAccount();
});

afterEach(async () => {
  await harness.stop();
});

describe("routing", () => {
  it("answers an unrouted path with an empty 404", async () => {
    const reply = await harness.send("GET", "/v1/nothing");
    expect(reply).toEqual({ status: PSS_STATUS.not_found, body: "" });
  });

  it("rejects a malformed account id and an unknown collection with 400", async () => {
    const bad = await harness.send("GET", "/v1/blob/notveryhex/state");
    expect(bad).toEqual({ status: PSS_STATUS.bad_request, body: "" });
    const wrongCollection = await harness.send(
      "GET",
      blobPath(account, "secrets"),
    );
    expect(wrongCollection).toEqual({
      status: PSS_STATUS.bad_request,
      body: "",
    });
  });

  it("rejects a percent-encoded collection rather than decoding it", async () => {
    const reply = await harness.send("GET", blobPath(account, "%73tate"));
    expect(reply.status).toBe(PSS_STATUS.bad_request);
  });

  it("answers a wrong method with 405", async () => {
    expect(
      (await harness.send("POST", blobPath(account, "state"))).status,
    ).toBe(405);
    expect((await harness.send("GET", `/v1/blob/${account.path}`)).status).toBe(
      405,
    );
  });
});

describe("get", () => {
  it("answers an unknown account with an empty 404", async () => {
    const reply = await harness.send("GET", blobPath(account, "state"));
    expect(reply).toEqual({ status: PSS_STATUS.not_found, body: "" });
  });

  it("returns the stored slot and the server clock", async () => {
    await create(account);
    const reply = await harness.send("GET", blobPath(account, "state"));
    expect(reply.status).toBe(PSS_STATUS.ok);
    const body: unknown = JSON.parse(reply.body);
    expect(body).toEqual({
      version: 1,
      prevVersion: 0,
      nonce: expect.any(String),
      ciphertext: toBase64(Uint8Array.of(1, 2, 3, 4)),
      serverTime: harness.seconds(),
    });
  });

  it("keeps the two collections apart", async () => {
    await create(account, "state");
    await create(account, "labels");
    const state = await harness.send("GET", blobPath(account, "state"));
    const labels = await harness.send("GET", blobPath(account, "labels"));
    expect(state.status).toBe(PSS_STATUS.ok);
    expect(labels.status).toBe(PSS_STATUS.ok);
  });
});

describe("put auth matrix", () => {
  it("accepts a create carrying an unspent invite", async () => {
    insertInvite(harness.db, INVITE);
    const reply = await put(account, "state", { invite: INVITE });
    expect(reply).toEqual({ status: PSS_STATUS.ok, body: "" });
  });

  it("refuses a create with no invite, an unknown invite or a spent one", async () => {
    const none = await put(account, "state");
    expect(none).toEqual({ status: PSS_STATUS.unauthorized, body: "" });

    const unknown = await put(account, "state", { invite: "never-issued" });
    expect(unknown).toEqual({ status: PSS_STATUS.unauthorized, body: "" });

    insertInvite(harness.db, INVITE);
    expect((await put(account, "state", { invite: INVITE })).status).toBe(
      PSS_STATUS.ok,
    );
    const second = newAccount();
    const reused = await harness.send(
      "PUT",
      blobPath(second, "state"),
      JSON.stringify(
        signedPut(second, "state", harness.seconds(), { invite: INVITE }),
      ),
    );
    expect(reused).toEqual({ status: PSS_STATUS.unauthorized, body: "" });
  });

  it("stops asking for an invite once the account owns a row", async () => {
    await create(account, "state");
    const labels = await put(account, "labels", { version: 1, prevVersion: 0 });
    expect(labels.status).toBe(PSS_STATUS.ok);
    const next = await put(account, "state", { version: 2, prevVersion: 1 });
    expect(next.status).toBe(PSS_STATUS.ok);
  });

  it("refuses a tampered signature", async () => {
    insertInvite(harness.db, INVITE);
    const body = signedPut(account, "state", harness.seconds(), {
      invite: INVITE,
    });
    const sig = fromBase64(body.sig, "sig");
    sig[0] ^= 1;
    const reply = await harness.send(
      "PUT",
      blobPath(account, "state"),
      JSON.stringify({ ...body, sig: toBase64(sig) }),
    );
    expect(reply).toEqual({ status: PSS_STATUS.unauthorized, body: "" });
  });

  it("refuses an authPk whose digest is not the path account", async () => {
    insertInvite(harness.db, INVITE);
    const stranger = newAccount();
    const reply = await harness.send(
      "PUT",
      blobPath(account, "state"),
      JSON.stringify(
        signedPut(account, "state", harness.seconds(), {
          invite: INVITE,
          signAs: stranger,
        }),
      ),
    );
    expect(reply).toEqual({ status: PSS_STATUS.unauthorized, body: "" });
  });

  it("refuses a write signed for one account and sent to another", async () => {
    insertInvite(harness.db, INVITE);
    const victim = newAccount();
    const body = signedPut(account, "state", harness.seconds(), {
      invite: INVITE,
    });
    const reply = await harness.send(
      "PUT",
      blobPath(victim, "state"),
      JSON.stringify(body),
    );
    expect(reply).toEqual({ status: PSS_STATUS.unauthorized, body: "" });
    expect((await harness.send("GET", blobPath(victim, "state"))).status).toBe(
      PSS_STATUS.not_found,
    );
  });

  it("refuses a labels signature replayed against state", async () => {
    insertInvite(harness.db, INVITE);
    const body = signedPut(account, "labels", harness.seconds(), {
      invite: INVITE,
      signCollection: "labels",
    });
    const reply = await harness.send(
      "PUT",
      blobPath(account, "state"),
      JSON.stringify(body),
    );
    expect(reply).toEqual({ status: PSS_STATUS.unauthorized, body: "" });
    expect((await harness.send("GET", blobPath(account, "state"))).status).toBe(
      PSS_STATUS.not_found,
    );
  });

  it("refuses a timestamp outside the skew window on either side", async () => {
    insertInvite(harness.db, INVITE);
    const ahead = await put(account, "state", {
      invite: INVITE,
      timestamp: harness.seconds() + TIMESTAMP_SKEW_SECONDS,
    });
    expect(ahead).toEqual({ status: PSS_STATUS.unauthorized, body: "" });
    const behind = await put(account, "state", {
      invite: INVITE,
      timestamp: harness.seconds() - TIMESTAMP_SKEW_SECONDS,
    });
    expect(behind).toEqual({ status: PSS_STATUS.unauthorized, body: "" });
    const inside = await put(account, "state", {
      invite: INVITE,
      timestamp: harness.seconds() + TIMESTAMP_SKEW_SECONDS - 1,
    });
    expect(inside.status).toBe(PSS_STATUS.ok);
  });

  it("refuses a signature that ages out of the window before it is replayed", async () => {
    insertInvite(harness.db, INVITE);
    const body = JSON.stringify(
      signedPut(account, "state", harness.seconds(), { invite: INVITE }),
    );
    harness.advance(TIMESTAMP_SKEW_SECONDS * MS_PER_SECOND);
    const reply = await harness.send("PUT", blobPath(account, "state"), body);
    expect(reply).toEqual({ status: PSS_STATUS.unauthorized, body: "" });
  });

  it("refuses a replay of an accepted write", async () => {
    insertInvite(harness.db, INVITE);
    const body = JSON.stringify(
      signedPut(account, "state", harness.seconds(), { invite: INVITE }),
    );
    expect(
      (await harness.send("PUT", blobPath(account, "state"), body)).status,
    ).toBe(PSS_STATUS.ok);
    const replay = await harness.send("PUT", blobPath(account, "state"), body);
    expect(replay).toEqual({ status: PSS_STATUS.version_conflict, body: "" });
  });

  it("refuses a gapped prevVersion and a version that does not advance", async () => {
    await create(account);
    const gapped = await put(account, "state", { version: 3, prevVersion: 2 });
    expect(gapped).toEqual({ status: PSS_STATUS.version_conflict, body: "" });
    const same = await put(account, "state", { version: 1, prevVersion: 1 });
    expect(same).toEqual({ status: PSS_STATUS.version_conflict, body: "" });
    const backwards = await put(account, "state", {
      version: 1,
      prevVersion: 0,
    });
    expect(backwards.status).toBe(PSS_STATUS.version_conflict);
  });

  it("refuses a create that claims a predecessor version", async () => {
    insertInvite(harness.db, INVITE);
    const reply = await put(account, "state", {
      invite: INVITE,
      version: 3,
      prevVersion: 2,
    });
    expect(reply).toEqual({ status: PSS_STATUS.version_conflict, body: "" });
    expect(harness.store.get(account.accountId, "state")).toBeNull();
  });

  it("rate limits the account after its burst and refills on the clock", async () => {
    await create(account);
    for (let version = 2; version <= WRITE_BURST; version++) {
      const reply = await put(account, "state", {
        version,
        prevVersion: version - 1,
      });
      expect(reply.status).toBe(PSS_STATUS.ok);
    }
    const limited = await put(account, "state", {
      version: WRITE_BURST + 1,
      prevVersion: WRITE_BURST,
    });
    expect(limited).toEqual({ status: PSS_STATUS.rate_limited, body: "" });

    harness.advance(60 * MS_PER_SECOND);
    const allowed = await put(account, "state", {
      version: WRITE_BURST + 1,
      prevVersion: WRITE_BURST,
    });
    expect(allowed.status).toBe(PSS_STATUS.ok);
  });

  it("spends no rate limit token on a request that fails authorization", async () => {
    insertInvite(harness.db, INVITE);
    for (let attempt = 0; attempt < WRITE_BURST * 2; attempt++) {
      const reply = await put(account, "state", {
        invite: INVITE,
        timestamp: harness.seconds() + TIMESTAMP_SKEW_SECONDS,
      });
      expect(reply.status).toBe(PSS_STATUS.unauthorized);
    }
    const reply = await put(account, "state", { invite: INVITE });
    expect(reply.status).toBe(PSS_STATUS.ok);
  });

  it("rejects a malformed body with 400", async () => {
    const reply = await harness.send(
      "PUT",
      blobPath(account, "state"),
      "{not json",
    );
    expect(reply).toEqual({ status: PSS_STATUS.bad_request, body: "" });
  });
});

describe("body size", () => {
  it("answers a declared length over the cap with 413 before reading a body", async () => {
    const reply = await rawRequest(
      harness.port,
      "PUT",
      blobPath(account, "state"),
      {
        headers: { "content-length": String(1_000_000_000) },
        chunks: [Buffer.from("{")],
        finish: false,
      },
    );
    expect(reply).toEqual({ status: PSS_STATUS.payload_too_large, body: "" });
  });

  it("answers an undeclared body over the cap with 413", async () => {
    const reply = await rawRequest(
      harness.port,
      "PUT",
      blobPath(account, "state"),
      {
        chunks: [Buffer.alloc(MAX_CIPHERTEXT_BYTES * 2, 0x61)],
        finish: true,
      },
    );
    expect(reply).toEqual({ status: PSS_STATUS.payload_too_large, body: "" });
  });

  it("rejects a non-numeric declared length with 400", async () => {
    const reply = await rawRequest(
      harness.port,
      "PUT",
      blobPath(account, "state"),
      {
        headers: { "content-length": "twelve" },
        chunks: [],
        finish: true,
      },
    );
    expect(reply.status).toBe(PSS_STATUS.bad_request);
  });

  it("answers a ciphertext one byte over the cap with 413", async () => {
    insertInvite(harness.db, INVITE);
    const reply = await put(account, "state", {
      invite: INVITE,
      ciphertext: new Uint8Array(MAX_CIPHERTEXT_BYTES + 1),
    });
    expect(reply).toEqual({ status: PSS_STATUS.payload_too_large, body: "" });
  });

  it("accepts a ciphertext exactly at the cap", async () => {
    insertInvite(harness.db, INVITE);
    const reply = await put(account, "state", {
      invite: INVITE,
      ciphertext: new Uint8Array(MAX_CIPHERTEXT_BYTES),
    });
    expect(reply.status).toBe(PSS_STATUS.ok);
  });
});

describe("delete", () => {
  it("erases every collection of the account", async () => {
    await create(account, "state");
    await create(account, "labels");
    const reply = await harness.send(
      "DELETE",
      `/v1/blob/${account.path}`,
      signedDelete(account),
    );
    expect(reply).toEqual({ status: PSS_STATUS.ok, body: "" });
    expect((await harness.send("GET", blobPath(account, "state"))).status).toBe(
      PSS_STATUS.not_found,
    );
    expect(
      (await harness.send("GET", blobPath(account, "labels"))).status,
    ).toBe(PSS_STATUS.not_found);
  });

  it("refuses a delete signed by a stranger", async () => {
    await create(account);
    const stranger = newAccount();
    const reply = await harness.send(
      "DELETE",
      `/v1/blob/${account.path}`,
      signedDelete(account, { signAs: stranger }),
    );
    expect(reply).toEqual({ status: PSS_STATUS.unauthorized, body: "" });
    expect((await harness.send("GET", blobPath(account, "state"))).status).toBe(
      PSS_STATUS.ok,
    );
  });

  it("refuses a delete outside the skew window", async () => {
    await create(account);
    const reply = await harness.send(
      "DELETE",
      `/v1/blob/${account.path}`,
      signedDelete(account, {
        timestamp: harness.seconds() - TIMESTAMP_SKEW_SECONDS,
      }),
    );
    expect(reply.status).toBe(PSS_STATUS.unauthorized);
  });

  it("answers a delete of an account with no rows the same way as one with rows", async () => {
    const reply = await harness.send(
      "DELETE",
      `/v1/blob/${account.path}`,
      signedDelete(account),
    );
    expect(reply).toEqual({ status: PSS_STATUS.ok, body: "" });
  });
});

describe("counters", () => {
  it("buckets by route and status class and names no account", async () => {
    await create(account);
    await harness.send("GET", blobPath(account, "state"));
    await harness.send("GET", blobPath(newAccount(), "state"));
    const snapshot = harness.counters.snapshot();
    expect(snapshot).toEqual({
      "blob_get.2xx": 1,
      "blob_get.4xx": 1,
      "blob_put.2xx": 1,
    });
    for (const key of Object.keys(snapshot)) {
      expect(key).not.toContain(account.path);
    }
  });
});

describe("body decoding", () => {
  let harness: Harness;
  beforeEach(async () => {
    harness = await startHarness();
  });
  afterEach(async () => {
    await harness.stop();
  });

  // The decoder is constructed with `fatal: true`, so invalid UTF-8 is refused before JSON.parse ever
  // sees it. A lone 0x80 is a continuation byte with no lead byte, which no JSON text can contain.
  it("refuses a body that is not valid UTF-8", async () => {
    const account = newAccount();
    const body = Buffer.from([0x7b, 0x80, 0x7d]);
    const reply = await rawRequest(
      harness.port,
      "PUT",
      `/v1/blob/${account.path}/state`,
      {
        headers: { "content-length": String(body.length) },
        chunks: [body],
        finish: true,
      },
    );
    expect(reply.status).toBe(PSS_STATUS.bad_request);
  });
});
