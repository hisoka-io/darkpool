import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";
import {
  GCM_NONCE_BYTES,
  PSS_STATUS,
  deletePreimage,
  toBase64,
} from "@hisoka/pss-client/wire";
import {
  type Harness,
  type TestAccount,
  newAccount,
  signedPut,
  startHarness,
} from "./harness.js";

let harness: Harness;
let established: TestAccount;

function blobPath(who: TestAccount): string {
  return `/v1/blob/${who.path}/state`;
}

function seed(who: TestAccount, version: number): void {
  const outcome = harness.store.upsert(
    {
      accountId: who.accountId,
      collection: "state",
      version,
      prevVersion: version - 1,
      nonce: new Uint8Array(12),
      ciphertext: Uint8Array.of(9),
      updatedOn: "2026-08-07",
    },
    { required: false },
  );
  expect(outcome).toBe("written");
}

// The gate is a v1 placeholder. Dropping its table is the migration v2 performs, so an established
// account keeping full read and write access is a property of the schema, not a promise in a comment.
beforeEach(async () => {
  harness = await startHarness();
  established = newAccount();
  seed(established, 1);
  harness.db.exec("DROP TABLE invites");
});

afterEach(async () => {
  await harness.stop();
});

describe("invites table dropped", () => {
  it("still reads an established account", async () => {
    const reply = await harness.send("GET", blobPath(established));
    expect(reply.status).toBe(PSS_STATUS.ok);
  });

  it("still writes an established account", async () => {
    const body = signedPut(established, "state", harness.seconds(), {
      version: 2,
      prevVersion: 1,
    });
    const reply = await harness.send(
      "PUT",
      blobPath(established),
      JSON.stringify(body),
    );
    expect(reply).toEqual({ status: PSS_STATUS.ok, body: "" });
    expect(harness.store.get(established.accountId, "state")?.version).toBe(2);
  });

  it("still deletes an established account over HTTP", async () => {
    const second = newAccount();
    seed(second, 1);
    const nonce = Uint8Array.from(randomBytes(GCM_NONCE_BYTES));
    const timestamp = harness.seconds();
    const reply = await harness.send(
      "DELETE",
      `/v1/blob/${second.path}`,
      JSON.stringify({
        authPk: toBase64(second.authPk),
        sig: toBase64(
          second.sign(
            deletePreimage({ accountId: second.accountId, nonce, timestamp }),
          ),
        ),
        timestamp,
        nonce: toBase64(nonce),
      }),
    );
    expect(reply).toEqual({ status: PSS_STATUS.ok, body: "" });
    expect(harness.store.get(second.accountId, "state")).toBeNull();
    expect(harness.store.get(second.accountId, "labels")).toBeNull();
  });

  it("refuses a create, since no code can be presented", async () => {
    const stranger = newAccount();
    const body = signedPut(stranger, "state", harness.seconds(), {
      invite: "anything",
    });
    const reply = await harness.send(
      "PUT",
      `/v1/blob/${stranger.path}/state`,
      JSON.stringify(body),
    );
    expect(reply).toEqual({ status: PSS_STATUS.unauthorized, body: "" });
  });

  it("accepts a create once the deployment stops requiring a code", async () => {
    const open = await startHarness({ inviteRequired: false });
    try {
      open.db.exec("DROP TABLE invites");
      const stranger = newAccount();
      const reply = await open.send(
        "PUT",
        `/v1/blob/${stranger.path}/state`,
        JSON.stringify(signedPut(stranger, "state", open.seconds())),
      );
      expect(reply).toEqual({ status: PSS_STATUS.ok, body: "" });
    } finally {
      await open.stop();
    }
  });
});
