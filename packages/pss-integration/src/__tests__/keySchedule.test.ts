import { describe, expect, it } from "vitest";
import {
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
} from "node:crypto";
import { DarkAccount } from "@hisoka/wallets";
import { deriveKeys, nobleBackend, toHexRaw } from "@hisoka/pss-client";

const MNEMONIC = "test test test test test test test test test test test junk";

// The two halves of the key schedule live in packages that may not import each other: the wallet derives
// k_state, and the client turns it into an Ed25519 key and then into accountId, which is the server's
// primary key. Nothing else in the repo can observe the join, so these goldens are what stands between
// a silent derivation change and every stored blob being orphaned.
const KAT = {
  stateKey:
    "0x0a8af92fddacb7bf30c09f0159261e469e3ab454a04cfe7071d76b00bee08eda",
  authSeed: "236fbe2a887a07535dfdee8b0919ecc38101265173f2417a8f209846df442cfd",
  authPublicKey:
    "76699a292915c91f54a567f560780bd5f95532fabf3ad7c3269e3e376c5175ea",
  accountId: "75840d549ff2b7e6e2d73e5162c9afd944fec37b4a708d27f8cdbf839d011173",
  cellState: "5acbb963968a8e2c8246bd1ee798cf0d6c485d092c278f58e0aac67c81505d90",
  cellLabels:
    "cb17fa51d2d75728fa739d696a55c28f04a29b468b54c92b7b5be610141074be",
};

// RFC 8410 PKCS#8 prefix for an Ed25519 private key, followed by the 32-byte seed.
const PKCS8_ED25519_PREFIX = Buffer.from(
  "302e020100300506032b657004220420",
  "hex",
);

// RFC 5869 section 2.3, written against node:crypto so the goldens are graded by an implementation that
// shares no code with the one under test.
function hkdfExpand(prk: Buffer, info: string, length: number): Buffer {
  const out = Buffer.alloc(length);
  let previous = Buffer.alloc(0);
  let written = 0;
  for (let counter = 1; written < length; counter++) {
    previous = createHmac("sha256", prk)
      .update(
        Buffer.concat([
          previous,
          Buffer.from(info, "utf8"),
          Buffer.of(counter),
        ]),
      )
      .digest();
    previous.copy(out, written);
    written += previous.length;
  }
  return out.subarray(0, length);
}

function ed25519PublicKey(seed: Buffer): Buffer {
  const priv = createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]),
    format: "der",
    type: "pkcs8",
  });
  return Buffer.from(
    createPublicKey(priv).export({ format: "der", type: "spki" }).subarray(-32),
  );
}

async function stateKeyBytes(mnemonic: string): Promise<Uint8Array> {
  const account = await DarkAccount.fromMnemonic(mnemonic);
  return Uint8Array.from((await account.getStateKey()).toBuffer());
}

describe("getStateKey feeds the client key schedule", () => {
  it("crosses the package boundary as exactly 32 big-endian bytes", async () => {
    const account = await DarkAccount.fromMnemonic(MNEMONIC);
    const stateKey = await account.getStateKey();
    const bytes = stateKey.toBuffer();

    expect(stateKey.toString()).toBe(KAT.stateKey);
    expect(bytes.length).toBe(32);
    // Big-endian, so the hex string and the byte order agree. A little-endian crossing would derive a
    // different Ed25519 key and a different accountId, with no error raised anywhere.
    expect(`0x${Buffer.from(bytes).toString("hex")}`).toBe(KAT.stateKey);
  });

  it("derives the pinned accountId, and node:crypto agrees at every step", async () => {
    const kState = Buffer.from(await stateKeyBytes(MNEMONIC));
    const keys = await deriveKeys(nobleBackend, kState);

    const seed = hkdfExpand(kState, "auth-v1", 32);
    const publicKey = ed25519PublicKey(seed);
    const accountId = createHash("sha256").update(publicKey).digest();

    expect(seed.toString("hex")).toBe(KAT.authSeed);
    expect(publicKey.toString("hex")).toBe(KAT.authPublicKey);
    expect(accountId.toString("hex")).toBe(KAT.accountId);

    expect(toHexRaw(keys.authSeed)).toBe(KAT.authSeed);
    expect(toHexRaw(keys.authPublicKey)).toBe(KAT.authPublicKey);
    expect(toHexRaw(keys.accountId)).toBe(KAT.accountId);
  });

  it("derives both cell keys, and they differ from each other and from the auth seed", async () => {
    const kState = Buffer.from(await stateKeyBytes(MNEMONIC));
    const keys = await deriveKeys(nobleBackend, kState);

    expect(toHexRaw(keys.cellKey.state)).toBe(KAT.cellState);
    expect(toHexRaw(keys.cellKey.labels)).toBe(KAT.cellLabels);
    expect(hkdfExpand(kState, "cell-state-v1", 32).toString("hex")).toBe(
      KAT.cellState,
    );
    expect(hkdfExpand(kState, "cell-labels-v1", 32).toString("hex")).toBe(
      KAT.cellLabels,
    );

    expect(new Set([KAT.authSeed, KAT.cellState, KAT.cellLabels]).size).toBe(3);
  });

  it("gives two different mnemonics two different accounts", async () => {
    const other = await stateKeyBytes(
      "legal winner thank year wave sausage worth useful legal winner thank yellow",
    );
    const keys = await deriveKeys(nobleBackend, other);
    expect(toHexRaw(keys.accountId)).not.toBe(KAT.accountId);
  });
});
