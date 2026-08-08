import { createHash, createHmac } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { cellAad } from "../wire/aad.js";
import { fromBase64, fromHexRaw, toHexRaw, utf8 } from "../wire/codec.js";
import {
  GCM_NONCE_BYTES,
  GCM_TAG_BYTES,
  HKDF_INFO_AUTH,
  HKDF_INFO_CELL_LABELS,
  HKDF_INFO_CELL_STATE,
  MAX_CIPHERTEXT_BYTES,
  MAX_PLAINTEXT_BYTES,
  PAD_TIERS,
} from "../wire/constants.js";
import { deletePreimage, putPreimage } from "../wire/preimage.js";
import {
  CryptoBackend,
  PssCryptoError,
  buildDeleteRequest,
  buildPutRequest,
  deriveKeys,
  hkdfExpand,
  maxPayloadBytes,
  nobleBackend,
  openCell,
  pad,
  sealCell,
  tierFor,
  unpad,
  webCryptoBackend,
} from "../crypto/index.js";
import {
  CAVP_AES_256_GCM,
  RFC5869_SHA256,
  RFC8032_ED25519,
} from "./vectors/published.js";
import * as fixed from "./vectors/fixedSeed.js";

const BACKENDS: readonly CryptoBackend[] = [nobleBackend, webCryptoBackend];
const hex = (text: string): Uint8Array => fromHexRaw(text, "vector");

// Written against node:crypto so the fixture is checked by an implementation that shares no code with
// the one under test.
function expandWithNode(
  prk: Uint8Array,
  info: Uint8Array,
  length: number,
): Uint8Array {
  const out = Buffer.alloc(length);
  let previous = Buffer.alloc(0);
  let written = 0;
  for (let counter = 1; written < length; counter++) {
    previous = createHmac("sha256", Buffer.from(prk))
      .update(
        Buffer.concat([previous, Buffer.from(info), Buffer.from([counter])]),
      )
      .digest();
    previous.copy(out, written);
    written += previous.length;
  }
  return new Uint8Array(out.subarray(0, length));
}

describe.each(BACKENDS.map((b) => [b.name, b] as const))(
  "published vectors (%s backend)",
  (_name: string, backend: CryptoBackend) => {
    it("matches RFC 5869 HKDF-Expand for every SHA-256 case", async () => {
      for (const v of RFC5869_SHA256) {
        const okm = await hkdfExpand(
          backend,
          hex(v.prk),
          hex(v.info),
          v.length,
        );
        expect(toHexRaw(okm), v.name).toBe(v.okm);
      }
    });

    it("matches RFC 8032 Ed25519 key derivation and verification", async () => {
      for (const v of RFC8032_ED25519) {
        expect(
          toHexRaw(await backend.ed25519PublicKey(hex(v.seed))),
          v.name,
        ).toBe(v.publicKey);
        // The signature bytes are not pinned as a golden: verification is the property that matters.
        expect(
          await backend.ed25519Verify(
            hex(v.publicKey),
            hex(v.message),
            hex(v.signature),
          ),
          v.name,
        ).toBe(true);
        const produced = await backend.ed25519Sign(hex(v.seed), hex(v.message));
        expect(
          await backend.ed25519Verify(
            hex(v.publicKey),
            hex(v.message),
            produced,
          ),
          v.name,
        ).toBe(true);
      }
    });

    it("rejects a signature over a different message", async () => {
      const v = RFC8032_ED25519[2];
      expect(
        await backend.ed25519Verify(
          hex(v.publicKey),
          utf8("not the signed message"),
          hex(v.signature),
        ),
      ).toBe(false);
    });

    it("matches NIST CAVP AES-256-GCM", async () => {
      for (const v of CAVP_AES_256_GCM) {
        const sealed = await backend.aesGcmSeal(
          hex(v.key),
          hex(v.iv),
          hex(v.aad),
          hex(v.plaintext),
        );
        expect(toHexRaw(sealed), v.name).toBe(v.ciphertext + v.tag);
        const opened = await backend.aesGcmOpen(
          hex(v.key),
          hex(v.iv),
          hex(v.aad),
          sealed,
        );
        expect(toHexRaw(opened), v.name).toBe(v.plaintext);
      }
    });

    it("refuses to open a cell whose associated data differs", async () => {
      const v = CAVP_AES_256_GCM[3];
      const sealed = await backend.aesGcmSeal(
        hex(v.key),
        hex(v.iv),
        hex(v.aad),
        hex(v.plaintext),
      );
      await expect(
        backend.aesGcmOpen(hex(v.key), hex(v.iv), utf8("wrong aad"), sealed),
      ).rejects.toThrow(PssCryptoError);
    });

    it("matches SHA-256 against node:crypto", async () => {
      const data = utf8("hisoka pss");
      expect(toHexRaw(await backend.sha256(data))).toBe(
        createHash("sha256").update(Buffer.from(data)).digest("hex"),
      );
    });
  },
);

describe("key schedule", () => {
  const kState = hex(fixed.K_STATE_HEX);

  it.each(BACKENDS.map((b) => [b.name, b] as const))(
    "reproduces the fixed-seed fixture (%s)",
    async (_name: string, backend: CryptoBackend) => {
      const keys = await deriveKeys(backend, kState);
      expect(toHexRaw(keys.authSeed)).toBe(fixed.AUTH_SEED_HEX);
      expect(toHexRaw(keys.authPublicKey)).toBe(fixed.AUTH_PUBLIC_KEY_HEX);
      expect(toHexRaw(keys.accountId)).toBe(fixed.ACCOUNT_ID_HEX);
      expect(toHexRaw(keys.cellKey.state)).toBe(fixed.CELL_KEY_STATE_HEX);
      expect(toHexRaw(keys.cellKey.labels)).toBe(fixed.CELL_KEY_LABELS_HEX);
    },
  );

  it("agrees with an independent node:crypto HKDF-Expand", () => {
    expect(toHexRaw(expandWithNode(kState, utf8(HKDF_INFO_AUTH), 32))).toBe(
      fixed.AUTH_SEED_HEX,
    );
    expect(
      toHexRaw(expandWithNode(kState, utf8(HKDF_INFO_CELL_STATE), 32)),
    ).toBe(fixed.CELL_KEY_STATE_HEX);
    expect(
      toHexRaw(expandWithNode(kState, utf8(HKDF_INFO_CELL_LABELS), 32)),
    ).toBe(fixed.CELL_KEY_LABELS_HEX);
  });

  it("binds accountId to the public key", async () => {
    const keys = await deriveKeys(nobleBackend, kState);
    expect(toHexRaw(keys.accountId)).toBe(
      createHash("sha256")
        .update(Buffer.from(keys.authPublicKey))
        .digest("hex"),
    );
  });

  it("separates the two cell keys and the auth seed", async () => {
    const keys = await deriveKeys(nobleBackend, kState);
    const derived = new Set([
      toHexRaw(keys.authSeed),
      toHexRaw(keys.cellKey.state),
      toHexRaw(keys.cellKey.labels),
    ]);
    expect(derived.size).toBe(3);
  });

  it("produces identical keys on both backends", async () => {
    const [a, b] = await Promise.all(
      BACKENDS.map((backend) => deriveKeys(backend, kState)),
    );
    expect(toHexRaw(a.authSeed)).toBe(toHexRaw(b.authSeed));
    expect(toHexRaw(a.accountId)).toBe(toHexRaw(b.accountId));
    expect(toHexRaw(a.cellKey.state)).toBe(toHexRaw(b.cellKey.state));
    expect(toHexRaw(a.cellKey.labels)).toBe(toHexRaw(b.cellKey.labels));
  });

  it("rejects a k_state that is not exactly 32 bytes", async () => {
    for (const length of [0, 31, 33, 64]) {
      await expect(
        deriveKeys(nobleBackend, new Uint8Array(length)),
      ).rejects.toThrow(PssCryptoError);
    }
  });

  it("changes every derived key when k_state changes by one bit", async () => {
    const flipped = Uint8Array.from(kState);
    flipped[31] ^= 1;
    const [a, b] = await Promise.all([
      deriveKeys(nobleBackend, kState),
      deriveKeys(nobleBackend, flipped),
    ]);
    expect(toHexRaw(a.accountId)).not.toBe(toHexRaw(b.accountId));
    expect(toHexRaw(a.cellKey.state)).not.toBe(toHexRaw(b.cellKey.state));
  });
});

describe("padding", () => {
  it("round trips as identity across every boundary and a random sample", () => {
    const sizes = new Set<number>([0, 1, 2, 3, 4, 5, 100]);
    for (const tier of PAD_TIERS) {
      for (const delta of [-5, -4, -3, -1, 0]) {
        const size = tier - 4 + delta;
        if (size >= 0) sizes.add(size);
      }
    }
    for (let i = 0; i < 64; i++) {
      sizes.add(Math.floor((i * 7919) % 5000));
    }
    for (const size of sizes) {
      const payload = Uint8Array.from(
        { length: size },
        (_, i) => (i * 31) % 256,
      );
      expect(unpad(pad(payload)), `size ${size}`).toEqual(payload);
    }
  });

  it("emits only the three tier sizes", () => {
    for (const size of [0, 1, 16_379, 16_380, 16_381, 131_067, 131_068]) {
      expect(PAD_TIERS).toContain(pad(new Uint8Array(size)).length);
    }
    expect(pad(new Uint8Array(0))).toHaveLength(PAD_TIERS[0]);
    expect(pad(new Uint8Array(PAD_TIERS[0] - 4))).toHaveLength(PAD_TIERS[0]);
    expect(pad(new Uint8Array(PAD_TIERS[0] - 3))).toHaveLength(PAD_TIERS[1]);
  });

  it("raises a typed error past the largest tier instead of truncating", () => {
    expect(() => tierFor(maxPayloadBytes() + 1)).toThrow(PssCryptoError);
    expect(() => pad(new Uint8Array(maxPayloadBytes() + 1))).toThrow(
      PssCryptoError,
    );
    expect(pad(new Uint8Array(maxPayloadBytes()))).toHaveLength(
      PAD_TIERS[PAD_TIERS.length - 1],
    );
  });

  it("rejects a padded buffer that is not a tier, over-long, or non-zero filled", () => {
    expect(() => unpad(new Uint8Array(100))).toThrow(PssCryptoError);
    const overlong = new Uint8Array(PAD_TIERS[0]);
    new DataView(overlong.buffer).setUint32(0, PAD_TIERS[0], false);
    expect(() => unpad(overlong)).toThrow(PssCryptoError);
    const dirty = pad(utf8("hello"));
    dirty[dirty.length - 1] = 1;
    expect(() => unpad(dirty)).toThrow(PssCryptoError);
  });
});

describe("cell AEAD", () => {
  const kState = hex(fixed.K_STATE_HEX);

  it.each(BACKENDS.map((b) => [b.name, b] as const))(
    "round trips a payload (%s)",
    async (_name: string, backend: CryptoBackend) => {
      const keys = await deriveKeys(backend, kState);
      const payload = utf8(fixed.PUT_PAYLOAD);
      const cell = await sealCell(
        backend,
        keys.cellKey.state,
        { collection: "state", version: 7 },
        payload,
      );
      expect(cell.nonce).toHaveLength(GCM_NONCE_BYTES);
      expect(cell.ciphertext).toHaveLength(PAD_TIERS[0] + GCM_TAG_BYTES);
      const opened = await openCell(
        backend,
        keys.cellKey.state,
        { collection: "state", version: 7 },
        cell,
      );
      expect(opened).toEqual(payload);
    },
  );

  it("refuses a cell replayed into the other collection", async () => {
    const keys = await deriveKeys(nobleBackend, kState);
    const cell = await sealCell(
      nobleBackend,
      keys.cellKey.state,
      { collection: "state", version: 7 },
      utf8("secret"),
    );
    await expect(
      openCell(
        nobleBackend,
        keys.cellKey.state,
        { collection: "labels", version: 7 },
        cell,
      ),
    ).rejects.toThrow(PssCryptoError);
  });

  it("refuses a cell replayed at a different version", async () => {
    const keys = await deriveKeys(nobleBackend, kState);
    const cell = await sealCell(
      nobleBackend,
      keys.cellKey.state,
      { collection: "state", version: 7 },
      utf8("secret"),
    );
    await expect(
      openCell(
        nobleBackend,
        keys.cellKey.state,
        { collection: "state", version: 8 },
        cell,
      ),
    ).rejects.toThrow(PssCryptoError);
  });

  it("refuses a cell opened with the other collection key", async () => {
    const keys = await deriveKeys(nobleBackend, kState);
    const cell = await sealCell(
      nobleBackend,
      keys.cellKey.state,
      { collection: "state", version: 7 },
      utf8("secret"),
    );
    await expect(
      openCell(
        nobleBackend,
        keys.cellKey.labels,
        { collection: "state", version: 7 },
        cell,
      ),
    ).rejects.toThrow(PssCryptoError);
  });

  it("refuses a flipped ciphertext bit", async () => {
    const keys = await deriveKeys(nobleBackend, kState);
    const cell = await sealCell(
      nobleBackend,
      keys.cellKey.state,
      { collection: "state", version: 7 },
      utf8("secret"),
    );
    const tampered = Uint8Array.from(cell.ciphertext);
    tampered[0] ^= 1;
    await expect(
      openCell(
        nobleBackend,
        keys.cellKey.state,
        { collection: "state", version: 7 },
        { nonce: cell.nonce, ciphertext: tampered },
      ),
    ).rejects.toThrow(PssCryptoError);
  });

  it("draws a fresh nonce on every seal and never a counter", async () => {
    const keys = await deriveKeys(nobleBackend, kState);
    const seen = new Set<string>();
    for (let i = 0; i < 32; i++) {
      const cell = await sealCell(
        nobleBackend,
        keys.cellKey.state,
        { collection: "state", version: 1 },
        utf8("same payload every time"),
      );
      seen.add(toHexRaw(cell.nonce));
    }
    expect(seen.size).toBe(32);
    // A counter would produce a low-Hamming-weight sequence; a CSPRNG will not sit near zero.
    expect([...seen].every((n) => n !== "0".repeat(24))).toBe(true);
  });

  it("binds the collection and version into the associated data", () => {
    const seen = new Set(
      [
        cellAad("state", 1),
        cellAad("labels", 1),
        cellAad("state", 2),
        cellAad("labels", 2),
      ].map(toHexRaw),
    );
    expect(seen.size).toBe(4);
  });

  // Distinctness alone is satisfied by ANY injective encoding, so it cannot see a reordering or a
  // dropped length prefix. These pin the bytes. Reordering the associated data orphans every stored
  // ciphertext: the AEAD open fails and the blob can never be read again.
  it("emits the associated data byte for byte", () => {
    expect(toHexRaw(cellAad("state", 7))).toBe(fixed.AAD_STATE_V7_HEX);
    expect(toHexRaw(cellAad("labels", 7))).toBe(fixed.AAD_LABELS_V7_HEX);
  });

  it("emits the padding length header big-endian, ahead of the payload", () => {
    const padded = pad(utf8(fixed.PUT_PAYLOAD));
    expect(toHexRaw(padded.subarray(0, 8))).toBe(fixed.PAD_PREFIX_HEX);
  });

  // The tiers and the plaintext ceiling are declared independently in wire/constants.ts, so an edit to
  // one silently desynchronises the server's body cap from the client's largest legal payload.
  it("keeps the padding tiers and the plaintext ceiling frozen and in step", () => {
    expect(PAD_TIERS).toEqual([16_384, 131_072, 1_048_576]);
    expect(MAX_PLAINTEXT_BYTES).toBe(PAD_TIERS[PAD_TIERS.length - 1]);
  });
});

describe("request signing", () => {
  const kState = hex(fixed.K_STATE_HEX);

  it("reproduces the fixed-seed PUT preimage byte for byte", async () => {
    const keys = await deriveKeys(nobleBackend, kState);
    const preimage = putPreimage({
      accountId: keys.accountId,
      collection: fixed.PUT_COLLECTION,
      version: fixed.PUT_VERSION,
      prevVersion: fixed.PUT_PREV_VERSION,
      ciphertextDigest: hex(fixed.PUT_CIPHERTEXT_SHA256_HEX),
      timestamp: fixed.PUT_TIMESTAMP,
    });
    expect(toHexRaw(preimage)).toBe(fixed.PUT_PREIMAGE_HEX);
  });

  // The only prior assertion over the DELETE preimage was that it differs from the PUT one, which any
  // change to its prefix, field order or widths still satisfies.
  it("reproduces the fixed-seed DELETE preimage byte for byte", async () => {
    const keys = await deriveKeys(nobleBackend, kState);
    const preimage = deletePreimage({
      accountId: keys.accountId,
      nonce: hex(fixed.DELETE_NONCE_HEX),
      timestamp: fixed.PUT_TIMESTAMP,
    });
    expect(toHexRaw(preimage)).toBe(fixed.DELETE_PREIMAGE_HEX);
  });

  it.each(BACKENDS.map((b) => [b.name, b] as const))(
    "builds a PUT whose signature verifies over the preimage (%s)",
    async (_name: string, backend: CryptoBackend) => {
      const keys = await deriveKeys(backend, kState);
      const ciphertext = utf8("ciphertext bytes");
      const request = await buildPutRequest(backend, keys, {
        collection: "state",
        version: 7,
        prevVersion: 6,
        nonce: new Uint8Array(GCM_NONCE_BYTES).fill(0x11),
        ciphertext,
        timestamp: fixed.PUT_TIMESTAMP,
      });
      const preimage = putPreimage({
        accountId: keys.accountId,
        collection: "state",
        version: 7,
        prevVersion: 6,
        ciphertextDigest: await backend.sha256(ciphertext),
        timestamp: fixed.PUT_TIMESTAMP,
      });
      expect(
        await backend.ed25519Verify(
          keys.authPublicKey,
          preimage,
          fromBase64(request.sig, "sig"),
        ),
      ).toBe(true);
      expect(fromBase64(request.authPk, "authPk")).toEqual(keys.authPublicKey);
    },
  );

  it("produces a signature that does not verify against the other collection", async () => {
    const keys = await deriveKeys(nobleBackend, kState);
    const ciphertext = utf8("ciphertext bytes");
    const request = await buildPutRequest(nobleBackend, keys, {
      collection: "labels",
      version: 7,
      prevVersion: 6,
      nonce: new Uint8Array(GCM_NONCE_BYTES).fill(0x11),
      ciphertext,
      timestamp: fixed.PUT_TIMESTAMP,
    });
    const asState = putPreimage({
      accountId: keys.accountId,
      collection: "state",
      version: 7,
      prevVersion: 6,
      ciphertextDigest: await nobleBackend.sha256(ciphertext),
      timestamp: fixed.PUT_TIMESTAMP,
    });
    expect(
      await nobleBackend.ed25519Verify(
        keys.authPublicKey,
        asState,
        fromBase64(request.sig, "sig"),
      ),
    ).toBe(false);
  });

  it("refuses to sign a PUT whose version does not advance", async () => {
    const keys = await deriveKeys(nobleBackend, kState);
    await expect(
      buildPutRequest(nobleBackend, keys, {
        collection: "state",
        version: 6,
        prevVersion: 6,
        nonce: new Uint8Array(GCM_NONCE_BYTES),
        ciphertext: utf8("x"),
        timestamp: fixed.PUT_TIMESTAMP,
      }),
    ).rejects.toThrow(PssCryptoError);
  });

  it("carries an invite only when one was supplied", async () => {
    const keys = await deriveKeys(nobleBackend, kState);
    const base = {
      collection: "state" as const,
      version: 1,
      prevVersion: 0,
      nonce: new Uint8Array(GCM_NONCE_BYTES),
      ciphertext: utf8("x"),
      timestamp: fixed.PUT_TIMESTAMP,
    };
    expect(await buildPutRequest(nobleBackend, keys, base)).not.toHaveProperty(
      "invite",
    );
    expect(
      await buildPutRequest(nobleBackend, keys, { ...base, invite: "code-1" }),
    ).toHaveProperty("invite", "code-1");
  });

  it("signs a DELETE that does not verify as a PUT", async () => {
    const keys = await deriveKeys(nobleBackend, kState);
    const nonce = new Uint8Array(GCM_NONCE_BYTES).fill(7);
    const request = await buildDeleteRequest(nobleBackend, keys, {
      nonce,
      timestamp: fixed.PUT_TIMESTAMP,
    });
    expect(fromBase64(request.nonce, "nonce")).toEqual(nonce);
    const asPut = putPreimage({
      accountId: keys.accountId,
      collection: "state",
      version: 0,
      prevVersion: 0,
      ciphertextDigest: new Uint8Array(32),
      timestamp: fixed.PUT_TIMESTAMP,
    });
    expect(
      await nobleBackend.ed25519Verify(
        keys.authPublicKey,
        asPut,
        fromBase64(request.sig, "sig"),
      ),
    ).toBe(false);
  });

  it("refuses a DELETE nonce of the wrong length", async () => {
    const keys = await deriveKeys(nobleBackend, kState);
    await expect(
      buildDeleteRequest(nobleBackend, keys, {
        nonce: new Uint8Array(16),
        timestamp: fixed.PUT_TIMESTAMP,
      }),
    ).rejects.toThrow(PssCryptoError);
  });
});

describe("backend selection", () => {
  const realCrypto: unknown = globalThis.crypto;

  function stubCrypto(value: unknown): void {
    Object.defineProperty(globalThis, "crypto", {
      value,
      configurable: true,
      writable: true,
    });
  }

  // The decision is memoised in module scope, so each case needs its own module instance or it grades
  // whatever the first case decided.
  async function freshSelect(): Promise<() => Promise<CryptoBackend>> {
    vi.resetModules();
    const module = await import("../crypto/select.js");
    return module.selectBackend;
  }

  afterEach(() => {
    stubCrypto(realCrypto);
    vi.resetModules();
  });

  it("falls back to noble when the runtime has no subtle", async () => {
    stubCrypto({});
    expect((await (await freshSelect())()).name).toBe("noble");
  });

  it("falls back to noble when subtle is present but rejects Ed25519", async () => {
    stubCrypto({
      subtle: {
        importKey: (): Promise<never> =>
          Promise.reject(new Error("Unrecognized algorithm name")),
      },
    });
    expect((await (await freshSelect())()).name).toBe("noble");
  });

  it("picks webcrypto exactly when the platform can derive an Ed25519 key", async () => {
    // Not pinned to the literal "webcrypto": Ed25519 in SubtleCrypto is still flagged experimental on
    // the pinned Node, so asserting it would bind this suite to a surface that can be withdrawn.
    const platformHasEd25519 = await webCryptoBackend
      .ed25519PublicKey(new Uint8Array(32))
      .then(
        () => true,
        () => false,
      );
    expect((await (await freshSelect())()).name).toBe(
      platformHasEd25519 ? "webcrypto" : "noble",
    );
  });

  it("probes once and reuses the answer", async () => {
    const importKey = vi.fn(
      (): Promise<never> => Promise.reject(new Error("no Ed25519 here")),
    );
    stubCrypto({ subtle: { importKey } });
    const select = await freshSelect();
    const first = await select();
    expect(await select()).toBe(first);
    expect(importKey).toHaveBeenCalledTimes(1);
  });
});

describe("request input validation", () => {
  it("refuses a PUT nonce or ciphertext the server would reject anyway", async () => {
    const keys = await deriveKeys(nobleBackend, hex(fixed.K_STATE_HEX));
    const base = {
      collection: "state" as const,
      version: 2,
      prevVersion: 1,
      nonce: new Uint8Array(GCM_NONCE_BYTES),
      ciphertext: utf8("x"),
      timestamp: fixed.PUT_TIMESTAMP,
    };
    await expect(
      buildPutRequest(nobleBackend, keys, {
        ...base,
        nonce: new Uint8Array(GCM_NONCE_BYTES + 1),
      }),
    ).rejects.toThrow(PssCryptoError);
    await expect(
      buildPutRequest(nobleBackend, keys, {
        ...base,
        ciphertext: new Uint8Array(0),
      }),
    ).rejects.toThrow(PssCryptoError);
    await expect(
      buildPutRequest(nobleBackend, keys, {
        ...base,
        ciphertext: new Uint8Array(MAX_CIPHERTEXT_BYTES + 1),
      }),
    ).rejects.toThrow(PssCryptoError);
  });
});
