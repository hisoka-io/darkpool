// Composition vectors for the PSS key schedule under a fixed k_state of 0x00..0x1f.
//
// The primitives underneath are pinned separately against published standards in ./published.ts. What
// this file pins is the WIRING: which info string feeds which key, that accountId is SHA256 of the
// public key, and the exact byte layout of a signed PUT preimage. Those values can only come from an
// implementation, so the accompanying test also recomputes the HKDF half with node:crypto rather than
// trusting these constants alone.

export const K_STATE_HEX =
  "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

export const AUTH_SEED_HEX =
  "5d841c5084a3f35b775af7d240ab7911d9da9f62e36d03e77046b003a3038c73";

export const AUTH_PUBLIC_KEY_HEX =
  "09e9aeb4ba9365ee9149a6857162eafa1491c02524e3fdd92b962e0753fcf358";

export const ACCOUNT_ID_HEX =
  "8cfa343c716638269401b19220ec6ff3607ac1ed9e11f0b29d125bee39bb6188";

export const CELL_KEY_STATE_HEX =
  "a64a208f0f36d1b52095fac9d988ecaa2e779f8e340ee24734879a5aa43c0bc3";

export const CELL_KEY_LABELS_HEX =
  "a50552482103b1555563c3ca27b5212e1d48a0180674244f2849b904f83be286";

export const PUT_PAYLOAD = '{"schema":1}';
export const PUT_NONCE_HEX = "111111111111111111111111";
export const PUT_COLLECTION = "state";
export const PUT_VERSION = 7;
export const PUT_PREV_VERSION = 6;
export const PUT_TIMESTAMP = 1_785_900_000;

export const PUT_CIPHERTEXT_SHA256_HEX =
  "bee222d07e58cf6b85ef6a8458f5b9c9f795e2dbee06f6111ea36eaa34956545";

// "pss-v1:put" || accountId(32) || 0x05 "state" || u64be(7) || u64be(6) || sha256(ct)(32) || u64be(ts)
export const PUT_PREIMAGE_HEX =
  "7073732d76313a7075748cfa343c716638269401b19220ec6ff3607ac1ed9e11f0b29d125bee39bb618805737461746500000000000000070000000000000006bee222d07e58cf6b85ef6a8458f5b9c9f795e2dbee06f6111ea36eaa34956545000000006a72abe0";
