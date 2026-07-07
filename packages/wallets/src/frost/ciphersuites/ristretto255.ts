// FROST(ristretto255, SHA-512) ciphersuite, RFC 9591 Section 6.2. Certifies the generic frost.ts protocol
// against the official RFC 9591 known-answer vectors: elements are ristretto255 Encode/Decode (RFC 9496),
// scalars are 32-byte little-endian, and hash-to-scalar reduces a 64-byte SHA-512 digest interpreted
// little-endian modulo the group order L (RFC 9496 Section 4.4). SHA-512 and L are taken from the ed25519
// curve object (@noble/curves); that is the same SHA-512 @noble/hashes exposes, avoiding a second direct
// hash dependency. Test-only: BabyJubJub+Poseidon2 (bjj.ts) is the production ciphersuite.

import { ed25519, RistrettoPoint } from "@noble/curves/ed25519";
import {
  bytesToNumberLE,
  numberToBytesLE,
  concatBytes,
} from "@noble/curves/abstract/utils";
import { Ciphersuite, Commitment } from "../ciphersuite.js";

type Point = InstanceType<typeof RistrettoPoint>;

const ORDER = ed25519.CURVE.n;
const sha512 = ed25519.CURVE.hash;

const ENC = new TextEncoder();
const CONTEXT_STRING = ENC.encode("FROST-RISTRETTO255-SHA512-v1");
const LABEL_RHO = ENC.encode("rho");
const LABEL_CHAL = ENC.encode("chal");
const LABEL_NONCE = ENC.encode("nonce");
const LABEL_MSG = ENC.encode("msg");
const LABEL_COM = ENC.encode("com");

function reduce(k: bigint): bigint {
  return ((k % ORDER) + ORDER) % ORDER;
}

/** H(contextString || label || m): the RFC 6.2 domain-separated SHA-512. */
function h(label: Uint8Array, m: Uint8Array): Uint8Array {
  return sha512(concatBytes(CONTEXT_STRING, label, m));
}

/** Map a 64-byte SHA-512 digest to a scalar: little-endian integer mod L (RFC 9496 Section 4.4). */
function hashToScalar(digest: Uint8Array): bigint {
  return bytesToNumberLE(digest) % ORDER;
}

/** SerializeScalar: 32-byte little-endian encoding of the reduced scalar (RFC 6.2). */
function serializeScalar(s: bigint): Uint8Array {
  return numberToBytesLE(reduce(s), 32);
}

/** SerializeElement: ristretto255 Encode, rejecting the identity element (RFC 6.2 / RFC 9496). */
function serializeElement(p: Point): Uint8Array {
  if (p.equals(RistrettoPoint.ZERO)) {
    throw new Error("ristretto255: refusing to serialize the identity element");
  }
  return p.toRawBytes();
}

/** encode_group_commitment_list: concat over the list SORTED ASCENDING by id of
 *  (SerializeScalar(id) || SerializeElement(D_i) || SerializeElement(E_i)) (RFC 4.3). */
function encodeCommitmentList(commitments: Commitment<Point>[]): Uint8Array {
  const sorted = [...commitments].sort((a, b) =>
    a.id < b.id ? -1 : a.id > b.id ? 1 : 0,
  );
  const parts: Uint8Array[] = [];
  for (const c of sorted) {
    parts.push(
      serializeScalar(c.id),
      serializeElement(c.D),
      serializeElement(c.E),
    );
  }
  return concatBytes(...parts);
}

/** The rho_i binding-factor preimage: SerializeElement(gpk) || H4(msg) || H5(list) || SerializeScalar(id)
 *  (RFC 4.4). Exported so the RFC 9591 KAT can assert the recorded binding_factor_input bytes directly. */
export function bindingFactorInput(
  gpk: Point,
  msg: Uint8Array,
  commitments: Commitment<Point>[],
  id: bigint,
): Uint8Array {
  const msgHash = h(LABEL_MSG, msg); // H4(msg)
  const listHash = h(LABEL_COM, encodeCommitmentList(commitments)); // H5(encode_group_commitment_list)
  return concatBytes(
    serializeElement(gpk),
    msgHash,
    listHash,
    serializeScalar(id),
  );
}

export const ristretto255Ciphersuite: Ciphersuite<Point> = {
  name: "FROST-RISTRETTO255-SHA512-v1",
  generator: RistrettoPoint.BASE,
  identity: RistrettoPoint.ZERO,
  add: (a, b) => a.add(b),
  // Reduce mod L, then multiplyUnsafe (accepts k in [0, L): 0 -> identity, identity*k -> identity). Variable
  // time is acceptable for this test-only certification ciphersuite.
  scalarMul: (k, p) => p.multiplyUnsafe(reduce(k)),
  negate: (p) => p.negate(),
  eq: (a, b) => a.equals(b),
  order: ORDER,

  // H3: nonce_generate(secret) = H3(random32 || SerializeScalar(secret)) (RFC 5.1 / 6.2).
  nonceScalar(random32: Uint8Array, secret: bigint): bigint {
    return hashToScalar(
      h(LABEL_NONCE, concatBytes(random32, serializeScalar(secret))),
    );
  },

  // H1: rho_i over the binding-factor input (RFC 4.4 / 6.2).
  bindingFactor(
    gpk: Point,
    msg: Uint8Array,
    commitments: Commitment<Point>[],
    id: bigint,
  ): bigint {
    return hashToScalar(
      h(LABEL_RHO, bindingFactorInput(gpk, msg, commitments, id)),
    );
  },

  // H2: c = H2(SerializeElement(R) || SerializeElement(gpk) || msg) (RFC 4.6 / 6.2).
  challenge(R: Point, gpk: Point, msg: Uint8Array): bigint {
    return hashToScalar(
      h(
        LABEL_CHAL,
        concatBytes(serializeElement(R), serializeElement(gpk), msg),
      ),
    );
  },
};
