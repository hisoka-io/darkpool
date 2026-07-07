// FROST(ristretto255, SHA-512) ciphersuite, RFC 9591 Section 6.2 (encodings per RFC 9496). Test-only; it
// certifies frost.ts against the official RFC 9591 KAT. bjj.ts is production.

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

function h(label: Uint8Array, m: Uint8Array): Uint8Array {
  return sha512(concatBytes(CONTEXT_STRING, label, m));
}

function hashToScalar(digest: Uint8Array): bigint {
  return bytesToNumberLE(digest) % ORDER;
}

function serializeScalar(s: bigint): Uint8Array {
  return numberToBytesLE(reduce(s), 32);
}

function serializeElement(p: Point): Uint8Array {
  if (p.equals(RistrettoPoint.ZERO)) {
    throw new Error("ristretto255: refusing to serialize the identity element");
  }
  return p.toRawBytes();
}

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

export function bindingFactorInput(
  gpk: Point,
  msg: Uint8Array,
  commitments: Commitment<Point>[],
  id: bigint,
): Uint8Array {
  const msgHash = h(LABEL_MSG, msg);
  const listHash = h(LABEL_COM, encodeCommitmentList(commitments));
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
  scalarMul: (k, p) => p.multiplyUnsafe(reduce(k)),
  negate: (p) => p.negate(),
  eq: (a, b) => a.equals(b),
  order: ORDER,

  nonceScalar(random32: Uint8Array, secret: bigint): bigint {
    return hashToScalar(
      h(LABEL_NONCE, concatBytes(random32, serializeScalar(secret))),
    );
  },

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

  challenge(R: Point, gpk: Point, msg: Uint8Array): bigint {
    return hashToScalar(
      h(
        LABEL_CHAL,
        concatBytes(serializeElement(R), serializeElement(gpk), msg),
      ),
    );
  },
};
