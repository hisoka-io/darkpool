import { Fr } from "@aztec/foundation/fields";
import { mulPointEscalar, Point, inCurve, subOrder } from "@zk-kit/baby-jubjub";
import { Poseidon } from "./Poseidon.js";
import { BJJ_SUBGROUP_ORDER } from "./constants.js";

function assertSubgroupScalar(scalar: Fr): void {
  const s = scalar.toBigInt();
  if (s === 0n) {
    throw new Error("KEM scalar must be non-zero");
  }
  if (s >= BJJ_SUBGROUP_ORDER) {
    throw new Error("KEM scalar not in BabyJubJub prime-order subgroup");
  }
}

// A low-order point leaks a scalar via the cofactor; mirrors the in-circuit point checks.
function assertValidPoint(p: Point<bigint>): void {
  if (!inCurve(p)) {
    throw new Error("KEM point is not on the BabyJubJub curve");
  }
  if (p[0] === 0n && p[1] === 1n) {
    throw new Error("KEM point is the identity");
  }
  const [ox, oy] = mulPointEscalar(p, subOrder);
  if (ox !== 0n || oy !== 1n) {
    throw new Error("KEM point is not in the prime-order subgroup");
  }
}

/** CEK = (eph * C).x. eph MUST be unique per note: reuse to the same C repeats the DEM keystream (two-time pad). */
export function deriveCek(eph: Fr, compliancePk: Point<bigint>): Fr {
  assertSubgroupScalar(eph);
  assertValidPoint(compliancePk);
  return new Fr(mulPointEscalar(compliancePk, eph.toBigInt())[0]);
}

/** cek_wrap = cek + Poseidon2([(eph*in_pub).x]); unwrap subtracts the same pad. */
export async function wrapCek(
  cek: Fr,
  eph: Fr,
  inPub: Point<bigint>,
): Promise<Fr> {
  assertSubgroupScalar(eph);
  assertValidPoint(inPub);
  const pad = new Fr(mulPointEscalar(inPub, eph.toBigInt())[0]);
  const padHash = await Poseidon.hash([pad]);
  return cek.add(padHash);
}

/** ECDH symmetry makes (in_key*eph_pub).x equal (eph*in_pub).x, so this pad matches wrapCek's. */
export async function unwrapCek(
  cekWrap: Fr,
  inKey: Fr,
  ephPub: Point<bigint>,
): Promise<Fr> {
  assertSubgroupScalar(inKey);
  assertValidPoint(ephPub);
  const pad = new Fr(mulPointEscalar(ephPub, inKey.toBigInt())[0]);
  const padHash = await Poseidon.hash([pad]);
  return cekWrap.sub(padHash);
}
