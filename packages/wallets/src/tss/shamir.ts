// Shamir sharing, ALL mod SUBORDER (a mod-BN254-Fr variant is silently catastrophic).

import { modSub, invSub, SUBORDER } from "./bjj.js";

export function polyEval(coeffs: bigint[], x: bigint): bigint {
  const xr = modSub(x);
  let acc = 0n;
  for (let k = coeffs.length - 1; k >= 0; k--) {
    acc = modSub(acc * xr + coeffs[k]);
  }
  return acc;
}

export function lagrangeAtZero(i: bigint, xs: bigint[]): bigint {
  const ir = modSub(i);
  let num = 1n;
  let den = 1n;
  for (const j of xs) {
    const jr = modSub(j);
    if (jr === ir) continue;
    num = modSub(num * jr);
    den = modSub(den * modSub(jr - ir));
  }
  if (den === 0n)
    throw new Error("tss: duplicate identifier in interpolation set");
  return modSub(num * invSub(den));
}

export function interpolateAtZero(
  shares: ReadonlyMap<bigint, bigint>,
  quorum: bigint[],
): bigint {
  let acc = 0n;
  for (const i of quorum) {
    const s = shares.get(i);
    if (s === undefined)
      throw new Error(`tss: missing share for identifier ${i}`);
    acc = modSub(acc + lagrangeAtZero(i, quorum) * s);
  }
  return acc;
}

export { SUBORDER };
