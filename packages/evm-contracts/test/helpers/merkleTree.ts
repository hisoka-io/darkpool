import { ethers } from "hardhat";
import type {
  MerkleTreeLibHarness,
  FullWalkMerkleTreeHarness,
  BreakBeforeWriteMerkleTreeHarness,
} from "../typechain-types";

/** BN254 scalar field modulus. Field.toField rejects anything at or above it. */
export const BN254_FR =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/** Highest set bit position + 1; bitLength(0) = 0. A frontier walk reaches index 0 at exactly this level. */
export function bitLength(n: number): number {
  let bits = 0;
  while (n > 0) {
    bits++;
    n >>>= 1;
  }
  return bits;
}

/** Deterministic PRNG so a fuzz failure is reproducible from its seed alone. */
export function makeRng(seed: bigint): () => bigint {
  let state = seed | 1n;
  const MASK = (1n << 64n) - 1n;
  return () => {
    state ^= (state << 13n) & MASK;
    state ^= state >> 7n;
    state ^= (state << 17n) & MASK;
    state &= MASK;
    return state;
  };
}

/** Non-zero leaves inside the BN254 scalar field. */
export function randomLeaves(rng: () => bigint, count: number): string[] {
  const leaves: string[] = [];
  for (let i = 0; i < count; i++) {
    const hi = rng();
    const lo = rng();
    const v = (((hi << 64n) | lo) % (BN254_FR - 1n)) + 1n;
    leaves.push(ethers.zeroPadValue(ethers.toBeHex(v), 32));
  }
  return leaves;
}

/** Deterministic in-field non-zero leaf. */
export function leafAt(i: number): string {
  const v = (BigInt(i) * 0x9e3779b97f4a7c15n) % (BN254_FR - 1n);
  return ethers.zeroPadValue(ethers.toBeHex(v + 1n), 32);
}

export type MerkleHarness =
  | MerkleTreeLibHarness
  | FullWalkMerkleTreeHarness
  | BreakBeforeWriteMerkleTreeHarness;

// Poseidon2 is stateless and library-linked, so one deployment serves every harness in a mocha process. The fast
// suite runs as a single mocha process (test-parallel.sh), so a per-tree deployment would otherwise pile ~70
// library contracts plus their deploy txs into one in-memory chain and drive peak RSS well past the baseline.
let poseidon2Address: string | undefined;

export async function sharedPoseidon2(): Promise<string> {
  if (!poseidon2Address) {
    const lib = await (await ethers.getContractFactory("Poseidon2")).deploy();
    poseidon2Address = await lib.getAddress();
  }
  return poseidon2Address;
}

export async function deployMerkleHarness(
  name: string,
  depth: number,
): Promise<MerkleHarness> {
  const factory = await ethers.getContractFactory(name, {
    libraries: { Poseidon2: await sharedPoseidon2() },
  });
  return (await factory.deploy(depth)) as unknown as MerkleHarness;
}

/** The shipped walk, the unconditional 32-level walk it replaced, and the break-before-write mutant. */
export async function deployTrio(depth: number) {
  return {
    patched: (await deployMerkleHarness(
      "MerkleTreeLibHarness",
      depth,
    )) as MerkleTreeLibHarness,
    reference: (await deployMerkleHarness(
      "FullWalkMerkleTreeHarness",
      depth,
    )) as FullWalkMerkleTreeHarness,
    mutant: (await deployMerkleHarness(
      "BreakBeforeWriteMerkleTreeHarness",
      depth,
    )) as BreakBeforeWriteMerkleTreeHarness,
  };
}

/** Chunked so a depth-32 sequence never brushes the block gas limit. */
export async function insertAll(
  harness: MerkleHarness,
  leaves: string[],
  chunk = 25,
): Promise<void> {
  for (let i = 0; i < leaves.length; i += chunk) {
    await harness.insertMany(leaves.slice(i, i + chunk));
  }
}
