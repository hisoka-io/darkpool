import { Fr } from "@aztec/foundation/fields";
import { keccak256, toUtf8Bytes } from "ethers";
import { Poseidon } from "../crypto/Poseidon.js";
import { toFr, toReducedFr } from "../crypto/fields.js";
import { LeanIMT } from "./LeanIMT.js";

const GENESIS_DOMAIN = "hisoka.darkpool.genesis";

/** Frozen with the on-chain tree: MUST equal `MERKLE_TREE_DEPTH` in DarkPool.sol. */
export const TREE_DEPTH = 32;

/**
 * Byte-identical to `DarkPool._genesisLeaf()`: Poseidon2(keccak256("hisoka.darkpool.genesis") reduced mod
 * the BN254 scalar field, chainId).
 *
 * `chainId` is REQUIRED. It is the tree's cross-chain replay defence, so a default would let a wallet build
 * a tree whose every root silently disagrees with the pool it is talking to.
 */
export async function genesisLeaf(chainId: bigint): Promise<Fr> {
  const domainTag = BigInt(keccak256(toUtf8Bytes(GENESIS_DOMAIN)));
  return Poseidon.hash([toReducedFr(domainTag), toFr(chainId)]);
}

/** A LeanIMT seeded exactly as the contract seeds it: genesis at index 0, so real notes start at index 1. */
export async function newSeededTree(chainId: bigint): Promise<LeanIMT> {
  const tree = new LeanIMT(TREE_DEPTH);
  await tree.insert(await genesisLeaf(chainId));
  return tree;
}
