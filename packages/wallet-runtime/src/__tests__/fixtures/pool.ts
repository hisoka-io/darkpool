import { Fr } from "@aztec/foundation/fields";
import type { Point } from "@zk-kit/baby-jubjub";
import {
  DarkAccount,
  demEncrypt,
  genesisLeaf,
  LeanIMT,
  publicKey,
  TREE_DEPTH,
  type MintedNote,
  type SentMemoNote,
} from "@hisoka/wallets";
import { configFor, FakeChain } from "./chain.js";
import type { ChainConfig } from "../../config.js";

export const MNEMONIC =
  "test test test test test test test test test test test junk";
export const OTHER_MNEMONIC =
  "legal winner thank year wave sausage worth useful legal winner thank yellow";
export const DEPLOY = 5;
export const CHAIN_ID = 31337n;

/** Compliance keys by version: v1, v2, v3. */
export const COMPLIANCE_SK = [101n, 202n, 303n].map((s) => new Fr(s));
export const COMPLIANCE_PK: Point<bigint>[] = COMPLIANCE_SK.map((sk) =>
  publicKey(sk),
);

function word(f: Fr): string {
  return `0x${f.toBigInt().toString(16).padStart(64, "0")}`;
}

/** The seven transmitted ciphertext words a note event carries. */
export async function packedCiphertext(
  m: Pick<MintedNote, "cek" | "note">,
): Promise<Fr[]> {
  const n = m.note;
  return demEncrypt(m.cek, [
    n.noteVersion,
    n.assetId,
    n.noteType,
    n.conditionsHash,
    n.value,
    n.owner,
    n.parents,
  ]);
}

interface PoolLeaf {
  readonly leaf: Fr;
  readonly block: number;
}

/**
 * A pool on a `FakeChain` that behaves like DarkPool: one LeanIMT with the genesis leaf, `LeafInserted` with
 * the real new root, the note event beside it, `isKnownRoot` over every root ever saved, and the state the
 * pool held at any block. A chain reorg drops the leaves of the replaced blocks.
 */
export class SimPool {
  readonly chain: FakeChain;
  readonly config: ChainConfig;
  leaves: PoolLeaf[] = [];
  complianceVersion = 1;
  rotations: { block: number; version: number }[] = [];

  constructor(height: number) {
    this.chain = new FakeChain(height);
    this.config = configFor(DEPLOY);
    this.chain.compliance = (n) => {
      if (n < DEPLOY) return { x: 0n, y: 0n, version: 0 };
      const live = this.rotations.filter((r) => r.block <= n);
      const v = live.length === 0 ? 1 : live[live.length - 1]!.version;
      const pk = COMPLIANCE_PK[v - 1]!;
      return { x: pk[0], y: pk[1], version: v };
    };
    this.chain.poolCall = (name, args, block) => {
      const at = this.leaves.filter((l) => l.block <= block);
      if (name === "getNextLeafIndex") return [BigInt(at.length)];
      if (name === "getCurrentRoot") return [word(this.#rootOf(at))];
      if (name === "isKnownRoot") {
        const asked = BigInt(args[0] as string);
        for (let k = 1; k <= at.length; k++) {
          if (this.#rootOf(at.slice(0, k)).toBigInt() === asked) return [true];
        }
        return [false];
      }
      throw new Error(`unscripted pool call ${name}`);
    };
  }

  #roots = new Map<string, Fr>();

  #rootOf(leaves: readonly PoolLeaf[]): Fr {
    const key = leaves.map((l) => l.leaf.toString()).join(",");
    const known = this.#roots.get(key);
    if (known === undefined) throw new Error("root of an unseen prefix");
    return known;
  }

  async #remember(leaves: readonly PoolLeaf[]): Promise<Fr> {
    const tree = new LeanIMT(TREE_DEPTH);
    for (const l of leaves) await tree.insert(l.leaf);
    const root = tree.getRoot();
    this.#roots.set(leaves.map((l) => l.leaf.toString()).join(","), root);
    return root;
  }

  static async create(height = 60): Promise<SimPool> {
    const pool = new SimPool(height);
    const pk = COMPLIANCE_PK[0]!;
    pool.chain.emit(DEPLOY, "ComplianceKeyRotated", [0n, 1n, pk[0], pk[1]]);
    const genesis = await genesisLeaf(CHAIN_ID);
    await pool.#append(DEPLOY, genesis);
    pool.chain.emit(DEPLOY, "GenesisSeeded", [CHAIN_ID, word(genesis)]);
    return pool;
  }

  async #append(block: number, leaf: Fr): Promise<number> {
    const index = this.leaves.length;
    this.leaves.push({ leaf, block });
    const root = await this.#remember(this.leaves);
    this.chain.emit(block, "LeafInserted", [
      BigInt(index),
      word(leaf),
      word(root),
    ]);
    return index;
  }

  /** Inserts a self note the way `_insertNote` does and returns its leaf index. */
  async insertSelf(block: number, minted: MintedNote): Promise<number> {
    const index = await this.#append(block, minted.commitment);
    this.chain.emit(block, "NewNote", [
      BigInt(index),
      word(minted.commitment),
      minted.ephPub[0],
      (await packedCiphertext(minted)).map(word),
    ]);
    return index;
  }

  /** Inserts a memo the way `_insertMemoAt` does. */
  async insertMemo(block: number, memo: SentMemoNote): Promise<number> {
    const index = await this.#append(block, memo.commitment);
    this.chain.emit(block, "NewPrivateMemo", [
      BigInt(index),
      word(memo.commitment),
      memo.inPub[0],
      memo.ephPub[0],
      memo.cekWrap.toBigInt(),
      (await packedCiphertext(memo)).map(word),
    ]);
    return index;
  }

  /** Inserts a note from raw public-input words, as `_insertNote` does with a proof's outputs. */
  async insertRaw(
    block: number,
    leaf: Fr,
    ephX: Fr,
    ct: readonly Fr[],
  ): Promise<number> {
    const index = await this.#append(block, leaf);
    this.chain.emit(block, "NewNote", [
      BigInt(index),
      word(leaf),
      ephX.toBigInt(),
      ct.map(word),
    ]);
    return index;
  }

  async insertRawMemo(
    block: number,
    leaf: Fr,
    tag: Fr,
    ephX: Fr,
    cekWrap: Fr,
    ct: readonly Fr[],
  ): Promise<number> {
    const index = await this.#append(block, leaf);
    this.chain.emit(block, "NewPrivateMemo", [
      BigInt(index),
      word(leaf),
      tag.toBigInt(),
      ephX.toBigInt(),
      cekWrap.toBigInt(),
      ct.map(word),
    ]);
    return index;
  }

  rotate(block: number, version: number): void {
    const pk = COMPLIANCE_PK[version - 1]!;
    this.rotations.push({ block, version });
    this.chain.emit(block, "ComplianceKeyRotated", [
      BigInt(version - 1),
      BigInt(version),
      pk[0],
      pk[1],
    ]);
  }

  spend(block: number, nullifier: Fr): void {
    this.chain.emit(block, "NullifierSpent", [word(nullifier)]);
  }

  /** Replaces every block from `height` (new hashes, logs dropped), as a real reorg does. */
  reorgFrom(height: number): void {
    this.chain.reorgFrom(height);
    this.leaves = this.leaves.filter((l) => l.block < height);
    this.rotations = this.rotations.filter((r) => r.block < height);
  }

  root(): Fr {
    return this.#rootOf(this.leaves);
  }
}

export async function accounts(): Promise<{
  readonly alice: DarkAccount;
  readonly bob: DarkAccount;
}> {
  return {
    alice: await DarkAccount.fromMnemonic(MNEMONIC),
    bob: await DarkAccount.fromMnemonic(OTHER_MNEMONIC),
  };
}
