import { describe, it, expect } from "vitest";
import { Point, mulPointEscalar, Base8 } from "@zk-kit/baby-jubjub";
import { Contract } from "ethers";
import { DarkAccount } from "../keys/DarkAccount";
import { KeyRepository } from "../state/KeyRepository";
import { UtxoRepository } from "../state/UtxoRepository";
import { LeanIMT } from "../merkle/LeanIMT";
import { ScanEngine } from "../sync/ScanEngine";

const MNEMONIC = "test test test test test test test test test test test junk";
const COMPLIANCE_PK: Point<bigint> = mulPointEscalar(Base8, 987654321n);

type Leaf = { leafIndex: number; commitment: string; block: number };

function fakeContract(leaves: Leaf[], head: { value: number }): Contract {
  const noteLogs = leaves.map((l) => ({
    blockNumber: l.block,
    index: l.leafIndex,
    transactionHash: "0xtx",
    fragment: { name: "NewNote" },
    args: {
      leafIndex: BigInt(l.leafIndex),
      commitment: l.commitment,
      ephemeralPK_x: 1n, // never matches this wallet -> no decryption side effects
      ephemeralPK_y: 2n,
      packedCiphertext: ["0x0", "0x0", "0x0", "0x0", "0x0", "0x0", "0x0"],
    },
  }));
  return {
    runner: { provider: { getBlockNumber: async () => head.value } },
    filters: {
      NewNote: () => "NewNote",
      NewPrivateMemo: () => "NewPrivateMemo",
      NullifierSpent: () => "NullifierSpent",
    },
    queryFilter: async (filter: string) =>
      filter === "NewNote" ? noteLogs : [],
  } as unknown as Contract;
}

describe("ScanEngine finality depth", () => {
  it("holds unfinalized leaves out of the committed tree, inserts once finalized", async () => {
    const account = await DarkAccount.fromMnemonic(MNEMONIC);
    const keyRepo = new KeyRepository(account, COMPLIANCE_PK);
    const utxoRepo = new UtxoRepository();
    const tree = new LeanIMT(32);

    const leaves: Leaf[] = [
      { leafIndex: 0, commitment: "0x05", block: 50 },
      { leafIndex: 1, commitment: "0x07", block: 100 },
    ];
    const head = { value: 100 };
    const contract = fakeContract(leaves, head);

    const engine = new ScanEngine(
      contract,
      keyRepo,
      utxoRepo,
      COMPLIANCE_PK,
      tree,
      20,
      0,
      12, // finalityDepth
    );

    // head 100, depth 12 -> finalized <= 88: leaf 0 (block 50) enters, leaf 1 (block 100) held.
    await engine.sync(0);
    expect(tree.nextLeafIndex).toBe(1);

    // Chain advances past finality for leaf 1 (block 100 <= 120 - 12).
    head.value = 120;
    await engine.sync(0);
    expect(tree.nextLeafIndex).toBe(2);
  });

  it("finalityDepth 0 is optimistic (inserts immediately)", async () => {
    const account = await DarkAccount.fromMnemonic(MNEMONIC);
    const keyRepo = new KeyRepository(account, COMPLIANCE_PK);
    const utxoRepo = new UtxoRepository();
    const tree = new LeanIMT(32);

    const leaves: Leaf[] = [
      { leafIndex: 0, commitment: "0x05", block: 50 },
      { leafIndex: 1, commitment: "0x07", block: 100 },
    ];
    const contract = fakeContract(leaves, { value: 100 });

    const engine = new ScanEngine(contract, keyRepo, utxoRepo, COMPLIANCE_PK, tree);
    await engine.sync(0);
    expect(tree.nextLeafIndex).toBe(2);
  });
});
