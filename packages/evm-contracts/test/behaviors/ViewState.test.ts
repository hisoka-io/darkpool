import { expect } from "chai";
import { ethers } from "hardhat";
import {
  MerkleTreeLibHarness,
  MerkleTreeLibHarness__factory,
  Poseidon2,
  Poseidon2__factory,
} from "../../typechain-types";
import { LeanIMT, toFr } from "@hisoka/wallets";

describe("ViewState: frontier tree parity + nextLeafIndex", function () {
  let harness: MerkleTreeLibHarness;
  let poseidon2Lib: Poseidon2;
  const TREE_DEPTH = 32; // Full tree depth for production parity

  function toBytes32(value: bigint): string {
    return ethers.zeroPadValue(ethers.toBeHex(value), 32);
  }

  beforeEach(async function () {
    const Poseidon2Factory = (await ethers.getContractFactory(
      "Poseidon2",
    )) as unknown as Poseidon2__factory;
    poseidon2Lib = await Poseidon2Factory.deploy();

    const HarnessFactory = (await ethers.getContractFactory(
      "MerkleTreeLibHarness",
      {
        libraries: {
          Poseidon2: await poseidon2Lib.getAddress(),
        },
      },
    )) as unknown as MerkleTreeLibHarness__factory;
    harness = await HarnessFactory.deploy(TREE_DEPTH);
  });

  it("root matches TS LeanIMT for a single leaf", async function () {
    const tsTree = new LeanIMT(TREE_DEPTH);
    const leaf = toFr(123456789n);
    await tsTree.insert(leaf);
    await harness.insert(toBytes32(leaf.toBigInt()));
    expect(await harness.getCurrentRoot()).to.equal(
      tsTree.getRoot().toString(),
    );
  });

  it("root matches TS LeanIMT across 5 leaves", async function () {
    const tsTree = new LeanIMT(TREE_DEPTH);
    for (const val of [1n, 2n, 3n, 4n, 5n]) {
      const fr = toFr(val);
      await tsTree.insert(fr);
      await harness.insert(toBytes32(fr.toBigInt()));
      expect(await harness.getCurrentRoot()).to.equal(
        tsTree.getRoot().toString(),
      );
    }
  });

  it("should return correct nextLeafIndex", async function () {
    expect(await harness.getNextLeafIndex()).to.equal(0);

    const leaf = toBytes32(1n);
    await harness.insert(leaf);
    expect(await harness.getNextLeafIndex()).to.equal(1);

    await harness.insert(leaf);
    await harness.insert(leaf);
    expect(await harness.getNextLeafIndex()).to.equal(3);
  });
});
