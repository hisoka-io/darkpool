import { expect } from "chai";
import { ethers } from "hardhat";
import {
  MerkleTreeLibHarness,
  MerkleTreeLibHarness__factory,
  Poseidon2,
  Poseidon2__factory,
} from "../typechain-types";
import { LeanIMT, toFr } from "@hisoka/wallets";

describe("MerkleTreeLib", function () {
  let harness: MerkleTreeLibHarness;
  let poseidon2Lib: Poseidon2;
  const TREE_DEPTH = 4;

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

  it("should have a zero root initially", async function () {
    expect(await harness.getCurrentRoot()).to.equal(
      "0x0000000000000000000000000000000000000000000000000000000000000000",
    );
  });

  it("should calculate roots that match the TypeScript implementation", async function () {
    // TS LeanIMT is the source of truth; the frontier tree must reproduce its root byte-for-byte.
    const tsTree = new LeanIMT(TREE_DEPTH);

    for (let i = 1; i <= 3; i++) {
      await tsTree.insert(toFr(BigInt(i)));
      await harness.insert(ethers.zeroPadValue(ethers.toBeHex(i), 32));
      expect(await harness.getCurrentRoot()).to.equal(
        tsTree.getRoot().toString(),
        `root mismatch after insert #${i}`,
      );
    }
  });
});
