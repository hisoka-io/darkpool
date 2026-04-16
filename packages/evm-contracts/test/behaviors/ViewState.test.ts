import { expect } from "chai";
import { ethers } from "hardhat";
import {
    MerkleTreeLibHarness,
    MerkleTreeLibHarness__factory,
    Poseidon2,
    Poseidon2__factory,
} from "../../typechain-types";
import { LeanIMT, toFr } from "@hisoka/wallets";

describe("ViewState: getMerklePath Parity", function () {
    let harness: MerkleTreeLibHarness;
    let poseidon2Lib: Poseidon2;
    const TREE_DEPTH = 32; // Full tree depth for production parity

    // Helper to convert bigint to bytes32
    function toBytes32(value: bigint): string {
        return ethers.zeroPadValue(ethers.toBeHex(value), 32);
    }

    beforeEach(async function () {
        // Deploy Poseidon2 library
        const Poseidon2Factory = (await ethers.getContractFactory(
            "Poseidon2"
        )) as unknown as Poseidon2__factory;
        poseidon2Lib = await Poseidon2Factory.deploy();

        // Deploy MerkleTreeLibHarness with full depth
        const HarnessFactory = (await ethers.getContractFactory(
            "MerkleTreeLibHarness",
            {
                libraries: {
                    Poseidon2: await poseidon2Lib.getAddress(),
                },
            }
        )) as unknown as MerkleTreeLibHarness__factory;
        harness = await HarnessFactory.deploy(TREE_DEPTH, 100);
    });

    it("should match TypeScript LeanIMT getMerklePath for single leaf", async function () {
        // Create matching tree instances
        const tsTree = new LeanIMT(TREE_DEPTH);

        // Insert single leaf
        const leaf1 = toFr(123456789n);
        await tsTree.insert(leaf1);

        const solLeaf1 = toBytes32(leaf1.toBigInt());
        await harness.insert(solLeaf1);

        // Get paths from both implementations
        const tsPath = tsTree.getMerklePath(0);
        const solPath = await harness.getMerklePath(0);

        // Verify parity - all 32 siblings must match
        for (let i = 0; i < TREE_DEPTH; i++) {
            const tsSibling = tsPath[i].toString();
            const solSibling = solPath[i];
            expect(solSibling).to.equal(
                tsSibling,
                `Sibling mismatch at level ${i}`
            );
        }
    });

    it("should match TypeScript LeanIMT getMerklePath for 5 leaves", async function () {
        // Create matching tree instances
        const tsTree = new LeanIMT(TREE_DEPTH);

        // Insert 5 leaves into both trees
        const leaves = [1n, 2n, 3n, 4n, 5n];
        for (const val of leaves) {
            const fr = toFr(val);
            await tsTree.insert(fr);
            const solLeaf = toBytes32(fr.toBigInt());
            await harness.insert(solLeaf);
        }

        // Verify roots match after all insertions
        const tsRoot = tsTree.getRoot().toString();
        const solRoot = await harness.getCurrentRoot();
        expect(solRoot).to.equal(tsRoot, "Root mismatch after 5 insertions");

        // Verify getMerklePath for each leaf index
        for (let leafIndex = 0; leafIndex < leaves.length; leafIndex++) {
            const tsPath = tsTree.getMerklePath(leafIndex);
            const solPath = await harness.getMerklePath(leafIndex);

            for (let level = 0; level < TREE_DEPTH; level++) {
                const tsSibling = tsPath[level].toString();
                const solSibling = solPath[level];
                expect(solSibling).to.equal(
                    tsSibling,
                    `Path mismatch: leaf ${leafIndex}, level ${level}`
                );
            }
        }
    });

    it("should revert for out-of-bounds leaf index", async function () {
        const tsTree = new LeanIMT(TREE_DEPTH);

        // Insert one leaf
        const leaf = toFr(999n);
        await tsTree.insert(leaf);
        const solLeaf = toBytes32(leaf.toBigInt());
        await harness.insert(solLeaf);

        // Index 0 should work
        await harness.getMerklePath(0);

        // Index 1 should revert (only 1 leaf inserted)
        await expect(harness.getMerklePath(1)).to.be.revertedWithCustomError(
            harness,
            "LeafIndexOutOfBounds"
        );
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
