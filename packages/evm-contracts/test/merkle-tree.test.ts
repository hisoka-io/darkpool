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
            "Poseidon2"
        )) as unknown as Poseidon2__factory;
        poseidon2Lib = await Poseidon2Factory.deploy();

        const HarnessFactory = (await ethers.getContractFactory(
            "MerkleTreeLibHarness",
            {
                libraries: {
                    Poseidon2: await poseidon2Lib.getAddress(),
                },
            }
        )) as unknown as MerkleTreeLibHarness__factory;
        harness = await HarnessFactory.deploy(TREE_DEPTH, 10);
    });

    it("should have a zero root initially", async function () {
        expect(await harness.getCurrentRoot()).to.equal(
            "0x0000000000000000000000000000000000000000000000000000000000000000"
        );
    });

    it("should calculate roots that match the TypeScript implementation", async function () {
        // Create the Source of Truth (TS implementation)
        const tsTree = new LeanIMT(TREE_DEPTH);

        // --- Insert 1 ---
        const leaf1 = toFr(1n);
        // TS Update
        await tsTree.insert(leaf1);
        const expectedRoot1 = tsTree.getRoot().toString();

        // Solidity Update
        await harness.insert(ethers.zeroPadValue("0x01", 32));

        // Verify
        expect(await harness.getCurrentRoot()).to.equal(expectedRoot1);

        // --- Insert 2 ---
        const leaf2 = toFr(2n);
        await tsTree.insert(leaf2);
        const expectedRoot2 = tsTree.getRoot().toString();

        await harness.insert(ethers.zeroPadValue("0x02", 32));
        expect(await harness.getCurrentRoot()).to.equal(expectedRoot2);

        // --- Insert 3 ---
        const leaf3 = toFr(3n);
        await tsTree.insert(leaf3);
        const expectedRoot3 = tsTree.getRoot().toString();

        await harness.insert(ethers.zeroPadValue("0x03", 32));
        expect(await harness.getCurrentRoot()).to.equal(expectedRoot3);
    });

    describe("getSubtreeWithProof", function () {
        it("should return empty proof and single leaf for level 0", async function () {
            // Insert a single leaf
            await harness.insert(ethers.zeroPadValue("0x01", 32));

            const [proof, leafs] = await harness.getSubtreeWithProof(0, 0);

            // At level 0, we're requesting a single leaf, so proof should go all the way to root
            expect(proof.length).to.equal(TREE_DEPTH);
            expect(leafs.length).to.equal(1);
            expect(leafs[0]).to.equal(ethers.zeroPadValue("0x01", 32));
        });

        it("should return correct proof and leafs for level 1 subtree", async function () {
            // Insert 4 leaves
            await harness.insert(ethers.zeroPadValue("0x01", 32));
            await harness.insert(ethers.zeroPadValue("0x02", 32));
            await harness.insert(ethers.zeroPadValue("0x03", 32));
            await harness.insert(ethers.zeroPadValue("0x04", 32));

            // Get left subtree (position 0) at level 1
            const [proof, leafs] = await harness.getSubtreeWithProof(1, 0);

            // At level 1, we get 2 leaves and proof to root (TREE_DEPTH - 1)
            expect(proof.length).to.equal(TREE_DEPTH - 1);
            expect(leafs.length).to.equal(2);
            expect(leafs[0]).to.equal(ethers.zeroPadValue("0x01", 32));
            expect(leafs[1]).to.equal(ethers.zeroPadValue("0x02", 32));
        });

        it("should return correct proof and leafs for right subtree", async function () {
            // Insert 4 leaves
            await harness.insert(ethers.zeroPadValue("0x01", 32));
            await harness.insert(ethers.zeroPadValue("0x02", 32));
            await harness.insert(ethers.zeroPadValue("0x03", 32));
            await harness.insert(ethers.zeroPadValue("0x04", 32));

            // Get right subtree (position 1) at level 1
            const [proof, leafs] = await harness.getSubtreeWithProof(1, 1);

            expect(proof.length).to.equal(TREE_DEPTH - 1);
            expect(leafs.length).to.equal(2);
            expect(leafs[0]).to.equal(ethers.zeroPadValue("0x03", 32));
            expect(leafs[1]).to.equal(ethers.zeroPadValue("0x04", 32));
        });

        it("should return zeros for empty leaf positions", async function () {
            // Insert only 2 leaves
            await harness.insert(ethers.zeroPadValue("0x01", 32));
            await harness.insert(ethers.zeroPadValue("0x02", 32));

            // Get right subtree (position 1) at level 1, which should be empty
            const [, leafs] = await harness.getSubtreeWithProof(1, 1);

            expect(leafs.length).to.equal(2);
            expect(leafs[0]).to.equal(ethers.ZeroHash);
            expect(leafs[1]).to.equal(ethers.ZeroHash);
        });

        it("should return all leafs at maximum level", async function () {
            // Insert 8 leaves
            for (let i = 1; i <= 8; i++) {
                await harness.insert(
                    ethers.zeroPadValue(ethers.toBeHex(i), 32)
                );
            }

            // At level TREE_DEPTH, we get all leafs (2^TREE_DEPTH = 16 for depth 4)
            const [proof, leafs] = await harness.getSubtreeWithProof(
                TREE_DEPTH,
                0
            );

            expect(proof.length).to.equal(0); // No proof needed at root level
            expect(leafs.length).to.equal(1 << TREE_DEPTH); // 2^TREE_DEPTH

            // Check first 8 are our inserted values
            for (let i = 0; i < 8; i++) {
                expect(leafs[i]).to.equal(
                    ethers.zeroPadValue(ethers.toBeHex(i + 1), 32)
                );
            }

            // Check remaining are zeros
            for (let i = 8; i < leafs.length; i++) {
                expect(leafs[i]).to.equal(ethers.ZeroHash);
            }
        });

        it("should return correct subtree for level 2", async function () {
            // Insert 8 leaves
            for (let i = 1; i <= 8; i++) {
                await harness.insert(
                    ethers.zeroPadValue(ethers.toBeHex(i), 32)
                );
            }

            // Get second subtree (position 1) at level 2
            const [proof, leafs] = await harness.getSubtreeWithProof(2, 1);

            expect(proof.length).to.equal(TREE_DEPTH - 2);
            expect(leafs.length).to.equal(4);

            // Position 1 at level 2 means leafs 4-7 (0-indexed)
            expect(leafs[0]).to.equal(
                ethers.zeroPadValue(ethers.toBeHex(5), 32)
            );
            expect(leafs[1]).to.equal(
                ethers.zeroPadValue(ethers.toBeHex(6), 32)
            );
            expect(leafs[2]).to.equal(
                ethers.zeroPadValue(ethers.toBeHex(7), 32)
            );
            expect(leafs[3]).to.equal(
                ethers.zeroPadValue(ethers.toBeHex(8), 32)
            );
        });

        it("should revert when level is out of bounds", async function () {
            await harness.insert(ethers.zeroPadValue("0x01", 32));

            await expect(
                harness.getSubtreeWithProof(TREE_DEPTH + 1, 0)
            ).to.be.revertedWithCustomError(harness, "LevelOutOfBounds");
        });

        it("should revert when position is out of bounds", async function () {
            await harness.insert(ethers.zeroPadValue("0x01", 32));

            // At level 0, max position is 2^(TREE_DEPTH - 0) - 1 = 15 for depth 4
            await expect(
                harness.getSubtreeWithProof(0, 1 << TREE_DEPTH)
            ).to.be.revertedWithCustomError(harness, "PositionOutOfBounds");
        });

        it("should work correctly with empty tree", async function () {
            // Don't insert any leaves
            const [proof, leafs] = await harness.getSubtreeWithProof(0, 0);

            expect(proof.length).to.equal(TREE_DEPTH);
            expect(leafs.length).to.equal(1);
            expect(leafs[0]).to.equal(ethers.ZeroHash);
        });

        it("should return correct multiple subtrees from same level", async function () {
            // Insert 8 leaves
            for (let i = 1; i <= 8; i++) {
                await harness.insert(
                    ethers.zeroPadValue(ethers.toBeHex(i), 32)
                );
            }

            // Get all subtrees at level 2 (4 subtrees, each with 4 leaves)
            const subtrees = [];
            for (let pos = 0; pos < 4; pos++) {
                const [proof, leafs] = await harness.getSubtreeWithProof(
                    2,
                    pos
                );
                subtrees.push({ proof, leafs });
            }

            // Verify each subtree has correct structure
            for (let i = 0; i < 4; i++) {
                expect(subtrees[i].proof.length).to.equal(TREE_DEPTH - 2);
                expect(subtrees[i].leafs.length).to.equal(4);
            }

            // Verify first subtree contains leaves 1-4
            for (let j = 0; j < 4; j++) {
                expect(subtrees[0].leafs[j]).to.equal(
                    ethers.zeroPadValue(ethers.toBeHex(j + 1), 32)
                );
            }

            // Verify second subtree contains leaves 5-8
            for (let j = 0; j < 4; j++) {
                expect(subtrees[1].leafs[j]).to.equal(
                    ethers.zeroPadValue(ethers.toBeHex(j + 5), 32)
                );
            }
        });
    });
});
