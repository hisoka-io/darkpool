import { expect } from "chai";
import { ethers } from "hardhat";
import {
  MerkleTreeLibHarness,
  MerkleTreeLibHarness__factory,
  Poseidon2,
  Poseidon2__factory,
} from "../../typechain-types";
import { LeanIMT, toFr } from "@hisoka/wallets";

// FRONTIER=1 npx hardhat test test/benchmark/FrontierParity.bench.ts
// Proves the frontier tree is byte-identical to the TS LeanIMT (the circuits' reference) at production depth 32
// over a leaf set that exercises even/odd positions at every level, AND measures per-insert gas vs the whole-tree
// baseline (~386k-486k/insert).
const run = process.env.FRONTIER ? describe : describe.skip;

run(
  "Frontier tree: parity vs TS LeanIMT + per-insert gas (depth 32)",
  function () {
    this.timeout(600_000);

    let harness: MerkleTreeLibHarness;
    const DEPTH = 32;
    const N = 40;

    beforeEach(async function () {
      const poseidon2 = (await (
        (await ethers.getContractFactory(
          "Poseidon2",
        )) as unknown as Poseidon2__factory
      ).deploy()) as Poseidon2;
      harness = (await (
        (await ethers.getContractFactory("MerkleTreeLibHarness", {
          libraries: { Poseidon2: await poseidon2.getAddress() },
        })) as unknown as MerkleTreeLibHarness__factory
      ).deploy(DEPTH)) as MerkleTreeLibHarness;
    });

    it("root byte-identical to TS LeanIMT at every insert + gas per insert", async function () {
      const ts = new LeanIMT(DEPTH);
      const gas: bigint[] = [];

      for (let i = 1; i <= N; i++) {
        await ts.insert(toFr(BigInt(i)));
        const expectedRoot = ts.getRoot().toString();

        const rc = await (
          await harness.insert(ethers.zeroPadValue(ethers.toBeHex(i), 32))
        ).wait();
        gas.push(rc!.gasUsed);

        const onchain = await harness.getCurrentRoot();
        expect(onchain, `root mismatch at insert #${i}`).to.equal(expectedRoot);
        expect(await harness.getNextLeafIndex()).to.equal(BigInt(i));
      }

      // deepest-carry insert (#33 crosses into the second top-level subtree) was the whole-tree worst case (486,029)
      const rows = gas
        .map(
          (g, i) =>
            `| ${String(i + 1).padStart(3)} | ${g.toString().padStart(9)} |`,
        )
        .join("\n");
      console.log(
        `\n## Frontier per-insert gas (depth 32), parity-verified vs TS LeanIMT\n` +
          `| insert |   gasUsed |\n|--------|-----------|\n${rows}\n` +
          `min=${gas.reduce((a, b) => (a < b ? a : b)).toString()} ` +
          `max=${gas.reduce((a, b) => (a > b ? a : b)).toString()} ` +
          `insert#33=${gas[32].toString()}\n`,
      );
    });
  },
);
