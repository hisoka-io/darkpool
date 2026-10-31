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
const run = process.env.FRONTIER ? describe : describe.skip;

// Ceilings, not targets: measured on this tree plus 3%, rounded up to the next thousand. The inserted leaves are
// fixed, so these figures reproduce exactly; a breach is a regression to explain and re-pin deliberately.
const MAX_INSERT_GAS = 188_000;
const TOTAL_INSERT_GAS = 5_687_000;

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

      const rows = gas
        .map(
          (g, i) =>
            `| ${String(i + 1).padStart(3)} | ${g.toString().padStart(9)} |`,
        )
        .join("\n");
      const max = gas.reduce((a, b) => (a > b ? a : b));
      const total = gas.reduce((a, b) => a + b, 0n);
      console.log(
        `\n## Frontier per-insert gas (depth 32), parity-verified vs TS LeanIMT\n` +
          `| insert |   gasUsed |\n|--------|-----------|\n${rows}\n` +
          `min=${gas.reduce((a, b) => (a < b ? a : b)).toString()} ` +
          `max=${max.toString()} total=${total.toString()} ` +
          `insert#33=${gas[32].toString()}\n`,
      );
      expect(Number(max)).to.be.at.most(
        MAX_INSERT_GAS,
        "per-insert gas regressed past its pinned ceiling",
      );
      expect(Number(total)).to.be.at.most(
        TOTAL_INSERT_GAS,
        `gas for ${N} inserts regressed past its pinned ceiling`,
      );
    });
  },
);
