import { expect } from "chai";
import { ethers } from "hardhat";
import { Poseidon as TsPoseidon, toFr } from "@hisoka/wallets";
import {
  Poseidon2,
  Poseidon2__factory,
  Poseidon2Harness,
  Poseidon2Harness__factory,
} from "../typechain-types";

// parity between TS `@aztec/foundation/crypto` and the Solidity Yul sponge.
const KNOWN_HASH_2_1_2 =
  "0x038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383";

describe("Poseidon2 parity (Yul-backed) vs TypeScript reference", () => {
  let lib: Poseidon2;
  let harness: Poseidon2Harness;

  before(async () => {
    const Factory = (await ethers.getContractFactory(
      "Poseidon2",
    )) as unknown as Poseidon2__factory;
    lib = await Factory.deploy();
    const HarnessFactory = (await ethers.getContractFactory(
      "Poseidon2Harness",
    )) as unknown as Poseidon2Harness__factory;
    harness = await HarnessFactory.deploy();
  });

  it("hash_2(1,2) matches the published test vector", async () => {
    const got = await lib.hash_2(1n, 2n);
    expect(ethers.toBeHex(got, 32)).to.equal(KNOWN_HASH_2_1_2);
  });

  it("hash_1 matches TS Poseidon.hash([x])", async () => {
    for (const x of [1n, 2n, 42n, 1n << 200n]) {
      const ts = (await TsPoseidon.hash([toFr(x)])).toBigInt();
      const sol = await lib.hash_1(x);
      expect(sol).to.equal(ts, `hash_1(${x})`);
    }
  });

  it("hash_2 matches TS Poseidon.hash([x,y])", async () => {
    for (const [x, y] of [
      [0n, 0n],
      [1n, 2n],
      [3n, 4n],
      [12345n, 67890n],
    ] as [bigint, bigint][]) {
      const ts = (await TsPoseidon.hash([toFr(x), toFr(y)])).toBigInt();
      const sol = await lib.hash_2(x, y);
      expect(sol).to.equal(ts, `hash_2(${x},${y})`);
    }
  });

  it("hash_3 matches TS Poseidon.hash([x,y,z])", async () => {
    for (const [x, y, z] of [
      [1n, 2n, 3n],
      [0n, 0n, 0n],
      [11n, 22n, 33n],
    ] as [bigint, bigint, bigint][]) {
      const ts = (
        await TsPoseidon.hash([toFr(x), toFr(y), toFr(z)])
      ).toBigInt();
      const sol = await lib.hash_3(x, y, z);
      expect(sol).to.equal(ts, `hash_3(${x},${y},${z})`);
    }
  });

  it("variable-length hash matches TS reference for lengths 1..10", async () => {
    for (let n = 1; n <= 10; n++) {
      const inputs = Array.from({ length: n }, (_, i) => BigInt(i + 1));
      const ts = (await TsPoseidon.hash(inputs.map((v) => toFr(v)))).toBigInt();
      const sol = await lib["hash(uint256[])"](inputs);
      expect(sol).to.equal(ts, `hash(len=${n})`);
    }
  });

  it("variable-length hash matches via the Poseidon2Lib internal path", async () => {
    for (const inputs of [
      [1n],
      [1n, 2n, 3n, 4n, 5n, 6n, 7n],
      [9n, 8n, 7n, 6n, 5n, 4n],
      Array.from({ length: 8 }, (_, i) => BigInt(100 + i)),
    ]) {
      const ts = (await TsPoseidon.hash(inputs.map((v) => toFr(v)))).toBigInt();
      const sol = await harness.hashArray(inputs);
      expect(sol).to.equal(ts, `harness.hashArray(len=${inputs.length})`);
    }
  });

  it("is_variable_length=true appends the `1` domain separator", async () => {
    const inputs = [1n, 2n, 3n];
    const fixed = await harness.hashFixed(inputs);
    const variable = await harness.hashVariable(inputs);
    expect(fixed).to.not.equal(variable);
  });

  // Golden KAT: the public-memo id is Poseidon2 over 6 fields (value, asset, timelock, ownerX, ownerY,
  // salt), byte-identical to DarkPool.publicTransfer and the public_claim circuit.
  it("memoId matches the public_claim fixture (6-field Poseidon2)", async () => {
    const value = 100n;
    const asset = 0x1234567890123456789012345678901234567890n;
    const timelock = 0n;
    const ownerX =
      0x2a39f6a9afe8c569977ec299af985e30142d18ee451008ffd13fc0a2a36cf54en;
    const ownerY =
      0x1d5a43dc73fe0493cce521cc92a4d34d4837214ce47871c587c567d2d0c72c8fn;
    const salt =
      0x004996117eaf098d97b6a42a8ec9c27b5ec30cdca90ffbdb6792eb4733c982d4n;
    const EXPECTED =
      "0x0731300919ae74d1507ab3b22cac576da8c86deb8ddc11f24317b861f17f6f93";

    const memoId = await lib["hash(uint256[])"]([
      value,
      asset,
      timelock,
      ownerX,
      ownerY,
      salt,
    ]);
    expect(ethers.toBeHex(memoId, 32)).to.equal(EXPECTED);
  });
});
