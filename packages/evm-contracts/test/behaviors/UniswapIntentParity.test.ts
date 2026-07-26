import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";

// TS<->Solidity parity goldens for the Uniswap intent hash, mirrored by packages/adaptors intent.test.ts.
// BASE is _calculateIntentHash; BOUND is the deadline-bound hash written to publicInputs[2].
const DEADLINE = 1800000000n;
const A_IN = "0x1111111111111111111111111111111111111111";
const A_OUT = "0x2222222222222222222222222222222222222222";
const RECIPIENT: [bigint, bigint] = [111n, 222n];
const SALT = 42n;

const coder = ethers.AbiCoder.defaultAbiCoder();

const PATH_IN = ethers.solidityPacked(
  ["address", "uint24", "address"],
  [A_IN, 3000, A_OUT],
);
const PATH_OUT = ethers.solidityPacked(
  ["address", "uint24", "address"],
  [A_OUT, 3000, A_IN],
);

type Case = {
  name: string;
  swapType: number;
  encoded: string;
  base: string;
  bound: string;
};

const CASES: Case[] = [
  {
    name: "ExactInputSingle",
    swapType: 0,
    encoded: coder.encode(
      [
        "tuple(address assetIn,address assetOut,uint24 fee,tuple(uint256 ownerX,uint256 ownerY) recipient,uint256 amountOutMin,uint256 salt)",
      ],
      [[A_IN, A_OUT, 3000, RECIPIENT, 1000n, SALT]],
    ),
    base: "0x2a32d4d602c0f860a19d63fc6a69aa0ec737be4b8d99a2ff036ff2f865c2fbbf",
    bound: "0x0d001900c8416e2225422cbdb1423bb38e5c879e72b704aad02bebaed3c6106d",
  },
  {
    name: "ExactInput",
    swapType: 1,
    encoded: coder.encode(
      [
        "tuple(bytes path,tuple(uint256 ownerX,uint256 ownerY) recipient,uint256 amountOutMin,uint256 salt)",
      ],
      [[PATH_IN, RECIPIENT, 1000n, SALT]],
    ),
    base: "0x1d870343a3a2010bbec7410913098090f3aba79395a049a41c4238539a2bb9fb",
    bound: "0x2eed82bc49420aa5efc2831ee05f9228c9232cb8f4f5a406f7bc6cbb5a0cd278",
  },
  {
    name: "ExactOutputSingle",
    swapType: 2,
    encoded: coder.encode(
      [
        "tuple(address assetIn,address assetOut,uint24 fee,tuple(uint256 ownerX,uint256 ownerY) recipient,uint256 amountOut,uint256 amountInMaximum,uint256 salt)",
      ],
      [[A_IN, A_OUT, 3000, RECIPIENT, 1000n, 5000n, SALT]],
    ),
    base: "0x203be794828822e7d0452efe1035e1879d542b126ec8362248c5ef88de5b9ed2",
    bound: "0x027e3c3bcd86a05f5ab06d003a1bef8ac0ce8f14956b2a4863ffb96681d1a398",
  },
  {
    name: "ExactOutput",
    swapType: 3,
    encoded: coder.encode(
      [
        "tuple(bytes path,tuple(uint256 ownerX,uint256 ownerY) recipient,uint256 amountOut,uint256 amountInMaximum,uint256 salt)",
      ],
      [[PATH_OUT, RECIPIENT, 1000n, 5000n, SALT]],
    ),
    base: "0x0b450e1fd1e79210eaa5e52954dda6b15fd8bf4d3ed96e7df2ca036078d73ffd",
    bound: "0x074dd110547b2d8b906b7a7d7baeb06a01450f41a0cc8778555ec179daa7e16d",
  },
];

// Deploy inside a fixture so the linked Poseidon2 survives another test's snapshot restore in parallel runs.
async function deployHarness() {
  const poseidon2 = await (
    await ethers.getContractFactory("Poseidon2")
  ).deploy();
  const dummy = "0x0000000000000000000000000000000000000001";
  const harness = await (
    await ethers.getContractFactory("UniswapIntentHarness", {
      libraries: { Poseidon2: await poseidon2.getAddress() },
    })
  ).deploy(dummy, dummy);
  return { harness };
}

describe("UniswapAdaptor intent-hash parity (Solidity golden)", function () {
  for (const c of CASES) {
    it(`${c.name} _calculateIntentHash matches the committed golden`, async function () {
      const { harness } = await loadFixture(deployHarness);
      expect(await harness.calcIntentHash(c.swapType, c.encoded)).to.equal(
        c.base,
      );
    });

    it(`${c.name} deadline-bound intent hash matches the committed golden`, async function () {
      const { harness } = await loadFixture(deployHarness);
      expect(
        await harness.calcBoundIntentHash(c.swapType, c.encoded, DEADLINE),
      ).to.equal(c.bound);
    });
  }

  it("every swap type produces a distinct hash", async function () {
    const { harness } = await loadFixture(deployHarness);

    const bases: string[] = [];
    const bounds: string[] = [];
    for (const c of CASES) {
      bases.push(await harness.calcIntentHash(c.swapType, c.encoded));
      bounds.push(
        await harness.calcBoundIntentHash(c.swapType, c.encoded, DEADLINE),
      );
    }

    expect(new Set(bases).size).to.equal(CASES.length);
    expect(new Set(bounds).size).to.equal(CASES.length);
  });
});
