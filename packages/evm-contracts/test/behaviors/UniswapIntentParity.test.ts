import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";

// TS<->Solidity parity golden for the Uniswap intent hash. The adaptor recomputes this on-chain and binds it to
// the proof's intentHash, so a silent Poseidon2 drift between hashUniswapIntent (TS) and _calculateIntentHash
// (Solidity) would strand every swap-withdraw. The same GOLDEN is asserted by the TS side in
// packages/adaptors/src/uniswap/intent.test.ts; both must agree.
const GOLDEN =
  "0x2a32d4d602c0f860a19d63fc6a69aa0ec737be4b8d99a2ff036ff2f865c2fbbf";

// Deploy inside a fixture so the linked Poseidon2 library is captured in the loadFixture snapshot and is not
// wiped by another test's snapshot restore during the parallel suite.
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
  it("ExactInputSingle _calculateIntentHash matches the committed golden", async function () {
    const { harness } = await loadFixture(deployHarness);

    const encoded = ethers.AbiCoder.defaultAbiCoder().encode(
      [
        "tuple(address assetIn,address assetOut,uint24 fee,tuple(uint256 ownerX,uint256 ownerY) recipient,uint256 amountOutMin,uint256 salt)",
      ],
      [
        [
          "0x1111111111111111111111111111111111111111",
          "0x2222222222222222222222222222222222222222",
          3000,
          [111n, 222n],
          1000n,
          42n,
        ],
      ],
    );

    // SwapType.ExactInputSingle == 0
    expect(await harness.calcIntentHash(0, encoded)).to.equal(GOLDEN);
  });
});
