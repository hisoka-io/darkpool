import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import {
  deployDarkPoolFixture,
  makeDeposit,
  mintSelfNote,
  evenYEphemeral,
  newSeededTree,
  COMPLIANCE_PK,
} from "../helpers/fixtures";
import { toFr, addressToFr, packParents } from "@hisoka/wallets";
import { proveWithdraw, WithdrawInputs } from "@hisoka/prover";
import { hashUniswapIntent, SwapType } from "@hisoka/adaptors";

// Runs the UniswapAdaptor swap-withdraw money path in CI (test:fast) against a deterministic mock router, so a
// regression in the intent binding / asset checks / return path ships red instead of green (the real-router
// suite is fork-only and never runs in CI). All contracts deploy inside the fixture so the linked Poseidon2 is
// captured in the loadFixture snapshot.
async function deploySwapFixture() {
  const base = await deployDarkPoolFixture();
  const tokenOut = await (
    await ethers.getContractFactory("MockERC20")
  ).deploy("Out", "OUT", 18);
  const router = await (
    await ethers.getContractFactory("MockSwapRouter")
  ).deploy();
  await tokenOut.mint(await router.getAddress(), ethers.parseEther("1000"));
  const poseidon2 = await (
    await ethers.getContractFactory("Poseidon2")
  ).deploy();
  const adaptor = await (
    await ethers.getContractFactory("UniswapAdaptor", {
      libraries: { Poseidon2: await poseidon2.getAddress() },
    })
  ).deploy(await base.darkPool.getAddress(), await router.getAddress());
  return { ...base, tokenOut, adaptor };
}

describe("UniswapAdaptor swap-withdraw (mock router, no fork)", function () {
  it("ExactInputSingle: withdraw -> swap -> public memo of the output", async function () {
    const ctx = await loadFixture(deploySwapFixture);
    const { darkPool, token, alice, tokenOut, adaptor } = ctx;
    const darkPoolAddr = await darkPool.getAddress();
    const adaptorAddr = await adaptor.getAddress();

    const assetIn = await token.getAddress();
    const assetOut = await tokenOut.getAddress();
    const amountIn = 40n;
    const ownerX = 111n;
    const ownerY = 222n;
    const fee = 3000;
    const salt = 7n;

    const intentHash = await hashUniswapIntent({
      type: SwapType.ExactInputSingle,
      assetIn,
      assetOut,
      fee,
      recipient: { ownerX, ownerY },
      amountOutMin: 0n,
      salt,
    });

    const dep = await makeDeposit(darkPool, token, alice, 100n);
    const tree = await newSeededTree();
    await tree.insert(dep.commitment);
    const assetFr = addressToFr(assetIn);
    const changeEph = evenYEphemeral(4242n);
    const change = await mintSelfNote(
      changeEph,
      100n - amountIn,
      dep.spendScalar,
      assetFr,
      packParents([{ leafIndex: 1 }, { leafIndex: 0 }]),
    );
    const inputs: WithdrawInputs = {
      withdrawValue: toFr(amountIn),
      recipient: addressToFr(adaptorAddr),
      intentHash,
      compliancePk: COMPLIANCE_PK,
      oldNote: dep.built.note,
      spendScalar: dep.spendScalar,
      oldNoteIndex: 1,
      oldNotePath: tree.getMerklePath(1),
      changeNote: change.note,
      changeEph,
    };
    const proof = await proveWithdraw(inputs);

    const encoded = ethers.AbiCoder.defaultAbiCoder().encode(
      [
        "tuple(address assetIn,address assetOut,uint24 fee,tuple(uint256 ownerX,uint256 ownerY) recipient,uint256 amountOutMin,uint256 salt)",
      ],
      [[assetIn, assetOut, fee, [ownerX, ownerY], 0n, salt]],
    );

    const before = await tokenOut.balanceOf(darkPoolAddr);
    // SwapType.ExactInputSingle == 0
    await expect(
      adaptor.executeSwap(proof.proof, proof.publicInputs, 0, encoded),
    ).to.emit(darkPool, "NewPublicMemo");

    // 1:1 mock rate: amountOut == amountIn, re-shielded into the pool as a public memo.
    expect((await tokenOut.balanceOf(darkPoolAddr)) - before).to.equal(
      amountIn,
    );
    expect(await token.balanceOf(adaptorAddr)).to.equal(0n);
    expect(await tokenOut.balanceOf(adaptorAddr)).to.equal(0n);
  });
});
