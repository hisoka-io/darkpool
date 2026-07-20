import { expect } from "chai";
import { ethers } from "hardhat";
import { publicKey, Fr } from "@hisoka/wallets";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import {
  deployDarkPoolFixture,
  makeDeposit,
  mintSelfNote,
  evenYEphemeral,
  COMPLIANCE_PK,
} from "../helpers/fixtures";
import { toFr, addressToFr } from "@hisoka/wallets";
import { proveDeposit } from "@hisoka/prover";
import { MockFeeOnTransferERC20 } from "../../typechain-types";

// A real derived key: publicTransfer validates the escrow destination is on-curve, so a placeholder
// point would revert there and mask the fee-on-transfer check this test exists to exercise.
const FOT_OWNER = publicKey(new Fr(0x1234n));

describe("DarkPool Behavior: fee-on-transfer rejection", function () {
  async function deployFoT(feeBps: number): Promise<MockFeeOnTransferERC20> {
    const FoT = await ethers.getContractFactory("MockFeeOnTransferERC20");
    return (await FoT.deploy(
      "FeeToken",
      "FEE",
      18,
      feeBps,
    )) as unknown as MockFeeOnTransferERC20;
  }

  async function buildDepositProof(tokenAddr: string, amount: bigint) {
    const built = await mintSelfNote(
      evenYEphemeral(12345n),
      amount,
      toFr(456n),
      addressToFr(tokenAddr),
    );
    return proveDeposit({
      compliancePk: COMPLIANCE_PK,
      note: built.note,
      eph: built.eph,
    });
  }

  it("rejects a fee-on-transfer token at deposit", async function () {
    const { darkPool, alice } = await loadFixture(deployDarkPoolFixture);
    const fot = await deployFoT(100); // 1%
    const amount = ethers.parseEther("100");
    await fot.mint(alice.address, amount);
    const proof = await buildDepositProof(await fot.getAddress(), amount);
    await fot.connect(alice).approve(await darkPool.getAddress(), amount);

    await expect(
      darkPool.connect(alice).deposit(proof.proof, proof.publicInputs),
    ).to.be.revertedWithCustomError(darkPool, "FeeOnTransferUnsupported");
  });

  it("still accepts a standard ERC20 deposit", async function () {
    const { darkPool, token, alice } = await loadFixture(deployDarkPoolFixture);
    await makeDeposit(darkPool, token, alice, ethers.parseEther("10"));
  });

  it("rejects a fee-on-transfer token at publicTransfer", async function () {
    const { darkPool, alice } = await loadFixture(deployDarkPoolFixture);
    const fot = await deployFoT(100);
    const amount = ethers.parseEther("50");
    await fot.mint(alice.address, amount);
    await fot.connect(alice).approve(await darkPool.getAddress(), amount);

    await expect(
      darkPool
        .connect(alice)
        .publicTransfer(
          FOT_OWNER[0],
          FOT_OWNER[1],
          await fot.getAddress(),
          amount,
          0n,
          12345n,
        ),
    ).to.be.revertedWithCustomError(darkPool, "FeeOnTransferUnsupported");
  });
});
