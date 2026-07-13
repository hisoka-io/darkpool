import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { anyValue } from "@nomicfoundation/hardhat-chai-matchers/withArgs";
import {
  deployDarkPoolFixture,
  newSeededTree,
  evenYEphemeral,
  COMPLIANCE_PK,
} from "../helpers/fixtures";
import {
  buildMultisigNote,
  frostSign,
  depositMultisig,
  packParents,
} from "../helpers/frostMultisig";
import { toFr, addressToFr, computeNullifier } from "@hisoka/wallets";
import * as frost from "@hisoka/wallets/frost";
import { frostAccountDkg } from "@hisoka/wallets/unsafe-sim";
import { proveWithdrawMultisig } from "@hisoka/prover";
import { MockMultisigAdaptor__factory } from "../../typechain-types";

async function deployAdaptorFixture() {
  const base = await deployDarkPoolFixture();
  const adaptor = await (
    (await ethers.getContractFactory(
      "MockMultisigAdaptor",
    )) as unknown as MockMultisigAdaptor__factory
  ).deploy(await base.darkPool.getAddress());
  return { ...base, adaptor };
}

describe("Behavior: MockMultisigAdaptor (FROST withdraw -> public-transfer)", function () {
  this.timeout(600_000);

  it("pulls a real 3-of-5 withdrawMultisig to the adaptor, then re-shields via publicTransfer", async function () {
    const ctx = await loadFixture(deployAdaptorFixture);
    const { darkPool, token, alice, adaptor } = ctx;
    const adaptorAddr = await adaptor.getAddress();
    const poolAddr = await darkPool.getAddress();
    const tokenAddr = await token.getAddress();
    const assetFr = addressToFr(tokenAddr);

    const account = await frostAccountDkg(5, 3, 0x484f574c05n);
    const quorum = account.qual.slice(0, 3);

    const ms = await depositMultisig(
      darkPool,
      token,
      alice,
      100n,
      account.owner,
      assetFr,
      0x9a01n,
    );
    const tree = await newSeededTree();
    await tree.insert(ms.commitment); // index 1
    const nullifier = await computeNullifier(ms.psi, toFr(1n));

    const changeEph = evenYEphemeral(0x9a02n);
    const change = await buildMultisigNote(
      changeEph,
      60n,
      account.owner,
      assetFr,
      packParents([{ leafIndex: 1 }, { leafIndex: 0 }]),
    );

    const withdrawValue = 40n;
    const m = await frost.msgWithdraw({
      root: tree.getRoot().toBigInt(),
      nullifier: nullifier.toBigInt(),
      changeLeaf: change.commitment.toBigInt(),
      publicOut: withdrawValue,
      asset: assetFr.toBigInt(),
      recipient: addressToFr(adaptorAddr).toBigInt(),
      intentHash: 0n,
    });
    const { R, z } = await frostSign(account.gpk, account.shares, quorum, m);

    const proof = await proveWithdrawMultisig({
      withdrawValue: toFr(withdrawValue),
      recipient: addressToFr(adaptorAddr),
      intentHash: toFr(0n),
      compliancePk: COMPLIANCE_PK,
      gpk: account.gpk,
      frostR: R,
      frostZ: toFr(z),
      oldNote: ms.noteInput,
      oldNoteIndex: 1,
      oldNotePath: tree.getMerklePath(1),
      changeNote: change.noteInput,
      changeEph,
    });

    // Re-shield the withdrawn public funds as a memo claimable by the group (owner == gpk).
    const salt = 0x515n;
    const ownerX = account.gpk[0];
    const ownerY = account.gpk[1];

    const poolBefore = await token.balanceOf(poolAddr);
    const tx = await adaptor
      .connect(alice)
      .pullAndForward(proof.proof, proof.publicInputs, ownerX, ownerY, salt);
    const receipt = await tx.wait();

    await expect(tx)
      .to.emit(adaptor, "MultisigWithdrawForwarded")
      .withArgs(tokenAddr, withdrawValue, ownerX, ownerY, salt);
    await expect(tx)
      .to.emit(darkPool, "NewPublicMemo")
      .withArgs(anyValue, tokenAddr, withdrawValue, 0n, salt);
    expect(await darkPool.isNullifierSpent(proof.publicInputs[5])).to.equal(
      true,
    );

    const memoId = pluckMemoId(darkPool.interface, receipt!.logs);
    expect(await darkPool.isValidPublicMemo(memoId)).to.equal(true);
    expect(await token.balanceOf(adaptorAddr)).to.equal(0n);
    expect(await token.allowance(adaptorAddr, poolAddr)).to.equal(0n);

    // Net pool ERC20 is conserved (40 out on withdraw, 40 back on publicTransfer); the change note lands.
    expect(await token.balanceOf(poolAddr)).to.equal(poolBefore);
    await tree.insert(change.commitment); // index 2
    expect(await darkPool.getCurrentRoot()).to.equal(tree.getRoot().toString());
  });

  it("rejects a withdraw whose recipient is not the adaptor before touching the pool", async function () {
    const { adaptor, bob } = await loadFixture(deployAdaptorFixture);
    const inputs = Array(17).fill(ethers.ZeroHash);
    inputs[1] = ethers.zeroPadValue(bob.address, 32); // recipient != adaptor
    await expect(
      adaptor.pullAndForward("0x", inputs, 1n, 2n, 0n),
    ).to.be.revertedWithCustomError(adaptor, "RecipientNotAdaptor");
  });

  it("rejects a wrong-length public-input array", async function () {
    const { adaptor } = await loadFixture(deployAdaptorFixture);
    const inputs = Array(16).fill(ethers.ZeroHash);
    await expect(
      adaptor.pullAndForward("0x", inputs, 1n, 2n, 0n),
    ).to.be.revertedWithCustomError(adaptor, "InvalidInputsLength");
  });
});

/** The repay memo is emitted by the DarkPool (not the adaptor the tx targets), so decode it explicitly. */
function pluckMemoId(
  iface: {
    parseLog(l: {
      topics: readonly string[];
      data: string;
    }): { name: string; args: Record<string, unknown> } | null;
  },
  logs: readonly { topics: readonly string[]; data: string }[],
): string {
  for (const l of logs) {
    let parsed: { name: string; args: Record<string, unknown> } | null = null;
    try {
      parsed = iface.parseLog({ topics: l.topics, data: l.data });
    } catch {
      parsed = null;
    }
    if (parsed?.name === "NewPublicMemo") return parsed.args.memoId as string;
  }
  throw new Error("NewPublicMemo not found in receipt logs");
}
