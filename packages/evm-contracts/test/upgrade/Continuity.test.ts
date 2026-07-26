import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import { toBeHex, ZeroHash } from "ethers";
import {
  deployDarkPoolFixture,
  makeDeposit,
  mintSelfNote,
  evenYEphemeral,
  newSeededTree,
  COMPLIANCE_PK,
} from "../helpers/fixtures";
import { Fr, toFr, addressToFr, packParents } from "@hisoka/wallets";
import { proveWithdraw, WithdrawInputs, NoteInput } from "@hisoka/prover";
import type { DarkPool, DarkPoolV2Mock__factory } from "../../typechain-types";

const UUPS_OPTS = {
  kind: "uups" as const,
  unsafeAllow: ["external-library-linking" as const],
};

interface SpendArgs {
  oldNote: NoteInput;
  spendScalar: Fr;
  index: number;
  path: Fr[];
  amount: bigint;
  changeValue: bigint;
  changeEphSeed: bigint;
  recipient: string;
  assetFr: Fr;
}

async function buildWithdraw(args: SpendArgs) {
  const changeEph = evenYEphemeral(args.changeEphSeed);
  const change = await mintSelfNote(
    changeEph,
    args.changeValue,
    args.spendScalar,
    args.assetFr,
    packParents([{ leafIndex: args.index }, { leafIndex: 0 }]),
  );
  const inputs: WithdrawInputs = {
    withdrawValue: toFr(args.amount),
    recipient: addressToFr(args.recipient),
    intentHash: toFr(0n),
    compliancePk: COMPLIANCE_PK,
    oldNote: args.oldNote,
    spendScalar: args.spendScalar,
    oldNoteIndex: args.index,
    oldNotePath: args.path,
    changeNote: change.note,
    changeEph,
  };
  const proof = await proveWithdraw(inputs);
  return { proof, changeCommitment: change.commitment };
}

describe("Anonymity-set continuity across upgrade (CI-6, anti-Nomad)", function () {
  it("preserves tree/nullifier state byte-identical and keeps pre-upgrade notes spendable", async function () {
    const ctx = await deployDarkPoolFixture();
    const { darkPool, token, alice } = ctx;
    const assetFr = addressToFr(await token.getAddress());

    const depA = await makeDeposit(darkPool, token, alice, 100n);
    const depB = await makeDeposit(darkPool, token, alice, 50n);

    const tree = await newSeededTree();
    await tree.insert(depA.commitment);
    await tree.insert(depB.commitment);

    const wA = await buildWithdraw({
      oldNote: depA.built.note,
      spendScalar: depA.spendScalar,
      index: 1,
      path: tree.getMerklePath(1),
      amount: 40n,
      changeValue: 60n,
      changeEphSeed: 4242n,
      recipient: alice.address,
      assetFr,
    });
    await darkPool
      .connect(alice)
      .withdraw(wA.proof.proof, wA.proof.publicInputs);
    await tree.insert(wA.changeCommitment);

    const realNullifier = wA.proof.publicInputs[5];

    const rootBefore = await darkPool.getCurrentRoot();
    const nextIndexBefore = await darkPool.getNextLeafIndex();
    expect(await darkPool.isNullifierSpent(realNullifier)).to.equal(true);
    expect(await darkPool.isKnownRoot(rootBefore)).to.equal(true);
    expect(nextIndexBefore).to.equal(4n);

    const proxyAddr = await darkPool.getAddress();

    // validateUpgrade cannot see a MerkleTreeLib.Tree reshape, so the live Tree members are asserted at their expected sub-slots off TREE_LOCATION.
    const TREE_LOCATION =
      "0xbdd00c81e71bd165e3ff2099ca204334ffd58a8d7225a33b4761542b7a86e200";
    const treeSlot = async (offset: bigint): Promise<bigint> =>
      BigInt(
        await ethers.provider.getStorage(
          proxyAddr,
          toBeHex(BigInt(TREE_LOCATION) + offset, 32),
        ),
      );
    expect(await treeSlot(0n)).to.equal(32n); // TREE_DEPTH
    expect(await treeSlot(2n)).to.equal(nextIndexBefore); // nextLeafIndex
    expect(await treeSlot(3n)).to.equal(BigInt(rootBefore)); // latestRoot

    const pos = await (await ethers.getContractFactory("Poseidon2")).deploy();
    await pos.waitForDeployment();
    const V2Factory = (await ethers.getContractFactory("DarkPoolV2Mock", {
      libraries: { Poseidon2: await pos.getAddress() },
    })) as unknown as DarkPoolV2Mock__factory;

    const upgraded = (await upgrades.upgradeProxy(
      proxyAddr,
      V2Factory,
      UUPS_OPTS,
    )) as unknown as DarkPool & { version(): Promise<bigint> };
    await upgraded.waitForDeployment();

    expect(await upgraded.version()).to.equal(2n);

    expect(await upgraded.getCurrentRoot()).to.equal(rootBefore);
    expect(await upgraded.getNextLeafIndex()).to.equal(nextIndexBefore);
    expect(await upgraded.isNullifierSpent(realNullifier)).to.equal(true);
    expect(await treeSlot(3n)).to.equal(BigInt(rootBefore));

    // Anti-Nomad zero-sentinel guard: an empty root and an unseen nullifier are never trusted.
    expect(await upgraded.isKnownRoot(ZeroHash)).to.equal(false);
    const unseenNullifier = ethers.keccak256(ethers.toUtf8Bytes("never-spent"));
    expect(await upgraded.isNullifierSpent(unseenNullifier)).to.equal(false);

    const wB = await buildWithdraw({
      oldNote: depB.built.note,
      spendScalar: depB.spendScalar,
      index: 2,
      path: tree.getMerklePath(2),
      amount: 50n,
      changeValue: 0n,
      changeEphSeed: 7777n,
      recipient: alice.address,
      assetFr,
    });
    await upgraded
      .connect(alice)
      .withdraw(wB.proof.proof, wB.proof.publicInputs);
    expect(await upgraded.isNullifierSpent(wB.proof.publicInputs[5])).to.equal(
      true,
    );
    expect(await upgraded.getNextLeafIndex()).to.equal(5n);
  });
});
