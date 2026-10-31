import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { newSeededTree } from "../helpers/fixtures";
import {
  b32,
  deployController,
  deployGoldenSettlementFixture,
} from "../helpers/settlementFixtures";
import { revertData } from "../helpers/revertData";
import { Fr } from "@hisoka/wallets";
import {
  KAGE_PROOF,
  KAGE_PUBLIC_INPUTS,
  KAGE_LEAF_A,
  KAGE_LEAF_B,
  KAGE_GOLDEN_ROOT,
} from "./kageGolden";

// Layout of the golden vector: [0,1] compliance; [2] timestamp; [3,4] nullifiers; [5] root; outputs at 6/15/24/33.
const OUTPUT_LEAF_INDICES = [6, 15, 24, 33];

// Error selectors of the generated UltraHonk verifier (`*_SELECTOR` constants in KageVerifier.sol).
const HONK_VALUE_GE_LIMB_MAX = "0xeb73e0bd";
const HONK_SUMCHECK_FAILED = "0x9fc3a218";

describe("settle (real recursive Kage proof through a registered module)", function () {
  it("genesis + seed reach the golden root", async function () {
    const { darkPool } = await loadFixture(deployGoldenSettlementFixture);
    expect(await darkPool.getCurrentRoot()).to.equal(KAGE_GOLDEN_ROOT);
    expect(await darkPool.getNextLeafIndex()).to.equal(3n);
  });

  it("settles the golden swap: 2 nullifiers spent, 4 notes at the pinned indices, rebuilt-root parity, ModuleSettled, no value moved", async function () {
    const { darkPool, controller, token } = await loadFixture(
      deployGoldenSettlementFixture,
    );
    const pi = KAGE_PUBLIC_INPUTS;
    const poolAddr = await darkPool.getAddress();
    const controllerAddr = await controller.getAddress();
    const poolTokenBefore = await token.balanceOf(poolAddr);

    const receipt = await (await controller.settle(KAGE_PROOF, pi)).wait();
    console.log(
      `      settle gasUsed (golden Kage proof, 3-leaf tree): ${receipt!.gasUsed}`,
    );

    expect(await darkPool.isNullifierSpent(pi[3])).to.equal(true);
    expect(await darkPool.isNullifierSpent(pi[4])).to.equal(true);
    expect(await darkPool.getNextLeafIndex()).to.equal(7n);

    const parsed = receipt!.logs
      .filter((l) => l.address === poolAddr)
      .map((l) => darkPool.interface.parseLog(l));
    const outLeaves = OUTPUT_LEAF_INDICES.map((i) => pi[i]);
    const newNotes = parsed.filter((p) => p?.name === "NewNote");
    expect(newNotes.length).to.equal(4);
    newNotes.forEach((log, j) => {
      const base = OUTPUT_LEAF_INDICES[j];
      expect(log!.args.leafIndex).to.equal(3n + BigInt(j));
      expect(log!.args.commitment).to.equal(pi[base]);
      expect(log!.args.ephemeralPK_x).to.equal(BigInt(pi[base + 1]));
      expect([...log!.args.packedCiphertext]).to.deep.equal(
        pi.slice(base + 2, base + 9),
      );
    });

    const spent = parsed.filter((p) => p?.name === "NullifierSpent");
    expect(spent.map((p) => p!.args.nullifierHash)).to.deep.equal([
      pi[3],
      pi[4],
    ]);

    const settled = parsed.filter((p) => p?.name === "ModuleSettled");
    expect(settled.length).to.equal(1);
    expect(settled[0]!.args.controller).to.equal(controllerAddr);
    expect(settled[0]!.args.firstLeafIndex).to.equal(3n);
    expect(settled[0]!.args.outputCount).to.equal(4n);
    expect(parsed[parsed.length - 1]!.name).to.equal("ModuleSettled");

    const tree = await newSeededTree();
    for (const h of [KAGE_LEAF_A, KAGE_LEAF_B, ...outLeaves]) {
      await tree.insert(new Fr(BigInt(h)));
    }
    expect(await darkPool.getCurrentRoot()).to.equal(tree.getRoot().toString());

    expect(await token.balanceOf(poolAddr)).to.equal(poolTokenBefore);
    expect(await ethers.provider.getBalance(poolAddr)).to.equal(0n);
    expect(await ethers.provider.getBalance(controllerAddr)).to.equal(0n);
  });

  it("rejects a replay: the spent nullifiers block resubmitting the same proof", async function () {
    const { darkPool, controller } = await loadFixture(
      deployGoldenSettlementFixture,
    );
    await controller.settle(KAGE_PROOF, KAGE_PUBLIC_INPUTS);
    await expect(
      controller.settle(KAGE_PROOF, KAGE_PUBLIC_INPUTS),
    ).to.be.revertedWithCustomError(darkPool, "NullifierAlreadySpent");
  });

  it("rejects a corrupted proof, a mutated output leaf and a mutated root, each with its exact error and no effect", async function () {
    const { darkPool, controller } = await loadFixture(
      deployGoldenSettlementFixture,
    );
    const pi = KAGE_PUBLIC_INPUTS;
    const rootBefore = await darkPool.getCurrentRoot();

    const expectUnchanged = async () => {
      expect(await darkPool.isNullifierSpent(pi[3])).to.equal(false);
      expect(await darkPool.isNullifierSpent(pi[4])).to.equal(false);
      expect(await darkPool.getNextLeafIndex()).to.equal(3n);
      expect(await darkPool.getCurrentRoot()).to.equal(rootBefore);
    };

    // The generated verifier reverts with raw selectors it does not declare in its ABI, so the data is matched
    // as bytes. DarkPool forwards it unchanged; a DarkPool guard firing first would carry a different selector.
    const corrupt = ethers.getBytesCopy(KAGE_PROOF);
    corrupt[32] ^= 0x01;
    expect(
      await revertData(controller.settle(ethers.hexlify(corrupt), pi)),
    ).to.equal(HONK_VALUE_GE_LIMB_MAX);
    await expectUnchanged();

    const mutO = [...pi];
    mutO[6] = b32(BigInt(pi[6]) + 1n);
    expect(await revertData(controller.settle(KAGE_PROOF, mutO))).to.equal(
      HONK_SUMCHECK_FAILED,
    );
    await expectUnchanged();

    const mutR = [...pi];
    mutR[5] = b32(BigInt(pi[5]) + 1n);
    await expect(
      controller.settle(KAGE_PROOF, mutR),
    ).to.be.revertedWithCustomError(darkPool, "InvalidRoot");
    await expectUnchanged();
  });

  it("rejects the golden proof from an EOA and from an unregistered controller", async function () {
    const { darkPool } = await loadFixture(deployGoldenSettlementFixture);
    const [signer] = await ethers.getSigners();
    await expect(darkPool.settle(KAGE_PROOF, KAGE_PUBLIC_INPUTS))
      .to.be.revertedWithCustomError(darkPool, "UnknownModule")
      .withArgs(signer.address);
    const stranger = await deployController(darkPool);
    await expect(stranger.settle(KAGE_PROOF, KAGE_PUBLIC_INPUTS))
      .to.be.revertedWithCustomError(darkPool, "UnknownModule")
      .withArgs(await stranger.getAddress());
  });
});
