import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { DarkPool } from "../../typechain-types";
import { newSeededTree, COMPLIANCE_PK } from "../helpers/fixtures";
import { Fr } from "@hisoka/wallets";
import {
  KAGE_PROOF,
  KAGE_PUBLIC_INPUTS,
  KAGE_LEAF_A,
  KAGE_LEAF_B,
  KAGE_GOLDEN_ROOT,
} from "./kageGolden";

// Real-proof-through-kageSwap e2e (CI-runnable; no proving at test time). The committed golden native-bb
// recursive proof (kageGolden.ts) flows through the ACTUAL kageSwap entrypoint into the REAL KageVerifier, and
// we assert the full settlement effects the way RealProofE2E does for the 10 base circuits: both nullifiers
// spent, 4 self-notes inserted, rebuilt-LeanIMT root parity (each output leaf lands at the pinned index), 4
// NewNote events, no ERC20 movement.
//
// The golden was proven against [genesis(31337), leaf_A@1, leaf_B@2], so we seed those two input leaves to make
// its root a KNOWN root. Seeding uses a StubVerifier at the deposit slot: leaf_A/leaf_B carry synthetic asset
// ids (0x1234.. / 0xabcd..) that are not real ERC20s, so a real deposit cannot mint them; the stub decouples
// the seeded leaf from the pulled seed token, while the KageVerifier under test at CIRCUIT_KAGE stays real.
const CIRCUIT_KAGE = 10;
const b32 = (v: bigint): string => ethers.zeroPadValue(ethers.toBeHex(v), 32);

async function deployAndSeedFixture(): Promise<{
  darkPool: DarkPool;
  seedToken: string;
}> {
  const [admin] = await ethers.getSigners();
  const pos = await (await ethers.getContractFactory("Poseidon2")).deploy();
  const stub = await (await ethers.getContractFactory("StubVerifier")).deploy();
  const stubAddr = await stub.getAddress();

  const zkLib = await (
    await ethers.getContractFactory(
      "contracts/verifiers/KageVerifier.sol:ZKTranscriptLib",
    )
  ).deploy();
  const kageVerifier = await (
    await ethers.getContractFactory(
      "contracts/verifiers/KageVerifier.sol:HonkVerifier",
      {
        libraries: {
          "contracts/verifiers/KageVerifier.sol:ZKTranscriptLib":
            await zkLib.getAddress(),
        },
      },
    )
  ).deploy();

  // Real KageVerifier at CIRCUIT_KAGE (index 10); stubs everywhere else (the swap path never calls them, and
  // the deposit stub is only used to seed the two input leaves).
  const verifiers = [
    ...Array<string>(CIRCUIT_KAGE).fill(stubAddr),
    await kageVerifier.getAddress(),
  ];

  const Factory = await ethers.getContractFactory("DarkPool", {
    libraries: { Poseidon2: await pos.getAddress() },
  });
  const darkPool = (await upgrades.deployProxy(
    Factory,
    [
      [
        ...verifiers,
        COMPLIANCE_PK[0],
        COMPLIANCE_PK[1],
        0,
        admin.address,
        admin.address,
        admin.address,
      ],
    ],
    {
      kind: "uups",
      initializer: "initialize",
      unsafeAllow: ["external-library-linking"],
    },
  )) as unknown as DarkPool;

  const seedTokenC = await (
    await ethers.getContractFactory("MockERC20")
  ).deploy("Seed", "SEED", 18);
  const seedToken = await seedTokenC.getAddress();
  await seedTokenC.mint(admin.address, 100n);
  await seedTokenC.approve(await darkPool.getAddress(), 100n);

  // Seed leaf_A@1 then leaf_B@2 via stub deposits (value 1 of the seed token each; the leaf comes from PI[2]).
  const stubDeposit = async (leafHex: string): Promise<void> => {
    const pi = new Array<string>(13).fill(b32(0n));
    pi[0] = b32(COMPLIANCE_PK[0]);
    pi[1] = b32(COMPLIANCE_PK[1]);
    pi[2] = leafHex; // inserted leaf
    pi[4] = b32(1n); // value (> 0)
    pi[5] = ethers.zeroPadValue(seedToken, 32); // pulled asset
    await darkPool.deposit("0x", pi);
  };
  await stubDeposit(KAGE_LEAF_A);
  await stubDeposit(KAGE_LEAF_B);

  return { darkPool, seedToken };
}

describe("kageSwap (real recursive proof through the entrypoint)", function () {
  it("genesis + seed reach the golden root", async function () {
    const { darkPool } = await loadFixture(deployAndSeedFixture);
    // Genesis was at index 0; the two seeded leaves make getCurrentRoot() the golden root the proof was over.
    expect(await darkPool.getCurrentRoot()).to.equal(KAGE_GOLDEN_ROOT);
    expect(await darkPool.getNextLeafIndex()).to.equal(3n); // genesis + leaf_A + leaf_B
  });

  it("settles the golden swap: 2 nullifiers spent, 4 self-notes inserted at the pinned indices, rebuilt-root parity, 4 NewNote events, no ERC20 movement", async function () {
    const { darkPool, seedToken } = await loadFixture(deployAndSeedFixture);
    const pi = KAGE_PUBLIC_INPUTS;
    const token = await ethers.getContractAt("MockERC20", seedToken);
    const poolAddr = await darkPool.getAddress();

    const before = await darkPool.getNextLeafIndex();
    const poolTokenBefore = await token.balanceOf(poolAddr);

    const receipt = await (await darkPool.kageSwap(KAGE_PROOF, pi)).wait();

    // Both input nullifiers spent.
    expect(await darkPool.isNullifierSpent(pi[3])).to.equal(true);
    expect(await darkPool.isNullifierSpent(pi[4])).to.equal(true);

    // Four self-notes appended: nextLeafIndex advances by exactly 4.
    expect(await darkPool.getNextLeafIndex()).to.equal(before + 4n);

    // Four NewNote events, one per output leaf, at consecutive indices carrying the layout's pinned leaves.
    const outLeaves = [pi[6], pi[15], pi[24], pi[33]];
    const newNotes = receipt!.logs
      .map((l) => {
        try {
          return darkPool.interface.parseLog(l);
        } catch {
          return null;
        }
      })
      .filter((p) => p?.name === "NewNote");
    expect(newNotes.length).to.equal(4);
    newNotes.forEach((log, i) => {
      expect(log!.args[0]).to.equal(before + BigInt(i)); // leafIndex
      expect(log!.args[1]).to.equal(outLeaves[i]); // commitment
    });

    // Drain-critical: rebuild the LeanIMT (genesis, leaf_A, leaf_B, then the 4 outputs in layout order) and
    // assert the contract root matches -- proves each real leaf landed at the index the public-input layout pins.
    const tree = await newSeededTree();
    for (const h of [KAGE_LEAF_A, KAGE_LEAF_B, ...outLeaves]) {
      await tree.insert(new Fr(BigInt(h)));
    }
    expect(await darkPool.getCurrentRoot()).to.equal(tree.getRoot().toString());

    // A swap moves no ERC20: it is purely internal (four self-notes, no token param).
    expect(await token.balanceOf(poolAddr)).to.equal(poolTokenBefore);
    expect(await ethers.provider.getBalance(poolAddr)).to.equal(0n);
  });

  it("rejects a replay: the spent nullifiers block resubmitting the same proof", async function () {
    const { darkPool } = await loadFixture(deployAndSeedFixture);
    await darkPool.kageSwap(KAGE_PROOF, KAGE_PUBLIC_INPUTS);
    await expect(
      darkPool.kageSwap(KAGE_PROOF, KAGE_PUBLIC_INPUTS),
    ).to.be.revertedWithCustomError(darkPool, "NullifierAlreadySpent");
  });

  it("rejects a corrupted proof and mutated public inputs through the entrypoint", async function () {
    const { darkPool } = await loadFixture(deployAndSeedFixture);
    const pi = KAGE_PUBLIC_INPUTS;

    const corrupt = ethers.getBytesCopy(KAGE_PROOF);
    corrupt[32] ^= 0x01;
    await expect(darkPool.kageSwap(ethers.hexlify(corrupt), pi)).to.be.reverted;

    // A mutated output leaf (real verifier rejects) and an unknown root (isKnownRoot precheck) both revert.
    const mutO = [...pi];
    mutO[6] = b32(BigInt(pi[6]) + 1n);
    await expect(darkPool.kageSwap(KAGE_PROOF, mutO)).to.be.reverted;

    const mutR = [...pi];
    mutR[5] = b32(BigInt(pi[5]) + 1n);
    await expect(
      darkPool.kageSwap(KAGE_PROOF, mutR),
    ).to.be.revertedWithCustomError(darkPool, "InvalidRoot");
  });
});
