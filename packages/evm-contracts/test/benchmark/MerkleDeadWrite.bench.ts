import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import type { DarkPool, MockERC20 } from "../typechain-types";
import { COMPLIANCE_PK } from "../helpers/fixtures";
import { bitLength, leafAt, deployMerkleHarness } from "../helpers/merkleTree";

// MERKLE_GAS=1 npx hardhat test test/benchmark/MerkleDeadWrite.bench.ts
// Measures the frontier walk end to end. Run once against the unconditional 32-level walk and once against the
// index==0 stop; the delta is the dead-write saving. Every action runs behind StubVerifier so the number is the
// tree, not the verifier.
const run = process.env.MERKLE_GAS ? describe : describe.skip;

/** DarkPool behind 10 StubVerifiers: isolates tree cost from proof verification. */
async function deployStubbedDarkPool() {
  const [deployer, alice] = await ethers.getSigners();

  const poseidon2 = await (
    await ethers.getContractFactory("Poseidon2")
  ).deploy();
  const stub = await (await ethers.getContractFactory("StubVerifier")).deploy();
  const stubAddr = await stub.getAddress();

  const token = (await (
    await ethers.getContractFactory("MockERC20")
  ).deploy("Mock", "MCK", 18)) as unknown as MockERC20;
  await token.mint(alice.address, ethers.parseEther("10000"));

  const DarkPoolFactory = await ethers.getContractFactory("DarkPool", {
    libraries: { Poseidon2: await poseidon2.getAddress() },
  });

  const darkPool = (await upgrades.deployProxy(
    DarkPoolFactory,
    [
      [
        ...Array<string>(10).fill(stubAddr),
        COMPLIANCE_PK[0],
        COMPLIANCE_PK[1],
        0,
        deployer.address,
        deployer.address,
        deployer.address,
      ],
    ],
    { kind: "uups", unsafeAllow: ["external-library-linking"] },
  )) as unknown as DarkPool;
  await darkPool.waitForDeployment();

  const initGas = (await darkPool.deploymentTransaction()!.wait())!.gasUsed;
  await token
    .connect(alice)
    .approve(await darkPool.getAddress(), ethers.MaxUint256);

  return { darkPool, token, alice, initGas };
}

/** deposit = 1 insert. Layout: [0,1] compliance; [2] leaf; [3,4] eph; [5] value; [6] asset; [7..13] ct. */
function depositInputs(leaf: string, asset: string): string[] {
  const inputs = Array<string>(14).fill(ethers.ZeroHash);
  inputs[0] = ethers.zeroPadValue(ethers.toBeHex(COMPLIANCE_PK[0]), 32);
  inputs[1] = ethers.zeroPadValue(ethers.toBeHex(COMPLIANCE_PK[1]), 32);
  inputs[2] = leaf;
  inputs[5] = ethers.zeroPadValue(ethers.toBeHex(1n), 32);
  inputs[6] = ethers.zeroPadValue(asset, 32);
  return inputs;
}

/** split = 2 inserts. Layout: [0,1] compliance; [2] nullifier; [3] root; [4] out1; [14] out2. */
function splitInputs(
  nullifier: string,
  root: string,
  out1: string,
  out2: string,
): string[] {
  const inputs = Array<string>(24).fill(ethers.ZeroHash);
  inputs[0] = ethers.zeroPadValue(ethers.toBeHex(COMPLIANCE_PK[0]), 32);
  inputs[1] = ethers.zeroPadValue(ethers.toBeHex(COMPLIANCE_PK[1]), 32);
  inputs[2] = nullifier;
  inputs[3] = root;
  inputs[4] = out1;
  inputs[14] = out2;
  return inputs;
}

const rows: string[] = [];
function report(label: string, gas: bigint) {
  rows.push(`| ${label.padEnd(42)} | ${gas.toString().padStart(10)} |`);
}

run("MerkleTreeLib: dead-write gas", function () {
  this.timeout(1_800_000);

  after(function () {
    console.log(
      `\n## Frontier walk gas\n| case                                       |    gasUsed |\n` +
        `|--------------------------------------------|------------|\n${rows.join("\n")}\n`,
    );
  });

  it("library: per-insert gas at depth 32 (leafIndex 0..40)", async function () {
    const h = await deployMerkleHarness("MerkleTreeLibHarness", 32);
    const perInsert: bigint[] = [];
    for (let i = 0; i < 41; i++) {
      const rc = await (await h.insert(leafAt(i + 1))).wait();
      perInsert.push(rc!.gasUsed);
    }
    report("lib genesis insert (leafIndex 0)", perInsert[0]);
    report("lib insert leafIndex 1", perInsert[1]);
    report("lib insert leafIndex 2", perInsert[2]);
    report("lib insert leafIndex 3", perInsert[3]);
    report("lib insert leafIndex 15", perInsert[15]);
    report("lib insert leafIndex 16", perInsert[16]);
    report("lib insert leafIndex 40", perInsert[40]);
    console.log(
      `\nper-insert (depth 32), leafIndex -> gas:\n` +
        perInsert
          .map(
            (g, i) =>
              `  ${String(i).padStart(3)} (bitLen ${String(bitLength(i)).padStart(2)}): ${g}`,
          )
          .join("\n"),
    );
  });

  it("reference sanity: the full walk pays the dead writes the index==0 stop skips", async function () {
    // The mature-tree rows below compare two DIFFERENT contracts, so the reference carries a small fixed
    // overhead the shipped library does not (virtual dispatch through the harness base, inlined _saveRoot). It
    // is a stand-in for the walk, not a gas-exact replica, so this asserts the ORDER of magnitude that matters:
    // on a fresh tree the full walk must pay for all 32 cold frontier slots while the stop pays for one.
    const full = await deployMerkleHarness("FullWalkMerkleTreeHarness", 32);
    const stop = await deployMerkleHarness("MerkleTreeLibHarness", 32);

    const fg = (await (await full.insert(leafAt(1))).wait())!.gasUsed;
    const sg = (await (await stop.insert(leafAt(1))).wait())!.gasUsed;
    report("full-walk genesis insert", fg);
    report("index==0 stop genesis insert", sg);

    // 31 dead cold writes at 22,100 = 685,100; anything near that proves the skipped writes were real.
    expect(fg - sg).to.be.greaterThan(600_000n);
  });

  it("library: mature-tree inserts (warped storage shape)", async function () {
    // Each variant is warped to the frontier shape its OWN history would leave: the index==0 stop has only ever
    // touched levels 0..bitLength(leafIndex-1), the full walk has touched all 32. Only that zero/non-zero
    // pattern drives SSTORE pricing, so the measured gas is what a real tree of this size would pay.
    // leafIndex exactly 2^k is the pessimistic case: it first-touches a brand new level and pays a cold
    // 0 -> non-zero write there (22,100) where the full walk pays a warm rewrite (5,000).
    const cases: [string, number][] = [
      ["2^20 (first-touch of level 21)", 2 ** 20],
      ["2^20 + 12345 (typical)", 2 ** 20 + 12345],
      ["2^20 - 1 (typical)", 2 ** 20 - 1],
      ["2^24 + 999 (typical)", 2 ** 24 + 999],
    ];

    for (const [label, L] of cases) {
      const patched = await deployMerkleHarness("MerkleTreeLibHarness", 32);
      await patched.warpTo(L, bitLength(L - 1) + 1);
      const pg = (await (await patched.insert(leafAt(7777))).wait())!.gasUsed;

      const full = await deployMerkleHarness("FullWalkMerkleTreeHarness", 32);
      await full.warpTo(L, 32);
      const fg = (await (await full.insert(leafAt(7777))).wait())!.gasUsed;

      report(`lib insert @ ${label} [full walk]`, fg);
      report(`lib insert @ ${label} [index==0 stop]`, pg);
      report(`lib insert @ ${label} SAVING`, fg - pg);
    }
  });

  it("DarkPool: initialize (genesis insert), deposit, split - empty and pre-filled", async function () {
    const { darkPool, token, alice, initGas } = await deployStubbedDarkPool();
    const asset = await token.getAddress();
    report("DarkPool proxy deploy + initialize", initGas);

    // Empty tree: genesis at leafIndex 0, so this deposit lands at leafIndex 1.
    const dep1 = await (
      await darkPool
        .connect(alice)
        .deposit("0x", depositInputs(leafAt(1_000_001), asset))
    ).wait();
    report("deposit @ empty tree (leafIndex 1)", dep1!.gasUsed);

    const root1 = await darkPool.getCurrentRoot();
    const split1 = await (
      await darkPool
        .connect(alice)
        .split(
          "0x",
          splitInputs(
            leafAt(2_000_001),
            root1,
            leafAt(1_000_002),
            leafAt(1_000_003),
          ),
        )
    ).wait();
    report("split @ empty tree (leafIndex 2,3)", split1!.gasUsed);

    // Pre-fill to a mid-depth tree, then re-measure at a deeper leafIndex.
    const PREFILL = 500;
    for (let i = 0; i < PREFILL; i++) {
      await darkPool
        .connect(alice)
        .deposit("0x", depositInputs(leafAt(3_000_000 + i), asset));
    }
    const nextIdx = Number(await darkPool.getNextLeafIndex());

    const dep2 = await (
      await darkPool
        .connect(alice)
        .deposit("0x", depositInputs(leafAt(4_000_001), asset))
    ).wait();
    report(
      `deposit @ pre-filled (leafIndex ${nextIdx}, bitLen ${bitLength(nextIdx)})`,
      dep2!.gasUsed,
    );

    const root2 = await darkPool.getCurrentRoot();
    const nextIdx2 = Number(await darkPool.getNextLeafIndex());
    const split2 = await (
      await darkPool
        .connect(alice)
        .split(
          "0x",
          splitInputs(
            leafAt(2_000_002),
            root2,
            leafAt(4_000_002),
            leafAt(4_000_003),
          ),
        )
    ).wait();
    report(
      `split @ pre-filled (leafIndex ${nextIdx2},${nextIdx2 + 1})`,
      split2!.gasUsed,
    );
  });
});
