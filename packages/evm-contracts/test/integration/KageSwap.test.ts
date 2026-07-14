import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import { DarkPool } from "../../typechain-types";

// Effects + guards for the kageSwap entrypoint. A StubVerifier stands in for the recursive Honk verifier (whose
// soundness is proven separately by the native-bb VK-pin gate), so this suite exercises exactly what the contract
// owns and the circuit deliberately cannot: the isKnownRoot / compliance / timestamp-FLOOR guards, the
// 2-nullifier / 4-insert / 4-event additive effects, and that a swap moves no ERC20.

// Canonical BabyJubJub Base8 (on-curve; initialize accepts it), used here as the registered compliance key.
const BASE8_X =
  5299619240641551281634865583518297030282874472190772894086521144482721001553n;
const BASE8_Y =
  16950150798460657717958625567821834550301663161624707787222815936182638968203n;
const TOLERANCE = 5n * 60n; // PROOF_TIMESTAMP_TOLERANCE

const b32 = (n: bigint): string => ethers.zeroPadValue(ethers.toBeHex(n), 32);

interface Overrides {
  complianceX?: bigint;
  complianceY?: bigint;
  timestamp?: bigint;
  root?: string;
  nullifierA?: bigint;
  nullifierB?: bigint;
}

async function deployStubbedDarkPool(): Promise<{
  darkPool: DarkPool;
  admin: { address: string };
}> {
  const [admin] = await ethers.getSigners();
  const pos = await (await ethers.getContractFactory("Poseidon2")).deploy();
  await pos.waitForDeployment();
  const stub = await (await ethers.getContractFactory("StubVerifier")).deploy();
  await stub.waitForDeployment();
  const stubAddr = await stub.getAddress();
  const verifiers = Array.from({ length: 11 }, () => stubAddr);
  const Factory = await ethers.getContractFactory("DarkPool", {
    libraries: { Poseidon2: await pos.getAddress() },
  });
  const darkPool = (await upgrades.deployProxy(
    Factory,
    [
      [
        ...verifiers,
        BASE8_X,
        BASE8_Y,
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
  await darkPool.waitForDeployment();
  return { darkPool, admin };
}

// A valid-shaped 42-field kageSwap public-input vector: [0,1] compliance; [2] timestamp; [3,4] nullifiers;
// [5] root; then four output notes at leaf/eph_x offsets 6/7, 15/16, 24/25, 33/34. Defaults pass every guard.
async function kagePublicInputs(
  darkPool: DarkPool,
  over: Overrides = {},
): Promise<string[]> {
  const now = BigInt((await ethers.provider.getBlock("latest"))!.timestamp);
  const pi = new Array<string>(42).fill(b32(0n));
  pi[0] = b32(over.complianceX ?? BASE8_X);
  pi[1] = b32(over.complianceY ?? BASE8_Y);
  pi[2] = b32(over.timestamp ?? now);
  pi[3] = b32(over.nullifierA ?? 0x1111n);
  pi[4] = b32(over.nullifierB ?? 0x2222n);
  pi[5] = over.root ?? (await darkPool.getCurrentRoot());
  const leaves = [6, 15, 24, 33];
  leaves.forEach((idx, i) => {
    pi[idx] = b32(0xa10n + BigInt(i)); // distinct nonzero leaves
    pi[idx + 1] = b32(0xe10n + BigInt(i)); // eph_pub.x
  });
  return pi;
}

describe("kageSwap (effects + guards)", function () {
  let darkPool: DarkPool;

  beforeEach(async function () {
    ({ darkPool } = await deployStubbedDarkPool());
  });

  it("settles a swap: 2 nullifiers spent, 4 self-notes inserted, 4 NewNote events, no ERC20 movement", async function () {
    const pi = await kagePublicInputs(darkPool);
    const before = await darkPool.getNextLeafIndex();

    const receipt = await (await darkPool.kageSwap("0x", pi)).wait();

    expect(await darkPool.getNextLeafIndex()).to.equal(before + 4n);
    expect(await darkPool.isNullifierSpent(pi[3])).to.equal(true);
    expect(await darkPool.isNullifierSpent(pi[4])).to.equal(true);

    const newNotes = receipt!.logs.filter((l) => {
      try {
        return darkPool.interface.parseLog(l)?.name === "NewNote";
      } catch {
        return false;
      }
    });
    expect(newNotes.length).to.equal(4);
    // No ERC20 path exists in kageSwap (no token param, no transfer): a swap is purely internal.
    expect(
      await ethers.provider.getBalance(await darkPool.getAddress()),
    ).to.equal(0n);
  });

  it("reverts InvalidRoot for a stale/unknown root", async function () {
    const pi = await kagePublicInputs(darkPool, { root: b32(0xdeadn) });
    await expect(darkPool.kageSwap("0x", pi)).to.be.revertedWithCustomError(
      darkPool,
      "InvalidRoot",
    );
  });

  it("reverts ComplianceKeyStale for a wrong compliance key", async function () {
    const pi = await kagePublicInputs(darkPool, {
      complianceX: BASE8_X + 1n,
    });
    await expect(darkPool.kageSwap("0x", pi)).to.be.revertedWithCustomError(
      darkPool,
      "ComplianceKeyStale",
    );
  });

  it("reverts TimestampInvalid when current_timestamp is below the floor (expired swap)", async function () {
    const now = BigInt((await ethers.provider.getBlock("latest"))!.timestamp);
    const pi = await kagePublicInputs(darkPool, {
      timestamp: now - TOLERANCE - 60n,
    });
    await expect(darkPool.kageSwap("0x", pi)).to.be.revertedWithCustomError(
      darkPool,
      "TimestampInvalid",
    );
  });

  it("accepts current_timestamp inside the floor tolerance", async function () {
    const now = BigInt((await ethers.provider.getBlock("latest"))!.timestamp);
    const pi = await kagePublicInputs(darkPool, {
      timestamp: now - TOLERANCE + 10n,
    });
    await expect(darkPool.kageSwap("0x", pi)).to.not.be.reverted;
  });

  it("reverts NullifierAlreadySpent on nullifier reuse across swaps", async function () {
    const pi1 = await kagePublicInputs(darkPool, { nullifierA: 0x7777n });
    await darkPool.kageSwap("0x", pi1);
    // A second swap reusing nullifier_a (as its nullifier_b) must revert.
    const pi2 = await kagePublicInputs(darkPool, {
      nullifierA: 0x8888n,
      nullifierB: 0x7777n,
    });
    await expect(darkPool.kageSwap("0x", pi2)).to.be.revertedWithCustomError(
      darkPool,
      "NullifierAlreadySpent",
    );
  });
});
