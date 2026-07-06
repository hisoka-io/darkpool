import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import { time } from "@nomicfoundation/hardhat-network-helpers";
import { ZeroHash, id as keccakId } from "ethers";
import type {
  DarkPool,
  DarkPool__factory,
  DarkPoolV2Mock,
  DarkPoolV2Mock__factory,
  TimelockController,
} from "../../typechain-types";

// Canonical BabyJubJub Base8 subgroup point; on-curve so initialize accepts it.
const BASE8_X =
  5299619240641551281634865583518297030282874472190772894086521144482721001553n;
const BASE8_Y =
  16950150798460657717958625567821834550301663161624707787222815936182638968203n;

const TIMELOCK_DELAY = 48n * 60n * 60n;
const UUPS_OPTS = {
  kind: "uups" as const,
  unsafeAllow: ["external-library-linking" as const],
};

/** DarkPool proxy whose DEFAULT_ADMIN + UPGRADER are a real 48h OZ TimelockController (proposer/executor/
 * canceller = gov), with a guardian holding only PAUSER. Mirrors the intended production governance wiring. */
async function deployWithTimelock() {
  const [gov, guardian, outsider] = await ethers.getSigners();

  const Timelock = await ethers.getContractFactory("TimelockController");
  const timelock = (await Timelock.deploy(
    TIMELOCK_DELAY,
    [gov.address],
    [gov.address],
    gov.address,
  )) as unknown as TimelockController;
  await timelock.waitForDeployment();
  const timelockAddr = await timelock.getAddress();

  const pos = await (await ethers.getContractFactory("Poseidon2")).deploy();
  await pos.waitForDeployment();
  const posAddr = await pos.getAddress();

  const DarkPoolFactory = (await ethers.getContractFactory("DarkPool", {
    libraries: { Poseidon2: posAddr },
  })) as unknown as DarkPool__factory;

  const verifierAddrs = Array.from(
    { length: 6 },
    () => ethers.Wallet.createRandom().address,
  );
  const params: DarkPool.InitParamsStruct = {
    depositVerifier: verifierAddrs[0],
    withdrawVerifier: verifierAddrs[1],
    transferVerifier: verifierAddrs[2],
    joinVerifier: verifierAddrs[3],
    splitVerifier: verifierAddrs[4],
    publicClaimVerifier: verifierAddrs[5],
    rewardPool: ethers.Wallet.createRandom().address,
    compliancePkX: BASE8_X,
    compliancePkY: BASE8_Y,
    initialAdminDelay: 0, // timelock holds DEFAULT_ADMIN immediately
    initialAdmin: timelockAddr,
    pauser: guardian.address,
    upgrader: timelockAddr,
  };

  const proxy = (await upgrades.deployProxy(DarkPoolFactory, [params], {
    ...UUPS_OPTS,
    initializer: "initialize",
  })) as unknown as DarkPool;
  await proxy.waitForDeployment();
  const proxyAddr = await proxy.getAddress();

  const V2Factory = (await ethers.getContractFactory("DarkPoolV2Mock", {
    libraries: { Poseidon2: posAddr },
  })) as unknown as DarkPoolV2Mock__factory;
  const v2Impl = await V2Factory.deploy();
  await v2Impl.waitForDeployment();
  const v2ImplAddr = await v2Impl.getAddress();

  const upgradeData = proxy.interface.encodeFunctionData("upgradeToAndCall", [
    v2ImplAddr,
    "0x",
  ]);

  return {
    gov,
    guardian,
    outsider,
    timelock,
    proxy,
    proxyAddr,
    V2Factory,
    v2ImplAddr,
    upgradeData,
  };
}

describe("Timelock-governed upgrade path (D-11)", function () {
  it("blocks execute before the 48h delay and allows it after", async function () {
    const { gov, timelock, proxyAddr, V2Factory, upgradeData } =
      await deployWithTimelock();
    const salt = keccakId("darkpool-upgrade-v2");

    await timelock
      .connect(gov)
      .schedule(proxyAddr, 0, upgradeData, ZeroHash, salt, TIMELOCK_DELAY);

    // Not yet ready: execute reverts.
    await expect(
      timelock.connect(gov).execute(proxyAddr, 0, upgradeData, ZeroHash, salt),
    ).to.be.revertedWithCustomError(
      timelock,
      "TimelockUnexpectedOperationState",
    );

    await time.increase(TIMELOCK_DELAY + 1n);

    await timelock
      .connect(gov)
      .execute(proxyAddr, 0, upgradeData, ZeroHash, salt);

    const upgraded = V2Factory.attach(proxyAddr) as unknown as DarkPoolV2Mock;
    expect(await upgraded.version()).to.equal(2n);
  });

  it("lets a CANCELLER cancel a queued upgrade", async function () {
    const { gov, timelock, proxyAddr, upgradeData } =
      await deployWithTimelock();
    const salt = keccakId("darkpool-upgrade-to-cancel");

    await timelock
      .connect(gov)
      .schedule(proxyAddr, 0, upgradeData, ZeroHash, salt, TIMELOCK_DELAY);
    const opId = await timelock.hashOperation(
      proxyAddr,
      0,
      upgradeData,
      ZeroHash,
      salt,
    );
    expect(await timelock.isOperationPending(opId)).to.equal(true);

    await timelock.connect(gov).cancel(opId);
    expect(await timelock.isOperation(opId)).to.equal(false);

    await time.increase(TIMELOCK_DELAY + 1n);
    await expect(
      timelock.connect(gov).execute(proxyAddr, 0, upgradeData, ZeroHash, salt),
    ).to.be.revertedWithCustomError(
      timelock,
      "TimelockUnexpectedOperationState",
    );
  });

  it("guardian PAUSER can pause but cannot upgrade or unpause", async function () {
    const { guardian, proxy, v2ImplAddr } = await deployWithTimelock();

    await proxy.connect(guardian).pause();
    expect(await proxy.paused()).to.equal(true);

    await expect(
      proxy.connect(guardian).unpause(),
    ).to.be.revertedWithCustomError(proxy, "AccessControlUnauthorizedAccount");

    await expect(
      proxy.connect(guardian).upgradeToAndCall(v2ImplAddr, "0x"),
    ).to.be.revertedWithCustomError(proxy, "AccessControlUnauthorizedAccount");
  });
});
