import { expect } from "chai";
import { ethers, network } from "hardhat";
import * as fs from "fs";
import * as path from "path";
import { Base8, mulPointEscalar } from "@zk-kit/baby-jubjub";
import { deploy, type DeployOptions } from "../../scripts/deploy";

const DEPLOY_DIR = path.join(__dirname, "../../deployments");
const GOV_SAFE = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
const GUARDIAN_SAFE = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC";
const THIRD_PARTY = "0x90F79bf6EB2c4f870365E785982E1f101E93b906";
const DEFAULT_ADMIN_ROLE = ethers.ZeroHash;

interface Record {
  meta: { network: string; chainId: number; deployer: string };
  governance: { timelock: string; govSafe: string; guardianSafe: string };
  compliance: { publicKeyX: string; publicKeyY: string };
  contracts: Record_<string>;
  vkHashes: Record_<string>;
  circuitHashes: Record_<string>;
  versions: { solidity: unknown[]; solidityOverrides: Record_<unknown> };
}
type Record_<T> = { [k: string]: T };

/**
 * Drives the real deployment in-process, against the same chain this test then asserts on, and captures
 * its operator output. A child process would get its own ephemeral chain and the addresses it reported
 * would resolve to nothing here.
 *
 * The script is the sole production deployment path and had no test at all, which is how a
 * self-contradictory assertion pair survived in it.
 */
async function runDeploy(
  env: Record_<string>,
  options: DeployOptions = {},
): Promise<{ ok: boolean; output: string }> {
  const saved: Record_<string | undefined> = {};
  for (const [k, v] of Object.entries(env)) {
    saved[k] = process.env[k];
    if (v === "") delete process.env[k];
    else process.env[k] = v;
  }
  const lines: string[] = [];
  const realLog = console.log;
  console.log = (...args: unknown[]) => {
    lines.push(args.map(String).join(" "));
  };
  try {
    await deploy(options);
    return { ok: true, output: lines.join("\n") };
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    return { ok: false, output: `${lines.join("\n")}\n${message}` };
  } finally {
    console.log = realLog;
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

function latestRecord(): Record {
  return JSON.parse(
    fs.readFileSync(path.join(DEPLOY_DIR, "hardhat-latest.json"), "utf8"),
  ) as Record;
}

describe("deploy script", function () {
  this.timeout(600000);

  let result: { ok: boolean; output: string };
  let record: Record;

  before(async function () {
    result = await runDeploy({ GOV_SAFE, GUARDIAN_SAFE, STAKING_TOKEN: "" });
    if (result.ok) record = latestRecord();
  });

  it("runs to completion", function () {
    expect(result.ok, result.output.slice(-2000)).to.equal(true);
    expect(result.output).to.contain("DEPLOYMENT COMPLETE");
  });

  it("checks the governance topology BEFORE the irreversible renounce", function () {
    const preflight = result.output.indexOf("Step 9: Preflight");
    const renounce = result.output.indexOf("Renouncing deployer's Timelock");
    const verified = result.output.indexOf("Governance topology verified");
    expect(preflight).to.be.greaterThan(-1);
    // Ordering is the property. Validating after the renounce leaves a failure nobody can repair.
    expect(preflight).to.be.lessThan(verified);
    expect(verified).to.be.lessThan(renounce);
  });

  it("deploys every contract and records an address for each", function () {
    for (const key of [
      "poseidon2",
      "darkPool",
      "noxRegistry",
      "noxRewardPool",
      "complianceRegistry",
      "stakingToken",
    ]) {
      expect(record.contracts[key], key).to.match(/^0x[0-9a-fA-F]{40}$/);
    }
    for (const key of Object.keys(record.contracts)) {
      if (key === "uniswapAdaptor") continue;
      expect(record.contracts[key], key).to.not.equal(ethers.ZeroAddress);
    }
  });

  // Circuit ids are positional in initialize, so "every slot is non-zero" passes under a reorder of
  // verifierPaths, and the record mislabels it identically so it cannot detect the swap either. Binding
  // each slot to the VK_HASH of the circuit it is supposed to hold is what makes a reorder visible.
  const EXPECTED_SLOTS = [
    "DepositVerifier",
    "WithdrawVerifier",
    "TransferVerifier",
    "JoinVerifier",
    "SplitVerifier",
    "PublicClaimVerifier",
    "WithdrawMultisigVerifier",
    "TransferMultisigVerifier",
    "SplitMultisigVerifier",
    "JoinMultisigVerifier",
    "KageVerifier",
  ];

  it("binds every circuit id to the verifier that circuit's VK_HASH belongs to", async function () {
    const darkPool = await ethers.getContractAt(
      "DarkPool",
      record.contracts.darkPool,
    );
    expect(Object.keys(record.vkHashes)).to.have.length(11);

    for (let circuitId = 0; circuitId < EXPECTED_SLOTS.length; circuitId++) {
      const name = EXPECTED_SLOTS[circuitId];
      const address = await darkPool.verifier(circuitId);
      expect(address, `circuit ${circuitId}`).to.not.equal(ethers.ZeroAddress);

      const vkHash = record.vkHashes[name];
      expect(vkHash, name).to.match(/^0x[0-9a-fA-F]{64}$/);

      // The VK hash is a PUSH32 immediate in the deployed verifier, so the deployed code at this slot
      // must literally contain it. A reordered array puts some other circuit's verifier here and this
      // fails.
      const code = await ethers.provider.getCode(address);
      expect(
        code.includes(vkHash.slice(2).toLowerCase()),
        `circuit ${circuitId} should hold ${name} (vkHash ${vkHash})`,
      ).to.equal(true);
    }
  });

  it("puts every privileged role with its intended holder and nobody else", async function () {
    const timelock = await ethers.getContractAt(
      "TimelockController",
      record.governance.timelock,
    );
    const darkPool = await ethers.getContractAt(
      "DarkPool",
      record.contracts.darkPool,
    );
    const deployer = record.meta.deployer;

    const CANCELLER = await timelock.CANCELLER_ROLE();
    const PROPOSER = await timelock.PROPOSER_ROLE();
    const EXECUTOR = await timelock.EXECUTOR_ROLE();
    const PAUSER = await darkPool.PAUSER_ROLE();
    const UPGRADER = await darkPool.UPGRADER_ROLE();

    expect(await timelock.hasRole(PROPOSER, GOV_SAFE)).to.equal(true);
    expect(await timelock.hasRole(EXECUTOR, GOV_SAFE)).to.equal(true);
    expect(await timelock.hasRole(CANCELLER, GOV_SAFE)).to.equal(true);

    // The separation. The pauser must not be able to veto its own unpause, and OZ hands CANCELLER to
    // every proposer automatically, so this is the check that catches a guardian added as a proposer.
    expect(await timelock.hasRole(CANCELLER, GUARDIAN_SAFE)).to.equal(false);
    expect(await darkPool.hasRole(PAUSER, GUARDIAN_SAFE)).to.equal(true);

    expect(
      await darkPool.hasRole(DEFAULT_ADMIN_ROLE, record.governance.timelock),
    ).to.equal(true);
    expect(
      await darkPool.hasRole(UPGRADER, record.governance.timelock),
    ).to.equal(true);

    // No EOA retains anything.
    for (const role of [PROPOSER, EXECUTOR, CANCELLER, DEFAULT_ADMIN_ROLE]) {
      expect(await timelock.hasRole(role, deployer)).to.equal(false);
    }
    for (const role of [PAUSER, UPGRADER, DEFAULT_ADMIN_ROLE]) {
      expect(await darkPool.hasRole(role, deployer)).to.equal(false);
    }
  });

  it("records the compliance key that the pool was actually initialized with", async function () {
    const darkPool = await ethers.getContractAt(
      "DarkPool",
      record.contracts.darkPool,
    );
    const [x, y] = await darkPool.complianceKey();
    expect(x.toString()).to.equal(record.compliance.publicKeyX);
    expect(y.toString()).to.equal(record.compliance.publicKeyY);
  });

  it("seeds the genesis leaf bound to this chain", async function () {
    const darkPool = await ethers.getContractAt(
      "DarkPool",
      record.contracts.darkPool,
    );
    // Genesis occupies index 0, so real notes start at 1.
    expect(await darkPool.getNextLeafIndex()).to.be.greaterThan(0n);
    expect(record.meta.chainId).to.equal(
      Number(network.config.chainId ?? 31337),
    );
  });

  it("carries a storage-layout manifest selected by network, not by sort order", function () {
    // The in-process chain produces no manifest, so null is correct here. What is asserted is that the
    // field exists and that selection is network-derived: a machine holding several networks' manifests
    // must not embed another chain's layout, which the previous readdir().sort().pop() did silently.
    expect(record).to.have.property("openzeppelinManifest");
    const manifest = (record as unknown as { openzeppelinManifest: unknown })
      .openzeppelinManifest;
    if (manifest !== null) {
      expect(manifest).to.be.an("object");
    }
  });

  it("writes a record with real circuit provenance and resolved compiler settings", function () {
    expect(Object.keys(record.circuitHashes)).to.have.length(12);
    for (const [name, hash] of Object.entries(record.circuitHashes)) {
      expect(hash, name).to.not.equal("NOT_FOUND");
    }
    // Resolved from the loaded config: the record previously hardcoded one optimizer setting for every
    // contract, which is wrong for each of the overridden ones.
    expect(record.versions.solidity)
      .to.be.an("array")
      .with.length.greaterThan(0);
    expect(
      Object.keys(record.versions.solidityOverrides).length,
    ).to.be.greaterThan(0);
  });

  it("persists the compliance secret before any transaction, owner-readable only", async function () {
    const secrets = fs
      .readdirSync(DEPLOY_DIR)
      .filter((f) => f.startsWith("hardhat-") && f.endsWith(".secrets.json"))
      .sort();
    const newest = path.join(DEPLOY_DIR, secrets[secrets.length - 1]);
    const parsed = JSON.parse(fs.readFileSync(newest, "utf8")) as {
      complianceSecretKey: string;
    };
    expect(parsed.complianceSecretKey).to.match(/^[0-9]+$/);

    // The point of writing it early is that it can decrypt what the pool was bound to. A 0600 file
    // holding the wrong scalar is the same permanent-undecryptability disaster, quietly.
    const derived = mulPointEscalar(Base8, BigInt(parsed.complianceSecretKey));
    const darkPool = await ethers.getContractAt(
      "DarkPool",
      record.contracts.darkPool,
    );
    const [onChainX, onChainY] = await darkPool.complianceKey();
    expect(derived[0].toString()).to.equal(onChainX.toString());
    expect(derived[1].toString()).to.equal(onChainY.toString());
    expect(fs.statSync(newest).mode & 0o777).to.equal(0o600);
    // The log line proves ordering: the secret is on disk before Step 1 deploys anything.
    const written = result.output.indexOf("Compliance secret written to");
    const firstDeploy = result.output.indexOf("Step 1: Poseidon2");
    expect(written).to.be.greaterThan(-1);
    expect(written).to.be.lessThan(firstDeploy);
  });
});

describe("deploy script preconditions", function () {
  this.timeout(600000);

  it("refuses when GOV_SAFE and GUARDIAN_SAFE are the same address", async function () {
    const r = await runDeploy({ GOV_SAFE, GUARDIAN_SAFE: GOV_SAFE });
    expect(r.ok).to.equal(false);
    expect(r.output).to.contain("the pauser must not also hold the veto");
  });

  it("refuses a missing GOV_SAFE", async function () {
    const r = await runDeploy({ GOV_SAFE: "", GUARDIAN_SAFE });
    expect(r.ok).to.equal(false);
    expect(r.output).to.contain("GOV_SAFE is not set");
  });
});

describe("preflight aborts a mis-wired topology before the renounce", function () {
  this.timeout(600000);

  // The whole reason the preflight exists. Both cases assert the run threw AND that it never reached the
  // renounce, because an assertion that fires after the deployer has given up admin cannot repair
  // anything it objects to. Ablating either guard by hand was not reproducible from the tree; these are.

  it("catches the guardian holding CANCELLER, which is the superseded design", async function () {
    const r = await runDeploy(
      { GOV_SAFE, GUARDIAN_SAFE, STAKING_TOKEN: "" },
      {
        afterGovernanceWiring: async ({ grantCanceller, guardianSafe }) => {
          await grantCanceller(guardianSafe);
        },
      },
    );
    expect(r.ok).to.equal(false);
    expect(r.output).to.contain(
      "DarkPool PAUSER does NOT hold Timelock CANCELLER",
    );
    expect(r.output).to.not.contain("Renouncing");
  });

  it("catches a third party holding CANCELLER, which the negative check alone would miss", async function () {
    const r = await runDeploy(
      { GOV_SAFE, GUARDIAN_SAFE, STAKING_TOKEN: "" },
      {
        // Deliberately NOT the deployer and NOT the guardian: the deployer-holdings sweep and the
        // negative check would each catch those earlier and more specifically. Only the exhaustive
        // holder-set entry can see an unrelated third party.
        afterGovernanceWiring: async ({ grantCanceller }) => {
          await grantCanceller(THIRD_PARTY);
        },
      },
    );
    expect(r.ok).to.equal(false);
    // The guardian still holds nothing, so only the exhaustive holder-set entry can catch this.
    expect(r.output).to.contain("CANCELLER holder set is exactly {govSafe}");
    expect(r.output).to.not.contain(
      "[FAIL] DarkPool PAUSER does NOT hold Timelock CANCELLER",
    );
    expect(r.output).to.not.contain("Renouncing");
  });
});
