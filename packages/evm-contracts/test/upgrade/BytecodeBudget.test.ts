import { expect } from "chai";
import { readdirSync, readFileSync } from "fs";
import { join, relative, resolve } from "path";

// hardhat and localhost set allowUnlimitedContractSize, so a contract over the EIP-170 24,576-byte cap passes every other test and is then undeployable.
const EIP_170_LIMIT = 24576;

const ARTIFACTS = resolve(process.cwd(), "artifacts/contracts");

// Keyed by artifact path: every generated verifier declares `contract HonkVerifier`, so the NAME is not a key.
const BUDGETS: Record<string, number> = {
  "Poseidon/Poseidon2.sol/Poseidon2.json": 24049,
  "DarkPool.sol/DarkPool.json": 17593,
  "verifiers/KageVerifier.sol/HonkVerifier.json": 18186,
  "verifiers/JoinMultisigVerifier.sol/HonkVerifier.json": 17066,
  "verifiers/TransferMultisigVerifier.sol/HonkVerifier.json": 17068,
  "verifiers/SplitMultisigVerifier.sol/HonkVerifier.json": 17068,
  "verifiers/JoinVerifier.sol/HonkVerifier.json": 17065,
  "verifiers/SplitVerifier.sol/HonkVerifier.json": 17066,
  "verifiers/TransferVerifier.sol/HonkVerifier.json": 17067,
  "verifiers/WithdrawVerifier.sol/HonkVerifier.json": 17067,
  "verifiers/WithdrawMultisigVerifier.sol/HonkVerifier.json": 17068,
  "verifiers/PublicClaimVerifier.sol/HonkVerifier.json": 16857,
  "verifiers/DepositVerifier.sol/HonkVerifier.json": 16856,
};

const WARN_RATIO = 0.95;

interface Deployed {
  key: string;
  name: string;
  bytes: number;
}

function collectDeployed(): Deployed[] {
  const found: Deployed[] = [];
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(full);
        continue;
      }
      if (!entry.name.endsWith(".json") || entry.name.endsWith(".dbg.json")) {
        continue;
      }
      const artifact = JSON.parse(readFileSync(full, "utf8")) as {
        contractName?: string;
        deployedBytecode?: string;
      };
      const code = artifact.deployedBytecode;
      if (code === undefined || code.length <= 2) continue;
      found.push({
        key: relative(ARTIFACTS, full).split(/[\\/]/).join("/"),
        name: artifact.contractName ?? entry.name,
        bytes: (code.length - 2) / 2,
      });
    }
  };
  walk(ARTIFACTS);
  return found;
}

describe("Deployed-bytecode budget (EIP-170)", function () {
  const deployed = collectDeployed();

  it("no contract exceeds the EIP-170 limit", function () {
    const over = deployed.filter((d) => d.bytes > EIP_170_LIMIT);
    expect(
      over.map((d) => `${d.key} = ${d.bytes}`),
      `over the ${EIP_170_LIMIT}-byte limit and therefore undeployable`,
    ).to.deep.equal([]);
  });

  it("every budgeted contract is present in the artifacts", function () {
    const keys = new Set(deployed.map((d) => d.key));
    const missing = Object.keys(BUDGETS).filter((k) => !keys.has(k));
    expect(
      missing,
      "budgeted artifact missing -- run `npx hardhat compile`",
    ).to.deep.equal([]);
  });

  for (const [key, expected] of Object.entries(BUDGETS)) {
    it(`${key.split("/")[key.split("/").length - 2]}: ${expected} bytes`, function () {
      const hit = deployed.find((d) => d.key === key);
      expect(hit, `no artifact at ${key}`).to.not.equal(undefined);
      expect(
        hit!.bytes,
        `${key} deployed size moved. If the change is intended, bump this pin deliberately and say why in the ` +
          `commit message; headroom to EIP-170 is ${EIP_170_LIMIT - hit!.bytes} bytes.`,
      ).to.equal(expected);
    });
  }

  it("reports anything within 5% of the limit", function () {
    const tight = deployed
      .filter((d) => d.bytes >= EIP_170_LIMIT * WARN_RATIO)
      .map(
        (d) =>
          `${d.key} = ${d.bytes} (${((d.bytes / EIP_170_LIMIT) * 100).toFixed(1)}%)`,
      );
    expect(tight).to.deep.equal([
      `Poseidon/Poseidon2.sol/Poseidon2.json = 24049 (97.9%)`,
    ]);
  });
});
