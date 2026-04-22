import type { HardhatUserConfig } from "hardhat/config";
import { task } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import "@nomicfoundation/hardhat-verify";
import "tsconfig-paths/register";
import * as fs from "fs";
import * as path from "path";
import { ethers } from "ethers";
import * as dotenv from "dotenv";

dotenv.config({ path: path.join(__dirname, ".env"), quiet: true });

const MAINNET_FORK_URL = process.env.MAINNET_FORK_URL;
const PRIVATE_KEY = process.env.PRIVATE_KEY || "";
const ARB_PRIV_KEY = process.env.ARB_PRIV_KEY || PRIVATE_KEY;
const ARB_SEPOLIA_RPC_URL =
  process.env.ARB_SEPOLIA_RPC_URL ||
  "https://sepolia-rollup.arbitrum.io/rpc";
const ARBISCAN_API_KEY = process.env.ARBISCAN_API_KEY || "";

// Validation for fork mode
if (process.env.FORK_MAINNET === "true" && !MAINNET_FORK_URL) {
  throw new Error("MAINNET_FORK_URL not set in .env but FORK_MAINNET is true");
}

function getTestFiles(dir: string): string[] {
  if (!fs.existsSync(dir)) return [];
  const stat = fs.statSync(dir);
  if (stat.isFile()) return [dir];

  const files: string[] = [];
  const list = fs.readdirSync(dir);
  for (const file of list) {
    const filePath = path.join(dir, file);
    const fileStat = fs.statSync(filePath);
    if (fileStat.isDirectory()) {
      files.push(...getTestFiles(filePath));
    } else if (file.endsWith(".test.ts")) {
      files.push(filePath);
    }
  }
  return files;
}


task("test:fast", "Runs core logic tests (no fork)")
  .addFlag("parallel", "Run tests in parallel")
  .setAction(async (args, hre) => {
    // Define the exact folders/files for fast tests
    const dirs = [
      "test/adversarial",
      "test/behaviors",
      "test/integration",
      "test/nox",
    ];
    const files = [
      "test/merkle-tree.test.ts",
      "test/poseidon-parity.test.ts",
    ];

    let testFiles: string[] = [];
    for (const d of dirs) testFiles = testFiles.concat(getTestFiles(d));
    testFiles = testFiles.concat(files.filter((f) => fs.existsSync(f)));

    // Exclude heavy tests that make 100+ deposits with proof generation.
    // These need dedicated CI time (test:slow) rather than the parallel suite.
    testFiles = testFiles.filter(
      (f) => !f.includes("RootEviction") && !f.includes("NoxMixnetE2E"),
    );

    console.log(`Running ${testFiles.length} fast tests...`);
    await hre.run("test", { testFiles, parallel: !!args.parallel });
  });

task("test:nox", "Runs mixnet E2E tests (requires nox mesh running)")
  .setAction(async (args, hre) => {
    const testFiles = getTestFiles("test/nox");
    console.log(`Running ${testFiles.length} nox mixnet tests...`);
    await hre.run("test", { testFiles });
  });

task("test:fork", "Runs adaptor tests (with mainnet fork)")
  .setAction(async (args, hre) => {
    const testFiles = getTestFiles("test/adaptors");
    console.log(`Running ${testFiles.length} fork tests...`);
    await hre.run("test", { testFiles });
  });


const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.28",
    settings: {
      optimizer: {
        enabled: true,
        runs: 1,
      },
    },
  },
  networks: {
    hardhat: {
      allowUnlimitedContractSize: true,
      forking: {
        url: MAINNET_FORK_URL || "",
        enabled: process.env.FORK_MAINNET === "true",
      },
    },
    localhost: {
      url: "http://127.0.0.1:8545",
      allowUnlimitedContractSize: true,
    },
    arbitrumSepolia: {
      url: ARB_SEPOLIA_RPC_URL,
      accounts: ARB_PRIV_KEY ? [ARB_PRIV_KEY] : [],
      chainId: 421614,
    },
  },
  etherscan: {
    apiKey: ARBISCAN_API_KEY,
  },
  mocha: {
    timeout: 120000,
  },
  typechain: {
    outDir: "typechain-types",
    target: "ethers-v6",
  },
};

task(
  "signatures",
  "List all function, event, and error signatures + selectors/topics across all contracts",
).setAction(async (_, hre) => {
  const artifactPaths = await hre.artifacts.getArtifactPaths();

  for (const artifactPath of artifactPaths) {
    const artifact = await import(artifactPath); // Dynamic import for JSON
    const { contractName, abi } = artifact;

    const functions = abi.filter((item: any) => item.type === "function");
    const events = abi.filter((item: any) => item.type === "event");
    const errors = abi.filter((item: any) => item.type === "error"); // Custom errors

    if (functions.length === 0 && events.length === 0 && errors.length === 0)
      continue;

    console.log(`\n${contractName}`);

    if (functions.length > 0) {
      console.log("  Functions:");
      for (const func of functions) {
        if (!func.name) continue; // Skip constructor, fallback, receive
        const sig = `${func.name}(${func.inputs.map((i: any) => i.type).join(",")})`;
        const selector = ethers.keccak256(ethers.toUtf8Bytes(sig)).slice(0, 10);
        console.log(`    ${sig} → ${selector}`);
      }
    }

    if (events.length > 0) {
      console.log("  Events:");
      for (const ev of events) {
        const sig = `${ev.name}(${ev.inputs.map((i: any) => i.type).join(",")})`;
        const topic = ethers.keccak256(ethers.toUtf8Bytes(sig));
        console.log(`    ${sig} → ${topic}`);
      }
    }

    if (errors.length > 0) {
      console.log("  Errors:");
      for (const err of errors) {
        const sig = `${err.name}(${err.inputs.map((i: any) => i.type).join(",")})`;
        const selector = ethers.keccak256(ethers.toUtf8Bytes(sig)).slice(0, 10); // First 4 bytes
        console.log(`    ${sig} → ${selector}`);
      }
    }
  }

  console.log("\n[OK] Done! Listed functions, events, and custom errors.");
});

export default config;
