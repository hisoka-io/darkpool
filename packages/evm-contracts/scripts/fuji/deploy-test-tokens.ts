/**
 * Deploys the three test tokens of the Fuji pre-freeze test build: mUSDC (6 decimals), mWETH (18) and mDAI (18).
 * Each is a HowlTestToken owned by the deployer, with owner-only mint. Refuses any chain but Fuji (43113), and
 * refuses to overwrite an existing record so a re-run cannot deploy a second set.
 *
 * Required env:
 *   TOKENS_OUT  output record path
 *
 * Usage:
 *   TOKENS_OUT=fuji-tokens.json npx hardhat run scripts/fuji/deploy-test-tokens.ts --network fuji
 */

import { ethers } from "hardhat";
import * as fs from "fs";

const FUJI_CHAIN_ID = 43113n;

const TOKENS = [
  { key: "mUSDC", name: "Howl Test USDC (pre-freeze test)", decimals: 6 },
  { key: "mWETH", name: "Howl Test WETH (pre-freeze test)", decimals: 18 },
  { key: "mDAI", name: "Howl Test DAI (pre-freeze test)", decimals: 18 },
] as const;

async function main(): Promise<void> {
  const out = process.env.TOKENS_OUT;
  if (out === undefined || out === "") {
    throw new Error(
      "TOKENS_OUT is required: the path the token record is written to.",
    );
  }
  if (fs.existsSync(out)) {
    throw new Error(
      `TOKENS_OUT ${out} already exists; refusing to deploy a second token set.`,
    );
  }
  const { chainId } = await ethers.provider.getNetwork();
  if (chainId !== FUJI_CHAIN_ID) {
    throw new Error(
      `deploy-test-tokens runs on Avalanche Fuji (43113) only, not chain id ${chainId}.`,
    );
  }
  const [deployer] = await ethers.getSigners();
  const factory = await ethers.getContractFactory("HowlTestToken");
  const record: Record<
    string,
    {
      address: string;
      name: string;
      symbol: string;
      decimals: number;
      block: number;
    }
  > = {};
  for (const t of TOKENS) {
    const token = await factory.deploy(
      t.name,
      t.key,
      t.decimals,
      deployer.address,
    );
    const receipt = await token.deploymentTransaction()?.wait();
    if (receipt === null || receipt === undefined) {
      throw new Error(`${t.key} deployment transaction has no receipt.`);
    }
    const address = await token.getAddress();
    if (
      (await token.decimals()) !== BigInt(t.decimals) ||
      (await token.owner()) !== deployer.address
    ) {
      throw new Error(
        `${t.key} at ${address} does not read back its decimals or owner.`,
      );
    }
    record[t.key] = {
      address,
      name: t.name,
      symbol: t.key,
      decimals: t.decimals,
      block: receipt.blockNumber,
    };
    console.log(
      `  ${t.key}: ${address} (${t.decimals} decimals, block ${receipt.blockNumber})`,
    );
  }
  fs.writeFileSync(
    out,
    JSON.stringify(
      { chainId: Number(chainId), owner: deployer.address, tokens: record },
      null,
      2,
    ) + "\n",
    { flag: "wx" },
  );
  console.log(`Token record: ${out}`);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
