/**
 * Prepares the Fuji simulation: generates the agent wallets once (keys written mode 600, never printed), deploys the
 * swap venue the trader uses (the 1:1 test router behind Howl's UniswapAdaptor), and tops every agent up to its
 * AVAX and test-token targets from the deployer, which owns the test tokens. Re-running only tops up.
 *
 * Env: SIM_AGENTS, SIM_VENUE, SIM_TOKENS, SIM_RECORD (paths), SIM_AGENT_AVAX (target per agent, in AVAX),
 * SIM_AGENT_TOKENS (whole tokens per agent and asset), SIM_WHALE_TOKENS (frank's), SIM_ROUTER_TOKENS (venue
 * liquidity per asset).
 */

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { ethers, network } from "hardhat";
import { HowlTestToken__factory } from "../../typechain-types";

const AGENT_NAMES = [
  "alice",
  "bob",
  "charlie",
  "david",
  "ellie",
  "frank",
  "grace",
] as const;
const WHALE = "frank";
const FUJI_CHAIN_ID = 43113n;

function env(k: string): string {
  const v = process.env[k];
  if (v === undefined || v === "") throw new Error(`${k} is required`);
  return v;
}

interface AgentsFile {
  chainId: number;
  label: string;
  agents: Record<string, { address: string; privateKey: string }>;
}

async function main(): Promise<void> {
  const chainId = (await ethers.provider.getNetwork()).chainId;
  if (chainId !== FUJI_CHAIN_ID)
    throw new Error(
      `sim-setup runs on Avalanche Fuji (43113) or a fork of it, not chain ${chainId} (${network.name})`,
    );
  const [deployer] = await ethers.getSigners();
  if (deployer === undefined)
    throw new Error("no deployer configured; set FUJI_DEPLOYER_KEY_FILE");

  const record = JSON.parse(readFileSync(env("SIM_RECORD"), "utf8")) as {
    meta: { chainId: number };
    contracts: { darkPool: string; poseidon2: string };
  };
  if (BigInt(record.meta.chainId) !== chainId)
    throw new Error("the deployment record is for another chain");
  const tokensRecord = JSON.parse(readFileSync(env("SIM_TOKENS"), "utf8")) as {
    owner: string;
    tokens: Record<string, { address: string; decimals: number }>;
  };
  if (ethers.getAddress(tokensRecord.owner) !== deployer.address)
    throw new Error("the configured deployer does not own the test tokens");

  // agents: generated once, never printed
  const agentsPath = env("SIM_AGENTS");
  let agents: AgentsFile;
  if (existsSync(agentsPath)) {
    agents = JSON.parse(readFileSync(agentsPath, "utf8")) as AgentsFile;
    if (BigInt(agents.chainId) !== chainId)
      throw new Error("the agents file is for another chain");
  } else {
    agents = {
      chainId: Number(chainId),
      label: "Howl Fuji test-build simulation agents",
      agents: {},
    };
    for (const name of AGENT_NAMES) {
      const w = ethers.Wallet.createRandom();
      agents.agents[name] = { address: w.address, privateKey: w.privateKey };
    }
    writeFileSync(agentsPath, JSON.stringify(agents, null, 2), {
      mode: 0o600,
      flag: "wx",
    });
    console.log(
      `generated ${AGENT_NAMES.length} agent wallets into the agents file (mode 600)`,
    );
  }
  for (const name of AGENT_NAMES)
    if (agents.agents[name] === undefined)
      throw new Error(`the agents file has no wallet for ${name}`);

  const tokens = Object.fromEntries(
    Object.entries(tokensRecord.tokens).map(([symbol, t]) => [
      symbol,
      {
        contract: HowlTestToken__factory.connect(t.address, deployer),
        decimals: t.decimals,
      },
    ]),
  );

  // the swap venue: deployed once
  const venuePath = env("SIM_VENUE");
  let venue: {
    chainId: number;
    router: string;
    adaptor: string;
    label: string;
  };
  if (existsSync(venuePath)) {
    venue = JSON.parse(readFileSync(venuePath, "utf8")) as typeof venue;
  } else {
    const router = await (
      await ethers.getContractFactory("MockSwapRouter", deployer)
    ).deploy();
    await router.waitForDeployment();
    const adaptor = await (
      await ethers.getContractFactory("UniswapAdaptor", {
        signer: deployer,
        libraries: { Poseidon2: record.contracts.poseidon2 },
      })
    ).deploy(record.contracts.darkPool, await router.getAddress());
    await adaptor.waitForDeployment();
    venue = {
      chainId: Number(chainId),
      label:
        "simulation swap venue: Howl's UniswapAdaptor over a fixed 1:1 test router (pre-freeze test build)",
      router: await router.getAddress(),
      adaptor: await adaptor.getAddress(),
    };
    writeFileSync(venuePath, JSON.stringify(venue, null, 2), { flag: "wx" });
    console.log(`venue: router ${venue.router}, adaptor ${venue.adaptor}`);
  }

  const topUpToken = async (symbol: string, holder: string, whole: bigint) => {
    const t = tokens[symbol];
    if (t === undefined) throw new Error(`no ${symbol} in the token record`);
    const want = whole * 10n ** BigInt(t.decimals);
    const have = await t.contract.balanceOf(holder);
    if (have >= want) return;
    const r = (await (await t.contract.mint(holder, want - have)).wait())!;
    console.log(`  minted ${symbol} to ${holder}: ${r.hash}`);
  };

  const routerTokens = BigInt(env("SIM_ROUTER_TOKENS"));
  for (const symbol of ["mDAI", "mWETH"])
    await topUpToken(symbol, venue.router, routerTokens);

  const avaxTarget = ethers.parseEther(env("SIM_AGENT_AVAX"));
  const agentTokens = BigInt(env("SIM_AGENT_TOKENS"));
  const whaleTokens = BigInt(env("SIM_WHALE_TOKENS"));
  for (const name of AGENT_NAMES) {
    const address = agents.agents[name]!.address;
    const have = await ethers.provider.getBalance(address);
    if (have < avaxTarget) {
      const r = (await (
        await deployer.sendTransaction({
          to: address,
          value: avaxTarget - have,
        })
      ).wait())!;
      console.log(
        `  ${name} ${address}: AVAX topped up to ${env("SIM_AGENT_AVAX")}: ${r.hash}`,
      );
    }
    for (const symbol of ["mDAI", "mWETH", "mUSDC"])
      await topUpToken(
        symbol,
        address,
        name === WHALE ? whaleTokens : agentTokens,
      );
    console.log(`${name} ${address}`);
  }
  console.log(
    `deployer balance ${ethers.formatEther(await ethers.provider.getBalance(deployer.address))} AVAX`,
  );
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
