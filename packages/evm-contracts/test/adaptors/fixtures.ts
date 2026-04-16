import { ethers } from "hardhat";
import { Base8, mulPointEscalar, Point } from "@zk-kit/baby-jubjub";
import { toFr } from "@hisoka/wallets";
import { DarkPool__factory, IERC20, UniswapAdaptor__factory, NoxRewardPool__factory } from "../../typechain-types";

// --- MAINNET CONSTANTS ---
export const WETH_ADDRESS = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";
export const USDC_ADDRESS = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
export const SWAP_ROUTER = "0xE592427A0AEce92De3Edee1F18E0157C05861564";
export const DAI_ADDRESS = "0x6B175474E89094C44Da98b954EedeAC495271d0F";
export const WBTC_ADDRESS = "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599";

// Uniswap V3 pools for on-chain price derivation
const WETH_USDC_POOL = "0x8ad599c3A0ff1De082011EFDDc58f1908eb6e6D8"; // 0.3% fee
const WBTC_USDC_POOL = "0x99ac8cA7087fA4A2A1FB6357269965A2014ABc35"; // 0.3% fee

const UNISWAP_POOL_ABI = [
  "function slot0() external view returns (uint160 sqrtPriceX96, int24 tick, uint16 observationIndex, uint16 observationCardinality, uint16 observationCardinalityNext, uint8 feeProtocol, bool unlocked)",
];

const Q96 = 2n ** 96n;

/**
 * Fetch live ETH/USD and BTC/USD prices from Uniswap V3 pool state on the forked chain.
 * Deterministic per fork block — no external API calls needed.
 */
export async function fetchLivePrices(): Promise<{ ethUsd: number; btcUsd: number }> {
  // WETH/USDC pool: token0=USDC (0xA0..), token1=WETH (0xC0..)
  // sqrtPriceX96 = sqrt(WETH_raw / USDC_raw) * 2^96
  // ethPriceUsd = 10^12 * 2^192 / sqrtPriceX96^2
  const wethUsdcPool = new ethers.Contract(WETH_USDC_POOL, UNISWAP_POOL_ABI, ethers.provider);
  const wethSlot0 = await wethUsdcPool.slot0();
  const wethSqrt = BigInt(wethSlot0.sqrtPriceX96);
  const ethNumerator = 10n ** 12n * Q96 * Q96;
  const ethDenominator = wethSqrt * wethSqrt;
  const ethUsd = Number(ethNumerator * 100n / ethDenominator) / 100;

  // WBTC/USDC pool: token0=WBTC (0x22..), token1=USDC (0xA0..)
  // sqrtPriceX96 = sqrt(USDC_raw / WBTC_raw) * 2^96
  // btcPriceUsd = (sqrtPriceX96 / 2^96)^2 * 10^(8-6) = sqrtPriceX96^2 * 100 / 2^192
  const wbtcUsdcPool = new ethers.Contract(WBTC_USDC_POOL, UNISWAP_POOL_ABI, ethers.provider);
  const wbtcSlot0 = await wbtcUsdcPool.slot0();
  const wbtcSqrt = BigInt(wbtcSlot0.sqrtPriceX96);
  const btcNumerator = wbtcSqrt * wbtcSqrt * 100n;
  const btcDenominator = Q96 * Q96;
  const btcUsd = Number(btcNumerator * 100n / btcDenominator) / 100;

  console.log(`   Live prices from fork: ETH=$${ethUsd.toFixed(2)}, BTC=$${btcUsd.toFixed(2)}`);
  return { ethUsd, btcUsd };
}

// --- CRYPTO CONSTANTS ---
export const COMPLIANCE_SK = 987654321n;
export const COMPLIANCE_PK: Point<bigint> = mulPointEscalar(
  Base8,
  COMPLIANCE_SK,
);
export const SK_VIEW = toFr(123456789n);
export const NONCE = toFr(1n);

const GAS_OVERRIDES = {
  maxFeePerGas: ethers.parseUnits("300", "gwei"),
  maxPriorityFeePerGas: ethers.parseUnits("10", "gwei"),
};

const IWETH_ABI = [
  "function deposit() payable",
  "function balanceOf(address) view returns (uint256)",
  "function approve(address, uint256) returns (bool)",
  "function transfer(address, uint256) returns (bool)"
];

export async function deployUniswapFixture() {
  const [deployer, alice, attacker] = await ethers.getSigners();

  // Capture the current block to use as fromBlock for event queries
  const fromBlock = await ethers.provider.getBlockNumber();

  const code = await ethers.provider.getCode(WETH_ADDRESS);
  if (code === "0x") {
    console.error("CRITICAL: WETH Address has no code!");
    console.error("You are likely running on an empty local chain, not a Mainnet Fork.");
    console.error("Usage: FORK_MAINNET=true npx hardhat test:fork");
    throw new Error("Forking disabled or invalid RPC.");
  }

  // 1. Deploy Libs
  const Poseidon2Factory = await ethers.getContractFactory("Poseidon2");
  const poseidon2Lib = await Poseidon2Factory.deploy(GAS_OVERRIDES);
  const poseidonAddress = await poseidon2Lib.getAddress();

  // 2. TranscriptLib is inlined (internal functions) — no separate deployment needed
  const getVerifierFactory = async (path: string) => {
    return ethers.getContractFactory(`${path}:HonkVerifier`);
  };

  // 3. Deploy Verifiers with linked libraries
  const DepVerifier = await (await getVerifierFactory("contracts/verifiers/DepositVerifier.sol")).deploy(GAS_OVERRIDES);
  const WdwVerifier = await (await getVerifierFactory("contracts/verifiers/WithdrawVerifier.sol")).deploy(GAS_OVERRIDES);
  const TrfVerifier = await (await getVerifierFactory("contracts/verifiers/TransferVerifier.sol")).deploy(GAS_OVERRIDES);
  const JoinVerifier = await (await getVerifierFactory("contracts/verifiers/JoinVerifier.sol")).deploy(GAS_OVERRIDES);
  const SplitVerifier = await (await getVerifierFactory("contracts/verifiers/SplitVerifier.sol")).deploy(GAS_OVERRIDES);
  const PublicClaimVerifier = await (await getVerifierFactory("contracts/verifiers/PublicClaimVerifier.sol")).deploy(GAS_OVERRIDES);
  const GasVerifier = await (await getVerifierFactory("contracts/verifiers/GasPaymentVerifier.sol")).deploy(GAS_OVERRIDES);

  // 3. Deploy Reward Pool
  const RewardPoolFactory = await ethers.getContractFactory("NoxRewardPool") as unknown as NoxRewardPool__factory;
  const rewardPool = await RewardPoolFactory.deploy(deployer.address, GAS_OVERRIDES);

  await rewardPool.setAssetStatus(WETH_ADDRESS, true);
  await rewardPool.setAssetStatus(USDC_ADDRESS, true);

  // 4. Deploy DarkPool
  const DarkPoolFactory = await ethers.getContractFactory("DarkPool", {
    libraries: { Poseidon2: poseidonAddress },
  }) as unknown as DarkPool__factory;

  const darkPool = await DarkPoolFactory.deploy(
    await DepVerifier.getAddress(),
    await WdwVerifier.getAddress(),
    await TrfVerifier.getAddress(),
    await JoinVerifier.getAddress(),
    await SplitVerifier.getAddress(),
    await PublicClaimVerifier.getAddress(),
    await GasVerifier.getAddress(),
    await rewardPool.getAddress(),
    COMPLIANCE_PK[0],
    COMPLIANCE_PK[1],
    deployer.address,
    GAS_OVERRIDES
  );

  // 5. Deploy Uniswap Adaptor
  const UniswapAdaptorFactory = await ethers.getContractFactory("UniswapAdaptor", {
    libraries: { Poseidon2: poseidonAddress },
  }) as unknown as UniswapAdaptor__factory;

  const uniswapAdaptor = await UniswapAdaptorFactory.deploy(
    await darkPool.getAddress(),
    SWAP_ROUTER,
    GAS_OVERRIDES
  );

  const wethContract = new ethers.Contract(WETH_ADDRESS, IWETH_ABI, alice);
  const tx = await wethContract.deposit({ value: ethers.parseEther("20"), ...GAS_OVERRIDES });
  await tx.wait();

  const bal = await wethContract.balanceOf(alice.address);
  if (bal < ethers.parseEther("20")) {
    throw new Error(`Critical: Alice WETH minting failed. Balance: ${bal}`);
  }

  const wethToken = await ethers.getContractAt("IERC20", WETH_ADDRESS) as unknown as IERC20;
  const usdc = await ethers.getContractAt("IERC20", USDC_ADDRESS) as unknown as IERC20;

  return { darkPool, uniswapAdaptor, rewardPool, weth: wethToken, usdc, alice, attacker, deployer, fromBlock };
}