/**
 * Prices a fork rehearsal for the live chain. anvil charges only L2 execution gas; on Arbitrum every tx also
 * pays an L1 calldata component, so each rehearsal tx's calldata is re-priced with the live chain's
 * NodeInterface.gasEstimateL1Component (read-only eth_call) and the live gas price.
 *
 * Required env:
 *   FORK_RPC_URL  the anvil fork the rehearsal ran on
 *   LIVE_RPC_URL  the live Arbitrum chain to price against
 *   STEPS_FILE    [{ "name": "..", "fromBlock": n, "toBlock": n }] block ranges per rehearsal step (inclusive)
 *   GAS_OUT       output JSON path
 *
 * Usage:
 *   FORK_RPC_URL=.. LIVE_RPC_URL=.. STEPS_FILE=steps.json GAS_OUT=gas.json npx tsx scripts/rehearsal-gas-report.ts
 */

import { ethers } from "ethers";
import * as fs from "fs";

// Arbitrum's NodeInterface virtual contract (callable only through eth_call / eth_estimateGas).
const NODE_INTERFACE = "0x00000000000000000000000000000000000000C8";
const NODE_INTERFACE_ABI = [
  "function gasEstimateL1Component(address to, bool contractCreation, bytes data) payable returns (uint64 gasEstimateForL1, uint256 baseFee, uint256 l1BaseFeeEstimate)",
];

interface Step {
  readonly name: string;
  readonly fromBlock: number;
  readonly toBlock: number;
}

function requireEnv(name: string): string {
  const raw = process.env[name];
  if (raw === undefined || raw.trim() === "") {
    throw new Error(`${name} is not set.`);
  }
  return raw.trim();
}

async function main(): Promise<void> {
  // Free public RPCs reject JSON-RPC batches (drpc allows at most 3), so every request goes out alone.
  const unbatched = { batchMaxCount: 1 };
  const fork = new ethers.JsonRpcProvider(
    requireEnv("FORK_RPC_URL"),
    undefined,
    unbatched,
  );
  const live = new ethers.JsonRpcProvider(
    requireEnv("LIVE_RPC_URL"),
    undefined,
    unbatched,
  );
  const steps = JSON.parse(
    fs.readFileSync(requireEnv("STEPS_FILE"), "utf8"),
  ) as Step[];
  const nodeInterface = new ethers.Contract(
    NODE_INTERFACE,
    NODE_INTERFACE_ABI,
    live,
  );
  const liveGasPrice = (await live.getFeeData()).gasPrice;
  if (liveGasPrice === null) throw new Error("live RPC returned no gas price.");

  const report = [];
  let totalGas = 0n;
  for (const step of steps) {
    let l2Gas = 0n;
    let l1Gas = 0n;
    let txs = 0;
    const senders = new Map<string, bigint>();
    for (let n = step.fromBlock; n <= step.toBlock; n++) {
      const block = await fork.getBlock(n, true);
      if (block === null) throw new Error(`fork block ${n} not found.`);
      for (const tx of block.prefetchedTransactions) {
        const receipt = await fork.getTransactionReceipt(tx.hash);
        if (receipt === null) throw new Error(`no receipt for ${tx.hash}.`);
        const creation = tx.to === null;
        const [gasForL1] =
          await nodeInterface.gasEstimateL1Component.staticCall(
            creation ? ethers.ZeroAddress : tx.to,
            creation,
            tx.data,
          );
        const gas = receipt.gasUsed + BigInt(gasForL1);
        l2Gas += receipt.gasUsed;
        l1Gas += BigInt(gasForL1);
        txs += 1;
        senders.set(tx.from, (senders.get(tx.from) ?? 0n) + gas);
      }
    }
    const stepGas = l2Gas + l1Gas;
    totalGas += stepGas;
    report.push({
      step: step.name,
      blocks: [step.fromBlock, step.toBlock],
      txs,
      l2GasUsed: l2Gas.toString(),
      l1GasEstimate: l1Gas.toString(),
      totalGas: stepGas.toString(),
      ethAtLiveGasPrice: ethers.formatEther(stepGas * liveGasPrice),
      bySender: Object.fromEntries(
        [...senders.entries()].map(([from, gas]) => [
          from,
          ethers.formatEther(gas * liveGasPrice),
        ]),
      ),
    });
    console.log(
      `  ${step.name.padEnd(22)} txs ${String(txs).padStart(3)}  L2 ${l2Gas.toString().padStart(10)}  L1 ${l1Gas.toString().padStart(10)}  ~${ethers.formatEther(stepGas * liveGasPrice)} ETH`,
    );
  }
  const out = {
    liveGasPriceWei: liveGasPrice.toString(),
    totalGas: totalGas.toString(),
    totalEthAtLiveGasPrice: ethers.formatEther(totalGas * liveGasPrice),
    steps: report,
  };
  fs.writeFileSync(requireEnv("GAS_OUT"), JSON.stringify(out, null, 2));
  console.log(
    `  total gas ${totalGas} ~ ${out.totalEthAtLiveGasPrice} ETH at ${ethers.formatUnits(liveGasPrice, "gwei")} gwei`,
  );
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
