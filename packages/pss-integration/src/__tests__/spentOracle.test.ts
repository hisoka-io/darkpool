import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type ChildProcess, spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { keccak_256 } from "@noble/hashes/sha3";
import {
  type NullifierLog,
  createLogSweepOracle,
  pruneSpentNotes,
} from "@hisoka/pss-client";
import type { ParsedStatePayload, UnspentNote } from "@hisoka/pss-client";

// The contract SOURCE, which is tracked, not the compiled artifact, which is gitignored and absent from
// a fresh checkout. Read by path so this package takes no dependency edge on evm-contracts.
const DARKPOOL_SOURCE = new URL(
  "../../../evm-contracts/contracts/DarkPool.sol",
  import.meta.url,
);

const NULLIFIER_SPENT_SIGNATURE = "NullifierSpent(bytes32)";
const NULLIFIER_SPENT_TOPIC =
  "0x2d8b76eb247945151bd870d531c84c5420f53e3cb9c0ab3b350f46bb09362096";

interface EventParameter {
  readonly type: string;
  readonly indexed: boolean;
}

/**
 * Pulls the `event NullifierSpent(...)` declaration out of the Solidity source and returns its
 * parameters. Appending a parameter changes the canonical signature, and therefore topic0, which is what
 * the sweep filters on: a desynchronised topic silently returns no logs and every spent note looks
 * unspent, so this has to be graded against the declaration rather than against a pasted constant.
 */
function declaredEventParameters(name: string): readonly EventParameter[] {
  const source = readFileSync(DARKPOOL_SOURCE, "utf8");
  const declaration = new RegExp(`event\\s+${name}\\s*\\(([^)]*)\\)\\s*;`).exec(
    source,
  );
  if (declaration === null) {
    throw new Error(`no event ${name} declared in DarkPool.sol`);
  }
  return declaration[1]
    .split(",")
    .map((parameter) => parameter.trim())
    .filter((parameter) => parameter.length > 0)
    .map((parameter) => {
      const words = parameter.split(/\s+/);
      return { type: words[0], indexed: words.includes("indexed") };
    });
}

function canonicalSignature(
  name: string,
  parameters: readonly EventParameter[],
): string {
  return `${name}(${parameters.map((p) => p.type).join(",")})`;
}

function topic0(signature: string): string {
  // keccak256, which is NOT node:crypto's "sha3-256". That is NIST SHA-3 and gives a different digest.
  return `0x${Buffer.from(keccak_256(Buffer.from(signature, "utf8"))).toString("hex")}`;
}

// Minimal emitter. Runtime: load a nullifier from calldata, then LOG2 with the real event topic and the
// nullifier as topic1, which is the exact shape DarkPool produces because the argument is `indexed`.
// A real spend needs a valid proof and the whole prover stack; what is under test here is the sweep.
const EMITTER_RUNTIME = `6000357f${NULLIFIER_SPENT_TOPIC.slice(2)}60006000a200`;
const EMITTER_INIT = `0x602a600c600039602a6000f3${EMITTER_RUNTIME}`;

let anvil: ChildProcess;
let rpcUrl: string;
let emitter: string;
let sender: string;
let firstBlock: number;

/** Every eth_getLogs filter this test issued, so the unfiltered rule can be asserted rather than trusted. */
const filtersIssued: Array<Record<string, unknown>> = [];

async function rpc(method: string, params: unknown[]): Promise<unknown> {
  const response = await fetch(rpcUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const body = (await response.json()) as {
    result?: unknown;
    error?: { message: string };
  };
  if (body.error !== undefined) {
    throw new Error(`${method} failed: ${body.error.message}`);
  }
  return body.result;
}

async function waitForAnvil(launchError: () => string): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt++) {
    try {
      await rpc("eth_blockNumber", []);
      return;
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  }
  const detail = launchError().trim();
  throw new Error(
    `anvil did not become ready on ${rpcUrl}${detail === "" ? "" : `: ${detail}`}`,
  );
}

async function mined(hash: string): Promise<{ blockNumber: number }> {
  for (let attempt = 0; attempt < 100; attempt++) {
    const receipt = (await rpc("eth_getTransactionReceipt", [hash])) as {
      blockNumber: string;
      contractAddress?: string;
    } | null;
    if (receipt !== null) {
      return { blockNumber: Number(receipt.blockNumber) };
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error(`transaction ${hash} was never mined`);
}

function note(leafIndex: number, nullifier: string): UnspentNote {
  return {
    leafIndex,
    assetId: "0x1234567890123456789012345678901234567890",
    amount: "1000",
    nullifier,
  };
}

function payload(notes: readonly UnspentNote[]): ParsedStatePayload {
  return {
    known: {
      schema: 1,
      installId: "0x11111111111111111111111111111111",
      platform: "extension/chrome",
      updatedAt: 1,
      selfEphHighwater: 0,
      incomingIssueHighwater: 0,
      issuedAddresses: [],
      unspentNotes: [...notes],
      syncCursor: { block: 0, logIndex: 0 },
      nullifierCheckedAt: { block: 0 },
      ephemeralCounters: {},
    },
    extra: {},
  };
}

const nullifierAt = (n: number): string =>
  `0x${n.toString(16).padStart(64, "0")}`;

beforeAll(async () => {
  const port = 8600 + Math.floor(process.pid % 200);
  rpcUrl = `http://127.0.0.1:${port}`;
  // No --block-time, so anvil auto-mines one block per transaction, which is what the chunked sweep
  // needs. stderr is kept so a launch failure reads as itself rather than as a readiness timeout.
  anvil = spawn("anvil", ["--port", String(port), "--silent"], {
    stdio: ["ignore", "ignore", "pipe"],
  });
  let launchError = "";
  anvil.stderr?.on("data", (chunk: Buffer) => {
    launchError += chunk.toString();
  });
  await waitForAnvil(() => launchError);

  const accounts = (await rpc("eth_accounts", [])) as string[];
  sender = accounts[0];

  const deployHash = (await rpc("eth_sendTransaction", [
    { from: sender, data: EMITTER_INIT, gas: "0x100000" },
  ])) as string;
  const receipt = (await rpc("eth_getTransactionReceipt", [deployHash])) as {
    contractAddress: string;
  } | null;
  emitter =
    receipt?.contractAddress ??
    (
      (await rpc("eth_getTransactionReceipt", [deployHash])) as {
        contractAddress: string;
      }
    ).contractAddress;

  // Spend four nullifiers, one per transaction, so the sweep has to cross several blocks.
  const spent = [1, 2, 3, 4];
  for (const n of spent) {
    const hash = (await rpc("eth_sendTransaction", [
      { from: sender, to: emitter, data: nullifierAt(n), gas: "0x100000" },
    ])) as string;
    const where = await mined(hash);
    firstBlock = firstBlock ?? where.blockNumber;
  }
}, 120_000);

afterAll(() => {
  anvil.kill("SIGKILL");
});

/**
 * The v1 log source. It asks for a block range and the event topic and NOTHING else: adding the
 * nullifier as a second topic would tell the node which notes are ours, which is the leak the shielded
 * pool exists to prevent, so downloading every spend is the price of the property.
 */
async function nullifierLogs(
  fromBlock: number,
  toBlock: number,
): Promise<readonly NullifierLog[]> {
  const filter = {
    address: emitter,
    topics: [NULLIFIER_SPENT_TOPIC],
    fromBlock: `0x${fromBlock.toString(16)}`,
    toBlock: `0x${toBlock.toString(16)}`,
  };
  filtersIssued.push(filter);
  const logs = (await rpc("eth_getLogs", [filter])) as Array<{
    topics: string[];
    blockNumber: string;
  }>;
  return logs.map((log) => ({
    nullifier: log.topics[1],
    blockNumber: Number(log.blockNumber),
  }));
}

describe("the spent-note sweep against a live chain", () => {
  it("binds the swept topic to the event the contract source declares", () => {
    const parameters = declaredEventParameters("NullifierSpent");
    const signature = canonicalSignature("NullifierSpent", parameters);

    // Appending or retyping a parameter moves topic0 and the sweep would silently return nothing.
    expect(signature).toBe(NULLIFIER_SPENT_SIGNATURE);
    expect(topic0(signature)).toBe(NULLIFIER_SPENT_TOPIC);

    // Indexed, so the nullifier rides in topic1 and the data field is empty. That is what makes
    // filtering on it possible, and therefore what makes the no-filter rule a rule.
    expect(parameters).toHaveLength(1);
    expect(parameters[0]).toEqual({ type: "bytes32", indexed: true });
  });

  it("drops exactly the notes the chain shows spent and advances the checkpoint", async () => {
    const head = Number((await rpc("eth_blockNumber", [])) as string);
    const oracle = createLogSweepOracle({
      source: nullifierLogs,
      chunkBlocks: 2,
    });

    const before = payload([
      note(10, nullifierAt(1)),
      note(11, nullifierAt(2)),
      note(12, nullifierAt(99)),
      note(13, nullifierAt(4)),
    ]);
    const result = await pruneSpentNotes(before, oracle, 0, head);

    expect(result.dropped.map((n) => n.leafIndex).sort()).toEqual([10, 11, 13]);
    expect(result.payload.known.unspentNotes.map((n) => n.leafIndex)).toEqual([
      12,
    ]);
    expect(result.checkedThroughBlock).toBe(head);
  });

  it("never asks the node which nullifiers are ours", () => {
    expect(filtersIssued.length).toBeGreaterThan(0);
    for (const filter of filtersIssued) {
      const topics = filter.topics as unknown[];
      // Exactly one topic: the event signature. A second entry would be the nullifier, and it would
      // tell the node which notes belong to this wallet.
      expect(topics).toHaveLength(1);
      expect(topics[0]).toBe(NULLIFIER_SPENT_TOPIC);
    }
  });

  it("covers the range in config-driven chunks rather than one unbounded query", async () => {
    const head = Number((await rpc("eth_blockNumber", [])) as string);
    const ranges: Array<[number, number]> = [];
    const oracle = createLogSweepOracle({
      chunkBlocks: 2,
      source: async (from, to) => {
        ranges.push([from, to]);
        return nullifierLogs(from, to);
      },
    });
    await oracle.spentBetween(0, head);

    expect(ranges.length).toBeGreaterThan(1);
    for (const [from, to] of ranges) expect(to - from).toBeLessThanOrEqual(1);
    expect(ranges[0][0]).toBe(0);
    expect(ranges[ranges.length - 1][1]).toBe(head);
  });

  it("does not route through ScanEngine, which would discard the caller's start block", () => {
    const source = readFileSync(
      new URL("../../../pss-client/src/sync/spentOracle.ts", import.meta.url),
      "utf8",
    );
    expect(source).not.toMatch(/ScanEngine/);
    expect(source).not.toMatch(/@hisoka\/wallets/);
  });
});
