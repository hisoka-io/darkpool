import { describe, it, expect } from "vitest";
import { Point } from "@zk-kit/baby-jubjub";
import { Contract } from "ethers";
import { DarkAccount } from "../keys/DarkAccount";
import { KeyRepository } from "../state/KeyRepository";
import { InMemoryEphemeralCounterStore } from "../state/EphemeralCounterStore";
import { UtxoRepository } from "../state/UtxoRepository";
import { ScanEngine } from "../sync/ScanEngine";

const MNEMONIC = "test test test test test test test test test test test junk";
const COMPLIANCE_PK: Point<bigint> = [
  0x085ed469c9a9f102b6d4f6f909b8ceaf6ca49b39759ac2e0feb7e0aada8b7111n,
  0x245e25ab2bd42f0280a5ade750828dd6868f5225ae798d6b51c676f519c8f4e8n,
];
const DEPLOYMENT_BLOCK = 500;

type Query = { name: string; fromBlock: number };

// Records the fromBlock each event query is issued with; returns no logs, so a scan is pure query behaviour.
function recordingContract(log: Query[]): Contract {
  const filterFor = (name: string) => () => ({ name });
  return {
    runner: { provider: { getBlockNumber: async () => 100000 } },
    filters: {
      NewNote: filterFor("NewNote"),
      NewPrivateMemo: filterFor("NewPrivateMemo"),
      NullifierSpent: filterFor("NullifierSpent"),
    },
    queryFilter: async (filter: { name: string }, fromBlock: number) => {
      log.push({ name: filter.name, fromBlock });
      return [];
    },
  } as unknown as Contract;
}

async function engineWith(
  queries: Query[],
): Promise<{ engine: ScanEngine; keyRepo: KeyRepository }> {
  const account = await DarkAccount.fromMnemonic(MNEMONIC);
  const keyRepo = new KeyRepository(
    account,
    new InMemoryEphemeralCounterStore(),
  );
  const engine = new ScanEngine(
    recordingContract(queries),
    keyRepo,
    new UtxoRepository(),
    COMPLIANCE_PK,
    undefined,
    20,
    DEPLOYMENT_BLOCK,
  );
  return { engine, keyRepo };
}

describe("ScanEngine block floor", () => {
  // Regression: a resync above deployment must floor note+memo queries too, not just nullifiers (else earlier notes vanish, balance understated).
  it("floors note and memo queries to the deployment block, not the caller's cursor", async () => {
    const queries: Query[] = [];
    const { engine } = await engineWith(queries);

    await engine.sync(DEPLOYMENT_BLOCK + 10_000);

    expect(queries.length).toBeGreaterThan(0);
    for (const q of queries) {
      expect(q.fromBlock, `${q.name} queried above the deployment block`).toBe(
        DEPLOYMENT_BLOCK,
      );
    }
    expect(queries.map((q) => q.name).sort()).toEqual([
      "NewNote",
      "NewPrivateMemo",
      "NullifierSpent",
    ]);
  });

  it("keeps a cursor below the deployment block", async () => {
    const queries: Query[] = [];
    const { engine } = await engineWith(queries);

    await engine.sync(1);

    for (const q of queries) expect(q.fromBlock).toBe(1);
  });

  // The pass loop re-runs only to widen the key lookahead; the log range is identical every pass, so the
  // three range queries must be issued once per sync rather than once per pass.
  it("issues each range query once per sync regardless of pass count", async () => {
    const queries: Query[] = [];
    const { engine, keyRepo } = await engineWith(queries);

    let extensionsLeft = 3;
    const realEnsure = keyRepo.ensureSelfLookahead.bind(keyRepo);
    keyRepo.ensureSelfLookahead = async (window: number) => {
      await realEnsure(window);
      return extensionsLeft-- > 0;
    };

    await engine.sync(DEPLOYMENT_BLOCK);

    expect(extensionsLeft).toBeLessThan(0);
    expect(queries.length).toBe(3);
  });
});
