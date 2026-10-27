import { describe, expect, it } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import { leaf } from "@hisoka/wallets";
import { EVENT_TOPICS } from "../abi.js";
import { RpcChainReader } from "../chain/chainReader.js";
import { RpcLogSource } from "../chain/logs.js";
import { sweepNullifiers } from "../history/nullifiers.js";
import { NoteStore, noteKey } from "../store/noteStore.js";
import { configFor, FakeChain } from "./fixtures/chain.js";
import { MemoryStore } from "./fixtures/store.js";
import { note } from "./fixtures/tree.js";

const word = (n: bigint): string => `0x${n.toString(16).padStart(64, "0")}`;

describe("nullifier sweep", () => {
  it("reads the whole public spent set from where it stopped, marks our notes, and never filters by nullifier", async () => {
    const chain = new FakeChain(30);
    const config = configFor(2);
    const deps = {
      config,
      chain: RpcChainReader.over(chain.rpc, config),
      logs: RpcLogSource.over(chain.rpc, config),
    };
    const notes = await NoteStore.open(new MemoryStore(), "k");
    const ours = {
      leafIndex: 1,
      commitment: await leaf(note(1n)),
      note: note(1n),
      nullifier: new Fr(0xabcn),
      origin: "self" as const,
      derivationIndex: 0,
      complianceVersion: 1,
      block: { number: 4, hash: chain.blocks[4]!.hash },
      verification: "verified" as const,
      spent: null,
      mirrored: false,
    };
    await notes.record([ours], null);
    chain.emit(9, "NullifierSpent", [word(0x111n)]);
    await sweepNullifiers(deps, notes);
    expect(notes.sweptThrough).toBe(30);
    expect(notes.find(noteKey(ours))?.spent).toBeNull();

    chain.mine(5);
    chain.emit(33, "NullifierSpent", [word(0xabcn)]);
    chain.calls.length = 0;
    await sweepNullifiers(deps, notes);
    expect(notes.find(noteKey(ours))?.spent).toMatchObject({
      block: { number: 33, hash: chain.blocks[33]!.hash },
    });
    const filters = chain.calls
      .filter((c) => c.method === "eth_getLogs")
      .map((c) => c.params[0] as { fromBlock: string; topics: string[][] });
    expect(Number(filters[0]!.fromBlock)).toBe(31);
    for (const f of filters) {
      expect(f.topics).toEqual([[EVENT_TOPICS.NullifierSpent]]);
    }
  });
});
