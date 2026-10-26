import { describe, expect, it } from "vitest";
import { keccak256, toUtf8Bytes } from "ethers";
import {
  DARK_POOL_INTERFACE,
  EVENT_TOPICS,
  type DarkPoolEvent,
} from "../abi.js";

/** The frozen event table: signature, topic0, indexed arguments after topic0, data words. */
const FROZEN: Record<
  DarkPoolEvent,
  { sig: string; topic0: string; indexed: number; words: number }
> = {
  NewNote: {
    sig: "NewNote(uint256,bytes32,uint256,bytes32[7])",
    topic0:
      "0xf908f59e72bf09167999004bbfe849fd507952d06581f7e70134588458700854",
    indexed: 2,
    words: 8,
  },
  NewPrivateMemo: {
    sig: "NewPrivateMemo(uint256,bytes32,uint256,uint256,uint256,bytes32[7])",
    topic0:
      "0x7a202c1f6029a8f736ab7bb5da53a4930c10ccb35effa9881ece389ad9bd2544",
    indexed: 3,
    words: 9,
  },
  LeafInserted: {
    sig: "LeafInserted(uint256,bytes32,bytes32)",
    topic0:
      "0x2d3c13ae449947e04070bf2ac89327dc1fc56f31042172f3c9fdceb8f51c90e6",
    indexed: 1,
    words: 2,
  },
  RootSaved: {
    sig: "RootSaved(bytes32)",
    topic0:
      "0xa55369296f4adc70a8d99192608e0c4d18f10f343890264bc50b59981afdec51",
    indexed: 1,
    words: 0,
  },
  GenesisSeeded: {
    sig: "GenesisSeeded(uint256,bytes32)",
    topic0:
      "0x707c829c9689eb6b774ddf7479ad4c494581c7b5b36237f80738895c016166d9",
    indexed: 1,
    words: 1,
  },
  NullifierSpent: {
    sig: "NullifierSpent(bytes32)",
    topic0:
      "0x2d8b76eb247945151bd870d531c84c5420f53e3cb9c0ab3b350f46bb09362096",
    indexed: 1,
    words: 0,
  },
  ComplianceKeyRotated: {
    sig: "ComplianceKeyRotated(uint256,uint256,uint256,uint256)",
    topic0:
      "0xa9279e08847efe2bd488e211363a7bc5fd413e506b6a325134cec43f64946007",
    indexed: 0,
    words: 4,
  },
  NewPublicMemo: {
    sig: "NewPublicMemo(bytes32,address,uint256,uint256,uint256)",
    topic0:
      "0x55ab54025db51da4c6f9511101ebf0e0f60cf2171427b607a142348656fe8898",
    indexed: 1,
    words: 4,
  },
  PublicMemoSpent: {
    sig: "PublicMemoSpent(bytes32)",
    topic0:
      "0x142b563796c862a1fb294596318cb4ce9492eed8f1b25bbf2ea2aa96d9f05bb3",
    indexed: 1,
    words: 0,
  },
};

describe("event fragments", () => {
  it.each(Object.keys(FROZEN) as DarkPoolEvent[])(
    "%s matches the frozen layout",
    (name: DarkPoolEvent) => {
      const frozen = FROZEN[name];
      const event = DARK_POOL_INTERFACE.getEvent(name);
      expect(event).not.toBeNull();
      expect(event!.format("sighash")).toBe(frozen.sig);
      expect(keccak256(toUtf8Bytes(frozen.sig))).toBe(frozen.topic0);
      expect(event!.topicHash).toBe(frozen.topic0);
      expect(EVENT_TOPICS[name]).toBe(frozen.topic0);
      expect(event!.inputs.filter((i) => i.indexed)).toHaveLength(
        frozen.indexed,
      );
      const words = event!.inputs
        .filter((i) => !i.indexed)
        .reduce(
          (n, i) =>
            n +
            (i.arrayLength !== null && i.arrayLength > 0 ? i.arrayLength : 1),
          0,
        );
      expect(words).toBe(frozen.words);
    },
  );

  it("pins exactly the events the runtime decodes", () => {
    expect(Object.keys(EVENT_TOPICS).sort()).toEqual(
      Object.keys(FROZEN).sort(),
    );
  });
});
