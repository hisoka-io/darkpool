import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import {
  ProtocolParseError,
  parseProofEnvelope,
  type ProofEnvelope,
} from "../index.js";
import {
  CIRCUIT_IDS,
  STANDARD_CIRCUIT_IDS,
  parseCircuitId,
  parseStandardWitnessDto,
  standardWitnessDtoToNoirInput,
  type CircuitId,
  type StandardCircuitId,
} from "../proving/index.js";

const field = (value: bigint): string =>
  `0x${value.toString(16).padStart(64, "0")}`;

const merklePath = Array.from({ length: 32 }, (_, index) =>
  field(BigInt(index + 1)),
);

const PUBLIC_INPUT_WIDTHS = {
  deposit: 13,
  withdraw: 17,
  transfer: 24,
  split: 22,
  join: 14,
  public_claim: 13,
  withdraw_multisig: 17,
  transfer_multisig: 24,
  split_multisig: 22,
  join_multisig: 14,
  swap_intent: 27,
  swap_settle: 42,
} as const satisfies Readonly<Record<CircuitId, number>>;

const VERIFIER_SOURCES = {
  deposit: "DepositVerifier.sol",
  withdraw: "WithdrawVerifier.sol",
  transfer: "TransferVerifier.sol",
  split: "SplitVerifier.sol",
  join: "JoinVerifier.sol",
  public_claim: "PublicClaimVerifier.sol",
  withdraw_multisig: "WithdrawMultisigVerifier.sol",
  transfer_multisig: "TransferMultisigVerifier.sol",
  split_multisig: "SplitMultisigVerifier.sol",
  join_multisig: "JoinMultisigVerifier.sol",
  swap_settle: "KageVerifier.sol",
} as const;

function hostileCircuitValue() {
  const invocations = {
    primitive: 0,
    toString: 0,
    valueOf: 0,
  };
  return {
    invocations,
    value: {
      [Symbol.toPrimitive]: () => {
        invocations.primitive += 1;
        throw new Error("coercion ran");
      },
      toString: () => {
        invocations.toString += 1;
        throw new Error("toString ran");
      },
      valueOf: () => {
        invocations.valueOf += 1;
        throw new Error("valueOf ran");
      },
    },
  };
}

function runtimeCircuit<T extends CircuitId | StandardCircuitId>(
  value: unknown,
): T {
  return value as T;
}

function rawProofEnvelope(
  circuit: CircuitId,
  width: number,
  proof = "0x00",
  firstPublicInput = 1n,
) {
  return {
    circuit_id: circuit,
    proof,
    public_inputs: Array.from({ length: width }, (_, index) =>
      field(firstPublicInput + BigInt(index)),
    ),
  };
}

function note(seed: bigint, value: string) {
  return {
    note_version: field(seed),
    asset_id: field(seed + 1n),
    note_type: field(seed + 2n),
    conditions_hash: field(seed + 3n),
    value,
    owner: field(seed + 4n),
    psi: field(seed + 5n),
    parents: field(seed + 6n),
  };
}

const RAW_WITNESSES = {
  deposit: {
    compliance_pubkey_x: field(10n),
    compliance_pubkey_y: field(11n),
    note: note(20n, "100"),
    eph: field(30n),
  },
  withdraw: {
    withdraw_value: "40",
    _recipient: field(31n),
    _intent_hash: field(32n),
    compliance_pubkey_x: field(33n),
    compliance_pubkey_y: field(34n),
    old_note: note(40n, "100"),
    spend_scalar: field(50n),
    old_note_index: "7",
    old_note_path: merklePath,
    change_note: note(60n, "60"),
    change_eph: field(70n),
  },
  transfer: {
    compliance_pubkey_x: field(71n),
    compliance_pubkey_y: field(72n),
    recipient_spend_pub: { x: field(73n), y: field(74n) },
    recipient_view_pub: { x: field(75n), y: field(76n) },
    old_note: note(80n, "100"),
    spend_scalar: field(90n),
    old_note_index: "8",
    old_note_path: merklePath,
    memo_note: note(100n, "40"),
    memo_eph: field(110n),
    change_note: note(120n, "60"),
    change_eph: field(130n),
  },
  split: {
    compliance_pubkey_x: field(131n),
    compliance_pubkey_y: field(132n),
    note_in: note(140n, "100"),
    spend_scalar: field(150n),
    index_in: "9",
    path_in: merklePath,
    note_out_1: note(160n, "40"),
    eph_1: field(170n),
    note_out_2: note(180n, "60"),
    eph_2: field(190n),
  },
  join: {
    compliance_pubkey_x: field(191n),
    compliance_pubkey_y: field(192n),
    note_a: note(200n, "40"),
    spend_scalar_a: field(210n),
    index_a: "10",
    path_a: merklePath,
    note_b: note(220n, "60"),
    spend_scalar_b: field(230n),
    index_b: "11",
    path_b: merklePath,
    note_out: note(240n, "100"),
    eph_out: field(250n),
  },
  public_claim: {
    memo_id: field(251n),
    compliance_pubkey_x: field(252n),
    compliance_pubkey_y: field(253n),
    current_timestamp: "1800000000",
    val: "100",
    asset_id: field(254n),
    timelock: "1700000000",
    owner_x: field(255n),
    owner_y: field(256n),
    salt: field(257n),
    recipient_sk: field(258n),
    note_out: note(260n, "100"),
    eph: field(270n),
  },
} as const;

function jsonClone(value: unknown): unknown {
  return JSON.parse(JSON.stringify(value)) as unknown;
}

function mutableRecord(value: unknown, path: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`test fixture ${path} is not an object`);
  }
  return value as Record<string, unknown>;
}

function objectAt(root: unknown, path: string): Record<string, unknown> {
  let current = root;
  for (const segment of path.slice(2).split(".").filter(Boolean)) {
    current = mutableRecord(current, path)[segment];
  }
  return mutableRecord(current, path);
}

function replaceAt(root: unknown, path: string, replacement: unknown): unknown {
  if (path === "$") {
    return replacement;
  }

  const segments = path.slice(2).split(".");
  const property = segments.pop();
  if (property === undefined) {
    throw new Error(`test fixture path ${path} has no property`);
  }
  const parentPath = segments.length === 0 ? "$" : `$.${segments.join(".")}`;
  mutableRecord(objectAt(root, parentPath), parentPath)[property] = replacement;
  return root;
}

const OBJECT_LEVELS = [
  ["deposit", "$", "compliance_pubkey_x"],
  ["deposit", "$.note", "note_version"],
  ["withdraw", "$", "withdraw_value"],
  ["withdraw", "$.old_note", "note_version"],
  ["withdraw", "$.change_note", "note_version"],
  ["transfer", "$", "compliance_pubkey_x"],
  ["transfer", "$.recipient_spend_pub", "x"],
  ["transfer", "$.recipient_view_pub", "x"],
  ["transfer", "$.old_note", "note_version"],
  ["transfer", "$.memo_note", "note_version"],
  ["transfer", "$.change_note", "note_version"],
  ["split", "$", "compliance_pubkey_x"],
  ["split", "$.note_in", "note_version"],
  ["split", "$.note_out_1", "note_version"],
  ["split", "$.note_out_2", "note_version"],
  ["join", "$", "compliance_pubkey_x"],
  ["join", "$.note_a", "note_version"],
  ["join", "$.note_b", "note_version"],
  ["join", "$.note_out", "note_version"],
  ["public_claim", "$", "memo_id"],
  ["public_claim", "$.note_out", "note_version"],
] as const satisfies readonly (readonly [StandardCircuitId, string, string])[];

const NOIR_KEYS = {
  deposit: ["compliance_pubkey_x", "compliance_pubkey_y", "note", "eph"],
  withdraw: [
    "withdraw_value",
    "_recipient",
    "_intent_hash",
    "compliance_pubkey_x",
    "compliance_pubkey_y",
    "old_note",
    "spend_scalar",
    "old_note_index",
    "old_note_path",
    "change_note",
    "change_eph",
  ],
  transfer: [
    "compliance_pubkey_x",
    "compliance_pubkey_y",
    "recipient_spend_pub",
    "recipient_view_pub",
    "old_note",
    "spend_scalar",
    "old_note_index",
    "old_note_path",
    "memo_note",
    "memo_eph",
    "change_note",
    "change_eph",
  ],
  split: [
    "compliance_pubkey_x",
    "compliance_pubkey_y",
    "note_in",
    "spend_scalar",
    "index_in",
    "path_in",
    "note_out_1",
    "eph_1",
    "note_out_2",
    "eph_2",
  ],
  join: [
    "compliance_pubkey_x",
    "compliance_pubkey_y",
    "note_a",
    "spend_scalar_a",
    "index_a",
    "path_a",
    "note_b",
    "spend_scalar_b",
    "index_b",
    "path_b",
    "note_out",
    "eph_out",
  ],
  public_claim: [
    "memo_id",
    "compliance_pubkey_x",
    "compliance_pubkey_y",
    "current_timestamp",
    "val",
    "asset_id",
    "timelock",
    "owner_x",
    "owner_y",
    "salt",
    "recipient_sk",
    "note_out",
    "eph",
  ],
} as const;

function noirNote(rawNote: ReturnType<typeof note>): Record<string, string> {
  return {
    note_version: rawNote.note_version,
    asset_id: rawNote.asset_id,
    note_type: rawNote.note_type,
    conditions_hash: rawNote.conditions_hash,
    value: field(BigInt(rawNote.value)),
    owner: rawNote.owner,
    psi: rawNote.psi,
    parents: rawNote.parents,
  };
}

const pointCoordinate = (value: string): string =>
  `0x${BigInt(value).toString(16)}`;

const EXPECTED_NOIR_INPUTS = {
  deposit: {
    compliance_pubkey_x: pointCoordinate(
      RAW_WITNESSES.deposit.compliance_pubkey_x,
    ),
    compliance_pubkey_y: pointCoordinate(
      RAW_WITNESSES.deposit.compliance_pubkey_y,
    ),
    note: noirNote(RAW_WITNESSES.deposit.note),
    eph: RAW_WITNESSES.deposit.eph,
  },
  withdraw: {
    withdraw_value: field(40n),
    _recipient: RAW_WITNESSES.withdraw._recipient,
    _intent_hash: RAW_WITNESSES.withdraw._intent_hash,
    compliance_pubkey_x: pointCoordinate(
      RAW_WITNESSES.withdraw.compliance_pubkey_x,
    ),
    compliance_pubkey_y: pointCoordinate(
      RAW_WITNESSES.withdraw.compliance_pubkey_y,
    ),
    old_note: noirNote(RAW_WITNESSES.withdraw.old_note),
    spend_scalar: RAW_WITNESSES.withdraw.spend_scalar,
    old_note_index: RAW_WITNESSES.withdraw.old_note_index,
    old_note_path: merklePath,
    change_note: noirNote(RAW_WITNESSES.withdraw.change_note),
    change_eph: RAW_WITNESSES.withdraw.change_eph,
  },
  transfer: {
    compliance_pubkey_x: pointCoordinate(
      RAW_WITNESSES.transfer.compliance_pubkey_x,
    ),
    compliance_pubkey_y: pointCoordinate(
      RAW_WITNESSES.transfer.compliance_pubkey_y,
    ),
    recipient_spend_pub: {
      x: pointCoordinate(RAW_WITNESSES.transfer.recipient_spend_pub.x),
      y: pointCoordinate(RAW_WITNESSES.transfer.recipient_spend_pub.y),
    },
    recipient_view_pub: {
      x: pointCoordinate(RAW_WITNESSES.transfer.recipient_view_pub.x),
      y: pointCoordinate(RAW_WITNESSES.transfer.recipient_view_pub.y),
    },
    old_note: noirNote(RAW_WITNESSES.transfer.old_note),
    spend_scalar: RAW_WITNESSES.transfer.spend_scalar,
    old_note_index: RAW_WITNESSES.transfer.old_note_index,
    old_note_path: merklePath,
    memo_note: noirNote(RAW_WITNESSES.transfer.memo_note),
    memo_eph: RAW_WITNESSES.transfer.memo_eph,
    change_note: noirNote(RAW_WITNESSES.transfer.change_note),
    change_eph: RAW_WITNESSES.transfer.change_eph,
  },
  split: {
    compliance_pubkey_x: pointCoordinate(
      RAW_WITNESSES.split.compliance_pubkey_x,
    ),
    compliance_pubkey_y: pointCoordinate(
      RAW_WITNESSES.split.compliance_pubkey_y,
    ),
    note_in: noirNote(RAW_WITNESSES.split.note_in),
    spend_scalar: RAW_WITNESSES.split.spend_scalar,
    index_in: RAW_WITNESSES.split.index_in,
    path_in: merklePath,
    note_out_1: noirNote(RAW_WITNESSES.split.note_out_1),
    eph_1: RAW_WITNESSES.split.eph_1,
    note_out_2: noirNote(RAW_WITNESSES.split.note_out_2),
    eph_2: RAW_WITNESSES.split.eph_2,
  },
  join: {
    compliance_pubkey_x: pointCoordinate(
      RAW_WITNESSES.join.compliance_pubkey_x,
    ),
    compliance_pubkey_y: pointCoordinate(
      RAW_WITNESSES.join.compliance_pubkey_y,
    ),
    note_a: noirNote(RAW_WITNESSES.join.note_a),
    spend_scalar_a: RAW_WITNESSES.join.spend_scalar_a,
    index_a: RAW_WITNESSES.join.index_a,
    path_a: merklePath,
    note_b: noirNote(RAW_WITNESSES.join.note_b),
    spend_scalar_b: RAW_WITNESSES.join.spend_scalar_b,
    index_b: RAW_WITNESSES.join.index_b,
    path_b: merklePath,
    note_out: noirNote(RAW_WITNESSES.join.note_out),
    eph_out: RAW_WITNESSES.join.eph_out,
  },
  public_claim: {
    memo_id: RAW_WITNESSES.public_claim.memo_id,
    compliance_pubkey_x: pointCoordinate(
      RAW_WITNESSES.public_claim.compliance_pubkey_x,
    ),
    compliance_pubkey_y: pointCoordinate(
      RAW_WITNESSES.public_claim.compliance_pubkey_y,
    ),
    current_timestamp: RAW_WITNESSES.public_claim.current_timestamp,
    val: field(100n),
    asset_id: RAW_WITNESSES.public_claim.asset_id,
    timelock: field(1700000000n),
    owner_x: RAW_WITNESSES.public_claim.owner_x,
    owner_y: RAW_WITNESSES.public_claim.owner_y,
    salt: RAW_WITNESSES.public_claim.salt,
    recipient_sk: RAW_WITNESSES.public_claim.recipient_sk,
    note_out: noirNote(RAW_WITNESSES.public_claim.note_out),
    eph: RAW_WITNESSES.public_claim.eph,
  },
} as const;

describe("circuit vocabulary", () => {
  it("pins all twelve circuits in protocol order", () => {
    expect(CIRCUIT_IDS).toEqual([
      "deposit",
      "withdraw",
      "transfer",
      "split",
      "join",
      "public_claim",
      "withdraw_multisig",
      "transfer_multisig",
      "split_multisig",
      "join_multisig",
      "swap_intent",
      "swap_settle",
    ]);
  });

  it("pins the six standard circuits in protocol order", () => {
    expect(STANDARD_CIRCUIT_IDS).toEqual([
      "deposit",
      "withdraw",
      "transfer",
      "split",
      "join",
      "public_claim",
    ]);
  });

  it("keeps the exported circuit vocabularies immutable at runtime", () => {
    expect(Reflect.set(CIRCUIT_IDS, "0", "tampered")).toBe(false);
    expect(Reflect.set(STANDARD_CIRCUIT_IDS, "0", "tampered")).toBe(false);
    expect(parseCircuitId("deposit")).toBe("deposit");
  });

  it.each(CIRCUIT_IDS)("parses circuit id %s", (circuit: CircuitId) => {
    expect(parseCircuitId(circuit)).toBe(circuit);
  });

  it.each(["", "Deposit", "public-claim", "unknown", 0, null])(
    "rejects invalid circuit id %#",
    (circuit: unknown) => {
      expect(() => parseCircuitId(circuit)).toThrowError(
        expect.objectContaining({ code: "INVALID_CIRCUIT_ID", path: "$" }),
      );
    },
  );
});

describe("standard witness parsing", () => {
  it("rejects unsupported and hostile circuit arguments without coercion", () => {
    expect(() =>
      parseStandardWitnessDto("bogus" as StandardCircuitId, {}),
    ).toThrowError(
      expect.objectContaining({ code: "INVALID_CIRCUIT_ID", path: "$" }),
    );

    const hostile = hostileCircuitValue();
    expect(() =>
      parseStandardWitnessDto(
        runtimeCircuit<StandardCircuitId>(hostile.value),
        {},
      ),
    ).toThrowError(
      expect.objectContaining({ code: "INVALID_CIRCUIT_ID", path: "$" }),
    );
    expect(hostile.invocations).toEqual({
      primitive: 0,
      toString: 0,
      valueOf: 0,
    });
  });

  it.each(STANDARD_CIRCUIT_IDS)(
    "parses and round-trips the complete %s witness",
    (circuit: StandardCircuitId) => {
      const parsed = parseStandardWitnessDto(circuit, RAW_WITNESSES[circuit]);
      expect(parsed).toEqual(RAW_WITNESSES[circuit]);
      expect(
        parseStandardWitnessDto(
          circuit,
          JSON.parse(JSON.stringify(parsed)) as unknown,
        ),
      ).toEqual(parsed);
    },
  );

  it.each(OBJECT_LEVELS)(
    "%s rejects an extra key at %s",
    (circuit: StandardCircuitId, path: string) => {
      const raw = jsonClone(RAW_WITNESSES[circuit]);
      objectAt(raw, path)["extra"] = field(999n);

      expect(() => parseStandardWitnessDto(circuit, raw)).toThrowError(
        expect.objectContaining({
          code: "UNEXPECTED_PROPERTY",
          path: path === "$" ? "$.extra" : `${path}.extra`,
        }),
      );
    },
  );

  it.each(OBJECT_LEVELS)(
    "%s rejects a missing own key at %s",
    (circuit: StandardCircuitId, path: string, property: string) => {
      const raw = jsonClone(RAW_WITNESSES[circuit]);
      delete objectAt(raw, path)[property];

      expect(() => parseStandardWitnessDto(circuit, raw)).toThrowError(
        expect.objectContaining({
          code: "INVALID_OBJECT",
          path: path === "$" ? `$.${property}` : `${path}.${property}`,
        }),
      );
    },
  );

  it.each(OBJECT_LEVELS)(
    "%s rejects an inherited key at %s",
    (circuit: StandardCircuitId, path: string, property: string) => {
      const raw = jsonClone(RAW_WITNESSES[circuit]);
      const target = objectAt(raw, path);
      const inherited = target[property];
      delete target[property];
      Object.setPrototypeOf(target, { [property]: inherited });

      expect(() => parseStandardWitnessDto(circuit, raw)).toThrowError(
        expect.objectContaining({ code: "INVALID_OBJECT", path }),
      );
    },
  );

  it.each(OBJECT_LEVELS)(
    "%s rejects an accessor at %s without invoking it",
    (circuit: StandardCircuitId, path: string, property: string) => {
      const raw = jsonClone(RAW_WITNESSES[circuit]);
      const target = objectAt(raw, path);
      let invoked = false;
      Object.defineProperty(target, property, {
        enumerable: true,
        get: () => {
          invoked = true;
          return field(999n);
        },
      });

      expect(() => parseStandardWitnessDto(circuit, raw)).toThrowError(
        expect.objectContaining({
          code: "INVALID_OBJECT",
          path: path === "$" ? `$.${property}` : `${path}.${property}`,
        }),
      );
      expect(invoked).toBe(false);
    },
  );

  it.each(OBJECT_LEVELS)(
    "%s fails closed on a trapped object at %s",
    (circuit: StandardCircuitId, path: string) => {
      const raw = jsonClone(RAW_WITNESSES[circuit]);
      const trapped = new Proxy(objectAt(raw, path), {
        getPrototypeOf: () => {
          throw new Error("hostile prototype trap");
        },
      });

      expect(() =>
        parseStandardWitnessDto(circuit, replaceAt(raw, path, trapped)),
      ).toThrowError(expect.objectContaining({ code: "INVALID_OBJECT", path }));
    },
  );

  it.each(OBJECT_LEVELS)(
    "%s fails closed on a revoked object at %s",
    (circuit: StandardCircuitId, path: string) => {
      const raw = jsonClone(RAW_WITNESSES[circuit]);
      const { proxy, revoke } = Proxy.revocable(objectAt(raw, path), {});
      revoke();

      expect(() =>
        parseStandardWitnessDto(circuit, replaceAt(raw, path, proxy)),
      ).toThrowError(expect.objectContaining({ code: "INVALID_OBJECT", path }));
    },
  );

  it.each([
    ["deposit", "withdraw"],
    ["withdraw", "transfer"],
    ["transfer", "split"],
    ["split", "join"],
    ["join", "public_claim"],
    ["public_claim", "deposit"],
  ] as const)(
    "rejects a %s witness parsed as %s",
    (actual: StandardCircuitId, expected: StandardCircuitId) => {
      expect(() =>
        parseStandardWitnessDto(expected, RAW_WITNESSES[actual]),
      ).toThrow(ProtocolParseError);
    },
  );

  it.each([
    ["withdraw", "old_note_path"],
    ["transfer", "old_note_path"],
    ["split", "path_in"],
    ["join", "path_a"],
    ["join", "path_b"],
  ] as const)(
    "accepts exactly 32 fields in %s.%s",
    (circuit: StandardCircuitId, property: string) => {
      const raw = jsonClone(RAW_WITNESSES[circuit]);
      expect(() => parseStandardWitnessDto(circuit, raw)).not.toThrow();

      const short = jsonClone(RAW_WITNESSES[circuit]);
      mutableRecord(short, "$.")[property] = merklePath.slice(0, 31);
      expect(() => parseStandardWitnessDto(circuit, short)).toThrowError(
        expect.objectContaining({
          code: "INVALID_MERKLE_PATH",
          path: `$.${property}`,
        }),
      );

      const long = jsonClone(RAW_WITNESSES[circuit]);
      mutableRecord(long, "$.")[property] = [...merklePath, field(33n)];
      expect(() => parseStandardWitnessDto(circuit, long)).toThrowError(
        expect.objectContaining({
          code: "INVALID_MERKLE_PATH",
          path: `$.${property}`,
        }),
      );
    },
  );

  it("reports a malformed Merkle sibling at its exact index", () => {
    const raw = jsonClone(RAW_WITNESSES.withdraw);
    const record = mutableRecord(raw, "$");
    const path = record["old_note_path"];
    if (!Array.isArray(path)) {
      throw new Error("test fixture old_note_path is not an array");
    }
    path[17] = "0x01";

    expect(() => parseStandardWitnessDto("withdraw", raw)).toThrowError(
      expect.objectContaining({
        code: "INVALID_FIELD_HEX",
        path: "$.old_note_path[17]",
      }),
    );
  });

  it("rejects accessor and trapped Merkle arrays without reading entries", () => {
    const accessorRaw = jsonClone(RAW_WITNESSES.withdraw);
    const accessorRecord = mutableRecord(accessorRaw, "$");
    const accessorPath = accessorRecord["old_note_path"];
    if (!Array.isArray(accessorPath)) {
      throw new Error("test fixture old_note_path is not an array");
    }
    let invoked = false;
    Object.defineProperty(accessorPath, "17", {
      enumerable: true,
      get: () => {
        invoked = true;
        return field(18n);
      },
    });
    expect(() => parseStandardWitnessDto("withdraw", accessorRaw)).toThrowError(
      expect.objectContaining({
        code: "INVALID_OBJECT",
        path: "$.old_note_path[17]",
      }),
    );
    expect(invoked).toBe(false);

    const trappedRaw = jsonClone(RAW_WITNESSES.withdraw);
    const trappedRecord = mutableRecord(trappedRaw, "$");
    const trappedPath = trappedRecord["old_note_path"];
    if (!Array.isArray(trappedPath)) {
      throw new Error("test fixture old_note_path is not an array");
    }
    trappedRecord["old_note_path"] = new Proxy(trappedPath, {
      ownKeys: () => {
        throw new Error("hostile array trap");
      },
    });
    expect(() => parseStandardWitnessDto("withdraw", trappedRaw)).toThrowError(
      expect.objectContaining({
        code: "INVALID_OBJECT",
        path: "$.old_note_path",
      }),
    );
  });

  it("reports an extra Merkle-array property at its exact path", () => {
    const raw = jsonClone(RAW_WITNESSES.withdraw);
    const record = mutableRecord(raw, "$");
    const path = record["old_note_path"];
    if (!Array.isArray(path)) {
      throw new Error("test fixture old_note_path is not an array");
    }
    Object.defineProperty(path, "extra", {
      enumerable: true,
      value: field(999n),
    });

    expect(() => parseStandardWitnessDto("withdraw", raw)).toThrowError(
      expect.objectContaining({
        code: "UNEXPECTED_PROPERTY",
        path: "$.old_note_path.extra",
      }),
    );
  });

  it("rejects oversized dense Merkle paths before reflecting their entries", () => {
    const raw = jsonClone(RAW_WITNESSES.withdraw);
    const densePath = Array.from({ length: 1_000_000 }, () => field(1n));
    mutableRecord(raw, "$")["old_note_path"] = densePath;

    expect(() => parseStandardWitnessDto("withdraw", raw)).toThrowError(
      expect.objectContaining({
        code: "INVALID_MERKLE_PATH",
        path: "$.old_note_path",
      }),
    );

    let ownKeyCalls = 0;
    let entryDescriptorCalls = 0;
    const target = Array.from({ length: 33 }, () => field(1n));
    const countedPath = new Proxy(target, {
      ownKeys: () => {
        ownKeyCalls += 1;
        return Reflect.ownKeys(target);
      },
      getOwnPropertyDescriptor: (array, key) => {
        if (key !== "length") {
          entryDescriptorCalls += 1;
        }
        return Reflect.getOwnPropertyDescriptor(array, key);
      },
    });
    mutableRecord(raw, "$")["old_note_path"] = countedPath;

    expect(() => parseStandardWitnessDto("withdraw", raw)).toThrowError(
      expect.objectContaining({ code: "INVALID_MERKLE_PATH" }),
    );
    expect(ownKeyCalls).toBe(0);
    expect(entryDescriptorCalls).toBe(0);
  });

  it("rejects malformed bounded decimals at their witness paths", () => {
    const cases = [
      ["withdraw", "withdraw_value", "340282366920938463463374607431768211456"],
      ["withdraw", "old_note_index", "4294967296"],
      ["public_claim", "current_timestamp", "18446744073709551616"],
      ["public_claim", "timelock", "01"],
    ] as const;

    for (const [circuit, property, invalid] of cases) {
      const raw = jsonClone(RAW_WITNESSES[circuit]);
      mutableRecord(raw, "$")[property] = invalid;
      expect(() => parseStandardWitnessDto(circuit, raw)).toThrowError(
        expect.objectContaining({ path: `$.${property}` }),
      );
    }
  });
});

describe("Noir input conversion", () => {
  it("rejects unsupported and hostile circuit arguments without coercion", () => {
    const depositWitness = parseStandardWitnessDto(
      "deposit",
      RAW_WITNESSES.deposit,
    );
    expect(() =>
      standardWitnessDtoToNoirInput(
        "bogus" as StandardCircuitId,
        depositWitness,
      ),
    ).toThrowError(
      expect.objectContaining({ code: "INVALID_CIRCUIT_ID", path: "$" }),
    );

    const hostile = hostileCircuitValue();
    expect(() =>
      standardWitnessDtoToNoirInput(
        runtimeCircuit<StandardCircuitId>(hostile.value),
        depositWitness,
      ),
    ).toThrowError(
      expect.objectContaining({ code: "INVALID_CIRCUIT_ID", path: "$" }),
    );
    expect(hostile.invocations).toEqual({
      primitive: 0,
      toString: 0,
      valueOf: 0,
    });
  });

  it.each(STANDARD_CIRCUIT_IDS)(
    "reproduces the current %s input map",
    (circuit: StandardCircuitId) => {
      const parsed = parseStandardWitnessDto(circuit, RAW_WITNESSES[circuit]);
      const before = JSON.stringify(parsed);
      const noirInput = standardWitnessDtoToNoirInput(circuit, parsed);

      expect(noirInput).toEqual(EXPECTED_NOIR_INPUTS[circuit]);
      expect(new Set(Object.keys(noirInput))).toEqual(
        new Set(NOIR_KEYS[circuit]),
      );
      expect(Object.getPrototypeOf(noirInput)).toBe(Object.prototype);
      expect(JSON.stringify(parsed)).toBe(before);
      expect(standardWitnessDtoToNoirInput(circuit, parsed)).not.toBe(
        noirInput,
      );
    },
  );

  it("returns fresh nested notes, points, and ordered paths", () => {
    const transfer = parseStandardWitnessDto(
      "transfer",
      RAW_WITNESSES.transfer,
    );
    const transferInput = standardWitnessDtoToNoirInput("transfer", transfer);
    expect(transferInput.old_note).not.toBe(transfer.old_note);
    expect(transferInput.recipient_spend_pub).not.toBe(
      transfer.recipient_spend_pub,
    );
    expect(transferInput.old_note_path).not.toBe(transfer.old_note_path);
    expect(transferInput.old_note_path).toEqual(transfer.old_note_path);
  });
});

const PROOF_JSON_FIXTURES = [
  [
    "deposit",
    JSON.stringify(
      rawProofEnvelope("deposit", PUBLIC_INPUT_WIDTHS.deposit, "0x00", 1n),
    ),
  ],
  [
    "withdraw",
    JSON.stringify(
      rawProofEnvelope("withdraw", PUBLIC_INPUT_WIDTHS.withdraw, "0x01", 2n),
    ),
  ],
  [
    "transfer",
    JSON.stringify(
      rawProofEnvelope("transfer", PUBLIC_INPUT_WIDTHS.transfer, "0x02", 3n),
    ),
  ],
  [
    "split",
    JSON.stringify(
      rawProofEnvelope("split", PUBLIC_INPUT_WIDTHS.split, "0x03", 4n),
    ),
  ],
  [
    "join",
    JSON.stringify(
      rawProofEnvelope("join", PUBLIC_INPUT_WIDTHS.join, "0x04", 5n),
    ),
  ],
  [
    "public_claim",
    JSON.stringify(
      rawProofEnvelope(
        "public_claim",
        PUBLIC_INPUT_WIDTHS.public_claim,
        "0x05",
        6n,
      ),
    ),
  ],
] as const satisfies readonly (readonly [StandardCircuitId, string])[];

describe("proof envelope parsing", () => {
  it.each(PROOF_JSON_FIXTURES)(
    "parses the literal %s proof envelope",
    (circuit: StandardCircuitId, json: string) => {
      const parsed = parseProofEnvelope(circuit, JSON.parse(json) as unknown);
      const typed: ProofEnvelope<typeof circuit> = parsed;
      expect(new Set(Object.keys(typed))).toEqual(
        new Set(["circuit_id", "proof", "public_inputs"]),
      );
      expect(typed.circuit_id).toBe(circuit);
      expect(typed.public_inputs).toHaveLength(PUBLIC_INPUT_WIDTHS[circuit]);
      expect(
        parseProofEnvelope(
          circuit,
          JSON.parse(JSON.stringify(typed)) as unknown,
        ),
      ).toEqual(typed);
    },
  );

  it("rejects unsupported and hostile circuit values without coercion", () => {
    const depositEnvelope = rawProofEnvelope(
      "deposit",
      PUBLIC_INPUT_WIDTHS.deposit,
    );
    expect(() =>
      parseProofEnvelope("bogus" as CircuitId, {
        ...depositEnvelope,
        circuit_id: "bogus",
      }),
    ).toThrowError(
      expect.objectContaining({ code: "INVALID_CIRCUIT_ID", path: "$" }),
    );

    const expectedHostile = hostileCircuitValue();
    expect(() =>
      parseProofEnvelope(
        runtimeCircuit<CircuitId>(expectedHostile.value),
        depositEnvelope,
      ),
    ).toThrowError(
      expect.objectContaining({ code: "INVALID_CIRCUIT_ID", path: "$" }),
    );
    expect(expectedHostile.invocations).toEqual({
      primitive: 0,
      toString: 0,
      valueOf: 0,
    });

    const discriminatorHostile = hostileCircuitValue();
    expect(() =>
      parseProofEnvelope("deposit", {
        ...depositEnvelope,
        circuit_id: discriminatorHostile.value,
      }),
    ).toThrowError(
      expect.objectContaining({
        code: "INVALID_CIRCUIT_ID",
        path: "$.circuit_id",
      }),
    );
    expect(discriminatorHostile.invocations).toEqual({
      primitive: 0,
      toString: 0,
      valueOf: 0,
    });
  });

  it("enforces every canonical circuit public-input width", () => {
    const repositoryRoot = fileURLToPath(
      new URL("../../../../", import.meta.url),
    );
    const sourceWidths: Partial<Record<CircuitId, number>> = {};
    for (const [circuit, filename] of Object.entries(VERIFIER_SOURCES)) {
      const source = readFileSync(
        `${repositoryRoot}packages/evm-contracts/contracts/verifiers/${filename}`,
        "utf8",
      );
      const match = /REAL_NUMBER_PUBLIC_INPUTS\s*=\s*(\d+);/.exec(source);
      if (match?.[1] === undefined) {
        throw new Error(`${filename} has no public-input width`);
      }
      sourceWidths[circuit as CircuitId] = Number(match[1]);
    }
    const intentSource = readFileSync(
      `${repositoryRoot}packages/circuits/kage/kage_lib/src/lib.nr`,
      "utf8",
    );
    const intentMatch = /INTENT_PI_LEN:\s*u32\s*=\s*(\d+);/.exec(intentSource);
    if (intentMatch?.[1] === undefined) {
      throw new Error("kage_lib has no intent public-input width");
    }
    sourceWidths.swap_intent = Number(intentMatch[1]);
    expect(sourceWidths).toEqual(PUBLIC_INPUT_WIDTHS);

    for (const circuit of CIRCUIT_IDS) {
      const width = sourceWidths[circuit];
      if (width === undefined) {
        throw new Error(`${circuit} has no canonical public-input width`);
      }
      expect(() =>
        parseProofEnvelope(circuit, rawProofEnvelope(circuit, width)),
      ).not.toThrow();
      expect(() =>
        parseProofEnvelope(circuit, rawProofEnvelope(circuit, width - 1)),
      ).toThrowError(
        expect.objectContaining({
          code: "INVALID_OBJECT",
          path: "$.public_inputs",
        }),
      );
      expect(() =>
        parseProofEnvelope(circuit, rawProofEnvelope(circuit, width + 1)),
      ).toThrowError(
        expect.objectContaining({
          code: "INVALID_OBJECT",
          path: "$.public_inputs",
        }),
      );
    }
  });

  it("rejects another circuit and a verified property", () => {
    const envelope = JSON.parse(PROOF_JSON_FIXTURES[0][1]) as Record<
      string,
      unknown
    >;
    envelope["circuit_id"] = "withdraw";
    expect(() => parseProofEnvelope("deposit", envelope)).toThrowError(
      expect.objectContaining({
        code: "INVALID_CIRCUIT_ID",
        path: "$.circuit_id",
      }),
    );

    envelope["circuit_id"] = "deposit";
    envelope["verified"] = true;
    expect(() => parseProofEnvelope("deposit", envelope)).toThrowError(
      expect.objectContaining({
        code: "UNEXPECTED_PROPERTY",
        path: "$.verified",
      }),
    );
  });

  it("rejects inherited, accessor, trapped, and revoked envelopes", () => {
    const canonical = JSON.parse(PROOF_JSON_FIXTURES[0][1]) as Record<
      string,
      unknown
    >;
    const inherited = Object.assign(
      Object.create({ inherited: true }) as object,
      canonical,
    );
    expect(() => parseProofEnvelope("deposit", inherited)).toThrowError(
      expect.objectContaining({ code: "INVALID_OBJECT", path: "$" }),
    );

    let invoked = false;
    const accessor = { ...canonical };
    Object.defineProperty(accessor, "proof", {
      enumerable: true,
      get: () => {
        invoked = true;
        return "0x00";
      },
    });
    expect(() => parseProofEnvelope("deposit", accessor)).toThrowError(
      expect.objectContaining({ code: "INVALID_OBJECT", path: "$.proof" }),
    );
    expect(invoked).toBe(false);

    const trapped = new Proxy(canonical, {
      ownKeys: () => {
        throw new Error("hostile envelope trap");
      },
    });
    expect(() => parseProofEnvelope("deposit", trapped)).toThrowError(
      expect.objectContaining({ code: "INVALID_OBJECT", path: "$" }),
    );

    const { proxy, revoke } = Proxy.revocable(canonical, {});
    revoke();
    expect(() => parseProofEnvelope("deposit", proxy)).toThrowError(
      expect.objectContaining({ code: "INVALID_OBJECT", path: "$" }),
    );
  });

  it("rejects malformed proof bytes and indexed public inputs", () => {
    const malformedProof = JSON.parse(PROOF_JSON_FIXTURES[0][1]) as Record<
      string,
      unknown
    >;
    malformedProof["proof"] = "0x0";
    expect(() => parseProofEnvelope("deposit", malformedProof)).toThrowError(
      expect.objectContaining({
        code: "INVALID_BYTES_HEX",
        path: "$.proof",
      }),
    );

    const malformedInput = JSON.parse(PROOF_JSON_FIXTURES[0][1]) as Record<
      string,
      unknown
    >;
    const malformedPublicInputs = Array.from(
      { length: PUBLIC_INPUT_WIDTHS.deposit },
      (_, index) => field(BigInt(index + 1)),
    );
    malformedPublicInputs[1] = "0x01";
    malformedInput["public_inputs"] = malformedPublicInputs;
    expect(() => parseProofEnvelope("deposit", malformedInput)).toThrowError(
      expect.objectContaining({
        code: "INVALID_FIELD_HEX",
        path: "$.public_inputs[1]",
      }),
    );
  });

  it("rejects accessor and trapped public-input arrays", () => {
    const accessorEnvelope = JSON.parse(PROOF_JSON_FIXTURES[0][1]) as Record<
      string,
      unknown
    >;
    const accessorInputs = Array.from(
      { length: PUBLIC_INPUT_WIDTHS.deposit },
      (_, index) => field(BigInt(index + 1)),
    );
    let invoked = false;
    Object.defineProperty(accessorInputs, "0", {
      enumerable: true,
      get: () => {
        invoked = true;
        return field(1n);
      },
    });
    accessorEnvelope["public_inputs"] = accessorInputs;
    expect(() => parseProofEnvelope("deposit", accessorEnvelope)).toThrowError(
      expect.objectContaining({
        code: "INVALID_OBJECT",
        path: "$.public_inputs[0]",
      }),
    );
    expect(invoked).toBe(false);

    const trappedEnvelope = JSON.parse(PROOF_JSON_FIXTURES[0][1]) as Record<
      string,
      unknown
    >;
    trappedEnvelope["public_inputs"] = new Proxy(
      Array.from({ length: PUBLIC_INPUT_WIDTHS.deposit }, (_, index) =>
        field(BigInt(index + 1)),
      ),
      {
        ownKeys: () => {
          throw new Error("hostile public input trap");
        },
      },
    );
    expect(() => parseProofEnvelope("deposit", trappedEnvelope)).toThrowError(
      expect.objectContaining({
        code: "INVALID_OBJECT",
        path: "$.public_inputs",
      }),
    );
  });

  it("rejects sparse public-input arrays before walking advertised length", () => {
    const envelope = JSON.parse(PROOF_JSON_FIXTURES[0][1]) as Record<
      string,
      unknown
    >;
    envelope["public_inputs"] = new Array(0xffffffff);

    expect(() => parseProofEnvelope("deposit", envelope)).toThrowError(
      expect.objectContaining({
        code: "INVALID_OBJECT",
        path: "$.public_inputs",
      }),
    );
  });

  it("rejects oversized dense public inputs before reflecting entries", () => {
    const envelope = rawProofEnvelope("deposit", PUBLIC_INPUT_WIDTHS.deposit);
    envelope.public_inputs = Array.from({ length: 1_000_000 }, () => field(1n));
    expect(() => parseProofEnvelope("deposit", envelope)).toThrowError(
      expect.objectContaining({
        code: "INVALID_OBJECT",
        path: "$.public_inputs",
      }),
    );

    let ownKeyCalls = 0;
    let entryDescriptorCalls = 0;
    const target = Array.from({ length: PUBLIC_INPUT_WIDTHS.deposit + 1 }, () =>
      field(1n),
    );
    envelope.public_inputs = new Proxy(target, {
      ownKeys: () => {
        ownKeyCalls += 1;
        return Reflect.ownKeys(target);
      },
      getOwnPropertyDescriptor: (array, key) => {
        if (key !== "length") {
          entryDescriptorCalls += 1;
        }
        return Reflect.getOwnPropertyDescriptor(array, key);
      },
    });
    expect(() => parseProofEnvelope("deposit", envelope)).toThrowError(
      expect.objectContaining({ code: "INVALID_OBJECT" }),
    );
    expect(ownKeyCalls).toBe(0);
    expect(entryDescriptorCalls).toBe(0);
  });
});
