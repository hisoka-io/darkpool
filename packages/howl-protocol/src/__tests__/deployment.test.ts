import { describe, expect, it } from "vitest";

import {
  ProtocolParseError,
  deploymentKey,
  parseDeploymentRef,
} from "../index.js";

const DEPLOYMENT = {
  domain_version: 1,
  chain_id: "43114",
  dark_pool: "0x1111111111111111111111111111111111111111",
  deployment_block: "7",
};

describe("parseDeploymentRef", () => {
  it("parses a canonical deployment and pins its identity", () => {
    const deployment = parseDeploymentRef(DEPLOYMENT);

    expect(deployment).toEqual(DEPLOYMENT);
    expect(parseDeploymentRef(JSON.parse(JSON.stringify(deployment)))).toEqual(
      deployment,
    );
    expect(deploymentKey(deployment)).toBe(
      "hisoka.howl.deployment.v1:43114:0x1111111111111111111111111111111111111111:7",
    );
  });

  it("accepts a null-prototype record with exact own properties", () => {
    const deployment = Object.assign(Object.create(null) as object, DEPLOYMENT);
    expect(parseDeploymentRef(deployment)).toEqual(DEPLOYMENT);
  });

  it.each([
    null,
    [],
    "deployment",
    Object.create({ ...DEPLOYMENT }) as object,
    Object.assign(Object.create({ inherited: true }) as object, DEPLOYMENT),
  ])("rejects non-record or unsafe-prototype input %#", (value: unknown) => {
    expect(() => parseDeploymentRef(value)).toThrowError(
      expect.objectContaining({ code: "INVALID_OBJECT", path: "$" }),
    );
  });

  it.each([
    {},
    { ...DEPLOYMENT, chain_id: undefined },
    { ...DEPLOYMENT, extra: "value" },
  ])(
    "rejects missing, invalid, or extra own properties %#",
    (value: unknown) => {
      expect(() => parseDeploymentRef(value)).toThrow(ProtocolParseError);
    },
  );

  it.each([0, 2, "1", null])(
    "rejects domain_version %#",
    (domainVersion: unknown) => {
      expect(() =>
        parseDeploymentRef({
          ...DEPLOYMENT,
          domain_version: domainVersion,
        }),
      ).toThrowError(
        expect.objectContaining({
          code: "INVALID_OBJECT",
          path: "$.domain_version",
        }),
      );
    },
  );

  it.each([
    ["chain_id", "+1"],
    ["chain_id", "01"],
    ["deployment_block", "-1"],
    ["deployment_block", "1.0"],
    ["dark_pool", `0x${"AA".repeat(20)}`],
  ] as const)("rejects invalid %s", (key: string, value: string) => {
    expect(() => parseDeploymentRef({ ...DEPLOYMENT, [key]: value })).toThrow(
      ProtocolParseError,
    );
  });

  it("rejects inherited required fields", () => {
    const value = Object.create({ chain_id: DEPLOYMENT.chain_id }) as Record<
      string,
      unknown
    >;
    value.domain_version = DEPLOYMENT.domain_version;
    value.dark_pool = DEPLOYMENT.dark_pool;
    value.deployment_block = DEPLOYMENT.deployment_block;

    expect(() => parseDeploymentRef(value)).toThrowError(
      expect.objectContaining({ code: "INVALID_OBJECT", path: "$" }),
    );
  });

  it("rejects symbol properties", () => {
    const value = { ...DEPLOYMENT, [Symbol("extra")]: true };
    expect(() => parseDeploymentRef(value)).toThrowError(
      expect.objectContaining({ code: "UNEXPECTED_PROPERTY", path: "$" }),
    );
  });

  it("rejects accessor properties without invoking them", () => {
    let invoked = false;
    const value = { ...DEPLOYMENT };
    Object.defineProperty(value, "chain_id", {
      enumerable: true,
      get: () => {
        invoked = true;
        return DEPLOYMENT.chain_id;
      },
    });

    expect(() => parseDeploymentRef(value)).toThrowError(
      expect.objectContaining({ code: "INVALID_OBJECT", path: "$.chain_id" }),
    );
    expect(invoked).toBe(false);
  });

  it("fails closed when own properties cannot be inspected", () => {
    let invoked = false;
    const target = { ...DEPLOYMENT };
    Object.defineProperty(target, "chain_id", {
      enumerable: true,
      get: () => {
        invoked = true;
        return DEPLOYMENT.chain_id;
      },
    });
    const descriptorTrap = new Proxy(target, {
      getOwnPropertyDescriptor: () => {
        throw new Error("hostile descriptor trap");
      },
    });
    const { proxy: revokedProxy, revoke } = Proxy.revocable(target, {});
    revoke();

    for (const value of [descriptorTrap, revokedProxy]) {
      expect(() => parseDeploymentRef(value)).toThrowError(
        expect.objectContaining({ code: "INVALID_OBJECT", path: "$" }),
      );
    }
    expect(invoked).toBe(false);
  });
});
