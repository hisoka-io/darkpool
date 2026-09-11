import { ProtocolParseError } from "./errors.js";
import { readExactObject } from "./internal/exact-object.js";
import {
  parseAddressHexAtPath,
  parseUintDecimalAtPath,
  type AddressHex,
  type UintDecimal,
} from "./primitives.js";

declare const DEPLOYMENT_KEY_BRAND: unique symbol;

export type DeploymentKey = string & {
  readonly [DEPLOYMENT_KEY_BRAND]: true;
};

export interface DeploymentRef {
  readonly domain_version: 1;
  readonly chain_id: UintDecimal;
  readonly dark_pool: AddressHex;
  readonly deployment_block: UintDecimal;
}

const DEPLOYMENT_PROPERTIES = [
  "domain_version",
  "chain_id",
  "dark_pool",
  "deployment_block",
] as const;

export function parseDeploymentRef(value: unknown): DeploymentRef {
  const record = readExactObject(value, DEPLOYMENT_PROPERTIES, "$");

  const domainVersion = record.domain_version;
  if (domainVersion !== 1) {
    throw new ProtocolParseError(
      "INVALID_OBJECT",
      "$.domain_version",
      "domain_version must be numeric 1",
    );
  }

  return {
    domain_version: domainVersion,
    chain_id: parseUintDecimalAtPath(record.chain_id, "$.chain_id"),
    dark_pool: parseAddressHexAtPath(record.dark_pool, "$.dark_pool"),
    deployment_block: parseUintDecimalAtPath(
      record.deployment_block,
      "$.deployment_block",
    ),
  };
}

export function deploymentKey(ref: DeploymentRef): DeploymentKey {
  return `hisoka.howl.deployment.v1:${ref.chain_id}:${ref.dark_pool}:${ref.deployment_block}` as DeploymentKey;
}
