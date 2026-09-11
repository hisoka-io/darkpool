import { createRequire } from "node:module";

const ROOT_EXPORTS = [
  "BN254_FR_MODULUS",
  "ProtocolParseError",
  "deploymentKey",
  "fieldHexFromBigInt",
  "parseAddressHex",
  "parseBytesHex",
  "parseDeploymentRef",
  "parseFieldHex",
  "parseOperationId",
  "parseProofEnvelope",
  "parseUint128Decimal",
  "parseUint32Decimal",
  "parseUint64Decimal",
  "parseUintDecimal",
].sort();

const PROVING_EXPORTS = [
  "CIRCUIT_IDS",
  "STANDARD_CIRCUIT_IDS",
  "parseCircuitId",
  "parseStandardWitnessDto",
  "standardWitnessDtoToNoirInput",
].sort();

function assertRootExports(moduleFormat, packageModule) {
  const actualExports = Object.keys(packageModule).sort();
  if (JSON.stringify(actualExports) !== JSON.stringify(ROOT_EXPORTS)) {
    throw new Error(
      `${moduleFormat} root exports ${actualExports.join(", ")}; expected ${ROOT_EXPORTS.join(", ")}`,
    );
  }

  for (const exportName of ROOT_EXPORTS) {
    if (
      exportName !== "BN254_FR_MODULUS" &&
      typeof packageModule[exportName] !== "function"
    ) {
      throw new Error(
        `${moduleFormat} root export ${exportName} is missing or is not a function`,
      );
    }
  }

  const modulus = packageModule.BN254_FR_MODULUS;
  if (
    modulus !==
    "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001"
  ) {
    throw new Error(
      `${moduleFormat} root export BN254_FR_MODULUS is missing or incorrect`,
    );
  }
}

function assertProvingExports(moduleFormat, packageModule) {
  const actualExports = Object.keys(packageModule).sort();
  if (JSON.stringify(actualExports) !== JSON.stringify(PROVING_EXPORTS)) {
    throw new Error(
      `${moduleFormat} proving exports ${actualExports.join(", ")}; expected ${PROVING_EXPORTS.join(", ")}`,
    );
  }

  for (const exportName of PROVING_EXPORTS) {
    if (
      exportName !== "CIRCUIT_IDS" &&
      exportName !== "STANDARD_CIRCUIT_IDS" &&
      typeof packageModule[exportName] !== "function"
    ) {
      throw new Error(
        `${moduleFormat} proving export ${exportName} is missing or is not a function`,
      );
    }
  }
}

function assertProtocolFailure(moduleFormat, invoke, expectedPath) {
  try {
    invoke();
  } catch (error) {
    if (
      error?.name === "ProtocolParseError" &&
      error.code === "INVALID_CIRCUIT_ID" &&
      error.path === expectedPath
    ) {
      return;
    }
    throw new Error(
      `${moduleFormat} returned the wrong circuit validation error`,
      { cause: error },
    );
  }
  throw new Error(`${moduleFormat} accepted an invalid circuit value`);
}

function hostileCircuitValue() {
  let invocations = 0;
  return {
    get invocations() {
      return invocations;
    },
    value: {
      [Symbol.toPrimitive]() {
        invocations += 1;
        throw new Error("coercion ran");
      },
      toString() {
        invocations += 1;
        throw new Error("toString ran");
      },
      valueOf() {
        invocations += 1;
        throw new Error("valueOf ran");
      },
    },
  };
}

function assertRuntimeCircuitValidation(moduleFormat, root, proving) {
  const envelope = {
    circuit_id: "bogus",
    proof: "0x",
    public_inputs: [],
  };
  assertProtocolFailure(
    `${moduleFormat} proof unsupported string`,
    () => root.parseProofEnvelope("bogus", envelope),
    "$",
  );

  const expectedHostile = hostileCircuitValue();
  assertProtocolFailure(
    `${moduleFormat} proof hostile expected circuit`,
    () => root.parseProofEnvelope(expectedHostile.value, envelope),
    "$",
  );
  if (expectedHostile.invocations !== 0) {
    throw new Error(
      `${moduleFormat} proof parser coerced its circuit argument`,
    );
  }

  const discriminatorHostile = hostileCircuitValue();
  assertProtocolFailure(
    `${moduleFormat} proof hostile discriminator`,
    () =>
      root.parseProofEnvelope("deposit", {
        ...envelope,
        circuit_id: discriminatorHostile.value,
      }),
    "$.circuit_id",
  );
  if (discriminatorHostile.invocations !== 0) {
    throw new Error(`${moduleFormat} proof parser coerced its discriminator`);
  }

  assertProtocolFailure(
    `${moduleFormat} proof supported mismatch`,
    () =>
      root.parseProofEnvelope("deposit", {
        ...envelope,
        circuit_id: "withdraw",
      }),
    "$.circuit_id",
  );

  for (const [entrypoint, invoke] of [
    [
      "witness parser",
      (circuit) => proving.parseStandardWitnessDto(circuit, {}),
    ],
    [
      "Noir converter",
      (circuit) => proving.standardWitnessDtoToNoirInput(circuit, {}),
    ],
  ]) {
    assertProtocolFailure(
      `${moduleFormat} ${entrypoint} unsupported string`,
      () => invoke("bogus"),
      "$",
    );
    const hostile = hostileCircuitValue();
    assertProtocolFailure(
      `${moduleFormat} ${entrypoint} hostile circuit`,
      () => invoke(hostile.value),
      "$",
    );
    if (hostile.invocations !== 0) {
      throw new Error(`${moduleFormat} ${entrypoint} coerced its circuit`);
    }
  }
}

async function main() {
  const esmModule = await import("@hisoka/howl-protocol");
  const esmProving = await import("@hisoka/howl-protocol/proving");
  const require = createRequire(import.meta.url);
  const cjsModule = require("@hisoka/howl-protocol");
  const cjsProving = require("@hisoka/howl-protocol/proving");

  assertRootExports("ESM", esmModule);
  assertRootExports("CJS", cjsModule);
  assertProvingExports("ESM", esmProving);
  assertProvingExports("CJS", cjsProving);
  assertRuntimeCircuitValidation("ESM", esmModule, esmProving);
  assertRuntimeCircuitValidation("CJS", cjsModule, cjsProving);
  console.log(
    `howl-protocol ESM and CJS exports verified: root ${ROOT_EXPORTS.length}, proving ${PROVING_EXPORTS.length}`,
  );
}

try {
  await main();
} catch (error) {
  console.error("howl-protocol export smoke failed", error);
  process.exitCode = 1;
}
