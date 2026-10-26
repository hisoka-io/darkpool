import tseslint from "typescript-eslint";
import root from "../../eslint.config.js";

const FORBIDDEN_EDGES = [
  {
    group: ["@hisoka/prover", "@hisoka/prover/*"],
    message:
      "Proving is an injected ProverPort; the prover pulls bb.js and process.env into every embedder.",
  },
  {
    group: ["evm-contracts", "evm-contracts/*", "**/evm-contracts/**"],
    message:
      "evm-contracts is CommonJS and Hardhat; decode with the fragments in src/abi.ts.",
  },
  {
    group: ["@hisoka-io/nox-client", "@hisoka-io/nox-client/*"],
    message:
      "The Nox submitter is duck-typed until the package with executePaid is published.",
  },
  {
    group: ["@hisoka/howl-e2e", "@hisoka/pss-integration"],
    message: "Test packages depend on the runtime, never the reverse.",
  },
  {
    group: ["@hisoka-io/raven-*", "@raven/*", "raven-*"],
    message:
      "Raven's client is Raven-owned and unpublished; its adapter is structural.",
  },
  {
    group: ["@hisoka/wallets/reference", "@hisoka/wallets/unsafe-sim"],
    message:
      "The reference layer and the simulation drivers are not production code.",
  },
];

export default tseslint.config(
  ...root,
  {
    files: ["src/**/*.ts"],
    ignores: ["src/__tests__/**"],
    rules: {
      "@typescript-eslint/no-explicit-any": "error",
      "@typescript-eslint/no-non-null-assertion": "error",
      "no-restricted-imports": ["error", { patterns: FORBIDDEN_EDGES }],
    },
  },
  {
    files: ["src/__tests__/**/*.ts"],
    rules: {
      "@typescript-eslint/no-explicit-any": "error",
    },
  },
);
