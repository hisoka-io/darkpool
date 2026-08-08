import tseslint from "typescript-eslint";

// The runbook promises no per-request log line and no accountId beside a timestamp. That is true today
// only because nothing in the request path writes; this is what keeps it true.
const LOG_DISCIPLINE =
  "pss-server emits no per-request output: an accountId beside a timestamp is the correlation data the design exists not to produce.";

export default tseslint.config(
  {
    ignores: [
      "**/dist/**",
      "**/build/**",
      "**/out/**",
      "**/coverage/**",
      "**/node_modules/**",
      "packages/evm-contracts/artifacts/**",
      "packages/evm-contracts/cache/**",
      "packages/evm-contracts/typechain-types/**",
      "packages/prover/src/generated/**",
    ],
  },

  ...tseslint.configs.recommended,

  {
    rules: {
      "no-console": ["error", { allow: ["warn", "error"] }],
      "no-debugger": "error",
      "@typescript-eslint/ban-ts-comment": "off",
      "@typescript-eslint/no-explicit-any": "off",
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
      "@typescript-eslint/no-unused-expressions": [
        "error",
        {
          allowShortCircuit: true,
          allowTernary: true,
          allowTaggedTemplates: true,
        },
      ],
    },
  },

  {
    files: [
      "**/*.test.ts",
      "**/*.spec.ts",
      "**/test/**",
      "**/__tests__/**",
      "**/scripts/**",
      "**/hardhat.config.ts",
    ],
    rules: { "no-console": "off" },
  },

  // `no-explicit-any` is off repo-wide, so it has to be re-enabled per package. Scoped by glob rather
  // than repeated per block, because a new pss-* package otherwise silently opts out of it.
  {
    files: ["packages/pss-*/**/*.ts"],
    rules: { "@typescript-eslint/no-explicit-any": "error" },
  },

  // PSS holds no Howl types and no chain access. pnpm's isolated linker already makes an undeclared
  // @hisoka/* import unresolvable and tsc's rootDir rejects a relative path out of the package; this is
  // the third layer, and the only one that names the reason in the error.
  {
    files: ["packages/pss-client/**/*.ts"],
    rules: {
      "@typescript-eslint/no-explicit-any": "error",
      "no-restricted-imports": [
        "error",
        {
          patterns: [
            {
              group: ["@hisoka/*"],
              message:
                "pss-client takes k_state as 32 raw bytes and imports no Hisoka package.",
            },
          ],
        },
      ],
    },
  },
  {
    files: ["packages/pss-server/**/*.ts"],
    rules: {
      // The runbook promises no per-request log line and no accountId beside a timestamp. That is true
      // today only because nothing writes; these keep it true. main.ts is exempted below: it owns the
      // boot line and the shutdown counter snapshot, neither of which is per request.
      // Listed as restricted properties rather than through no-console, because that rule's `allow`
      // list cannot be emptied (its schema demands at least one entry) and a bare severity in flat
      // config retains the earlier options, so the repo-wide allowance for warn and error would survive.
      "no-restricted-properties": [
        "error",
        ...["stdout", "stderr"].map((stream) => ({
          object: "process",
          property: stream,
          message: LOG_DISCIPLINE,
        })),
        ...["log", "info", "warn", "error", "debug", "trace"].map((level) => ({
          object: "console",
          property: level,
          message: LOG_DISCIPLINE,
        })),
      ],
      "no-restricted-imports": [
        "error",
        {
          patterns: [
            {
              group: [
                "@hisoka/*",
                "!@hisoka/pss-client",
                "!@hisoka/pss-client/*",
              ],
              message:
                "pss-server imports the wire contract only, never a Howl package, and never reads the chain.",
            },
          ],
        },
      ],
    },
  },
  {
    files: ["packages/pss-server/src/main.ts"],
    // Owns the boot line and the shutdown counter snapshot. Neither is per request.
    rules: { "no-restricted-properties": "off" },
  },
);
