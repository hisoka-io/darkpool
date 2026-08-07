import tseslint from "typescript-eslint";

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
      "@typescript-eslint/no-explicit-any": "error",
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
);
