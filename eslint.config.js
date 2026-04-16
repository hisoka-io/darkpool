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
      "no-console": [
        "error",
        { allow: ["warn", "error", "debug", "info", "log"] },
      ],
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
      "**/scripts/**",
      "**/hardhat.config.ts",
    ],
    rules: { "no-console": "off" },
  },
);
