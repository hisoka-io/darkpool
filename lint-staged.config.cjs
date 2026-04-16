module.exports = {
  "**/*.{ts,tsx}": ["eslint --fix"],
  "**/*.sol": ["solhint --fix"],
  "**/*.{js,cjs,mjs,json,md}": ["prettier --write"],
  "*": (filenames) => {
    const ignoredPaths = [
      "packages/prover/src/generated/",
      "packages/circuits/target/",
      "pnpm-lock.yaml",
    ];

    const filesToScan = filenames.filter((file) => {
      return !ignoredPaths.some((ignored) => file.includes(ignored));
    });

    if (filesToScan.length === 0) {
      return [];
    }

    return `trufflehog filesystem --no-update --fail --exclude-paths .trufflehog-ignore-paths ${filesToScan.join(" ")}`;
  },
};
