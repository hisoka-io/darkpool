import { execFileSync, execSync } from "child_process";
import {
  readFileSync,
  writeFileSync,
  existsSync,
  mkdirSync,
  statSync,
} from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const NARGO_PATH = execSync("which nargo", { encoding: "utf8" }).trim();

const circuits = [
  "deposit",
  "withdraw",
  "transfer",
  "join",
  "split",
  "public_claim",
  "gas_payment",
];
const circuitsDir = resolve(__dirname, "../../circuits");
const proverDir = resolve(__dirname, "..");
const generatedDir = resolve(proverDir, "src/generated");

console.log(`--- Compiling Noir Circuits to ${generatedDir} ---`);

if (!existsSync(generatedDir)) {
  mkdirSync(generatedDir, { recursive: true });
}

for (const name of circuits) {
  process.stdout.write(`Compiling ${name}... `);
  try {
    const args = ["compile", "--package", name];
    execFileSync(NARGO_PATH, args, { cwd: circuitsDir, stdio: "pipe" });

    const artifactPath = resolve(circuitsDir, "target", `${name}.json`);
    if (!existsSync(artifactPath)) {
      throw new Error(`Artifact not found: ${artifactPath}`);
    }
    const circuitJson = JSON.parse(readFileSync(artifactPath, "utf8"));

    const tsArtifactPath = resolve(generatedDir, `${name}_circuit.ts`);
    const tsContent = `// @ts-nocheck
export const circuit = ${JSON.stringify(circuitJson, null, 2)} as const;
`;
    writeFileSync(tsArtifactPath, tsContent);

    if (!existsSync(tsArtifactPath))
      throw new Error(`Failed to write ${tsArtifactPath}`);
    const stats = statSync(tsArtifactPath);
    if (stats.size === 0) throw new Error(`File is empty: ${tsArtifactPath}`);

    console.log(`[OK] (${(stats.size / 1024).toFixed(1)} KB)`);
  } catch (error) {
    console.log(`[Error]`);
    console.error(`Failed to compile ${name}:`, error.message);
    process.exit(1);
  }
}
