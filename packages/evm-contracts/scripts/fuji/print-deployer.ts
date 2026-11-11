/** Prints the configured deployer's address (never its key) as the last output line. */

import { ethers } from "hardhat";

async function main(): Promise<void> {
  const signers = await ethers.getSigners();
  if (signers.length === 0) {
    throw new Error(
      "no deployer configured for this network; set FUJI_DEPLOYER_KEY_FILE.",
    );
  }
  console.log(signers[0].address);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
