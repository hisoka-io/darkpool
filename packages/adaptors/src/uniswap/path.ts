import { solidityPacked } from "ethers";
import { AdaptorError } from "../errors.js";

export function encodePath(tokens: string[], fees: number[]): string {
  if (tokens.length !== fees.length + 1) {
    throw new AdaptorError(
      "Invalid path: tokens length must be fees length + 1",
    );
  }

  const types: string[] = [];
  const values: (number | string)[] = [];

  for (let i = 0; i < fees.length; i++) {
    types.push("address", "uint24");
    values.push(tokens[i]!, fees[i]!);
  }
  types.push("address");
  values.push(tokens[tokens.length - 1]!);

  return solidityPacked(types, values);
}
