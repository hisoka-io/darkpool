import { parseFieldHex } from "@hisoka/howl-protocol";
import type { DerivedEph } from "../types/ephemeral.js";
import {
  toStandardWitnessDto,
  type DepositWitness,
  type WithdrawWitness,
} from "./protocol.js";

declare const deposit: DepositWitness;
declare const withdraw: WithdrawWitness;

toStandardWitnessDto("deposit", deposit);

// @ts-expect-error wrong native witness for circuit
toStandardWitnessDto("deposit", withdraw);

// @ts-expect-error serialized field has no derivation provenance
const forged: DerivedEph = parseFieldHex(
  "0x0000000000000000000000000000000000000000000000000000000000000001",
);
void forged;
