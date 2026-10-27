import { UltraHonkBackend } from "@aztec/bb.js";
import { CompiledCircuit } from "@noir-lang/noir_js";
import { Buffer } from "node:buffer";
import { circuit as intentCircuit } from "../../generated/swap_intent_circuit.js";
import { SwapSettleInputs, SwapIntentProof, ProofData } from "../../types.js";
import { ProofError } from "../../errors.js";
import { ensureBBInitialized } from "../../prover-base.js";
import { INTENT_VK_HASH } from "../../config.js";
import { assertNativeBb, proveSwapSettleNative } from "./settleNative.js";

export function nativeBbAvailable(): boolean {
  try {
    assertNativeBb();
    return true;
  } catch {
    return false;
  }
}

/** The taker's intent proof is not under the pinned swap_intent key; swap_settle would reject it after a full prove. */
export class IntentVkMismatchError extends ProofError {
  constructor(detail: string) {
    super("swap_settle", `intent proof is not a swap_intent proof: ${detail}`);
    this.name = "IntentVkMismatchError";
  }
}

const FIELD_HEX = /^0x[0-9a-fA-F]{1,64}$/;

function fieldOf(word: string): bigint | null {
  return FIELD_HEX.test(word) ? BigInt(word) : null;
}

let pinnedIntentVk: Promise<readonly bigint[]> | undefined;

function pinnedIntentVkFields(): Promise<readonly bigint[]> {
  pinnedIntentVk ??= (async () => {
    const backend = new UltraHonkBackend(
      (intentCircuit as CompiledCircuit).bytecode,
      await ensureBBInitialized(),
    );
    const vk = await backend.getVerificationKey({
      verifierTarget: "noir-recursive",
    });
    const fields: bigint[] = [];
    for (let i = 0; i < vk.length; i += 32) {
      fields.push(
        BigInt("0x" + Buffer.from(vk.subarray(i, i + 32)).toString("hex")),
      );
    }
    return fields;
  })().catch((err: unknown) => {
    pinnedIntentVk = undefined;
    throw err;
  });
  return pinnedIntentVk;
}

/** The vkHash a taker reports is only a claim, so the key itself is compared word by word as well. */
async function assertPinnedIntentVk(intent: SwapIntentProof): Promise<void> {
  if (fieldOf(intent.vkHash) !== BigInt(INTENT_VK_HASH)) {
    throw new IntentVkMismatchError(
      `vkHash ${intent.vkHash} != pinned ${INTENT_VK_HASH}`,
    );
  }
  const pinned = await pinnedIntentVkFields();
  if (intent.vkAsFields.length !== pinned.length) {
    throw new IntentVkMismatchError(
      `verification key has ${intent.vkAsFields.length} fields, pinned key has ${pinned.length}`,
    );
  }
  const drift = intent.vkAsFields.findIndex(
    (word, i) => fieldOf(word) !== pinned[i],
  );
  if (drift !== -1) {
    throw new IntentVkMismatchError(
      `verification key field ${drift} differs from the pinned swap_intent key`,
    );
  }
}

export async function proveSwapSettle(
  inputs: SwapSettleInputs,
): Promise<ProofData> {
  await assertPinnedIntentVk(inputs.intent);
  return proveSwapSettleNative(inputs);
}
