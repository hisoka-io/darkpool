// esbuild `inject` target. `Fr.toBuffer()` needs Buffer, and `@aztec/foundation`'s poseidon2Hash reads
// `process.env.BB_WASM_PATH`, so both must exist as globals before the crypto core loads.
import { Buffer } from "buffer";
const process = {
  env: {},
  browser: true,
  version: "",
  versions: {},
  platform: "browser",
  nextTick: (f) => queueMicrotask(f),
};
export { Buffer, process };
