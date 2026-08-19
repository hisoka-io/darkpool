// `@aztec/foundation` imports `inspect` from node's `util` in fields.js, buffer32.js, buffer16.js,
// eth-address.js and bls12_point.js, in every case ONLY to implement `[inspect.custom]()` pretty-printing.
// Nothing functional reads it, so a browser build aliases `util` here rather than shipping node's.
export const inspect = Object.assign(() => "[object]", {
  custom: Symbol.for("nodejs.util.inspect.custom"),
});
export default { inspect };
