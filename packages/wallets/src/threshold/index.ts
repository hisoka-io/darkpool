// Threshold-compliance toolkit (`@hisoka/wallets/threshold`): a (t,n) committee threshold-decrypts notes
// (uniform CEK = (c*eph_pub).x) and traces chains, without ever reconstructing the compliance secret c. Also
// carries `chainTrace` (committee deanonymization tooling) and the GJKR anti-bias committee-DKG reference.
// Built on the shared tss primitives. The simulated single-process DKG driver (unsafe-sim) is NOT exported.

export * from "./compliance.js";
export * from "./chainTrace.js";
export * from "../tss/gjkr.js";
