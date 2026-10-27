import { FunctionFragment } from "ethers";

/** Field order MUST match the Solidity `BundleExecutor.BundleCall` struct, or the intent hash diverges. */
export const BUNDLE_CALL_TUPLE =
  "tuple(address target, bytes data, uint256 value, bool requireSuccess, address approveToken, uint256 approveAmount, uint256 gasLimit, uint256 returnDataLimit)[]";

export const BUNDLE_EXECUTE_FRAGMENT = FunctionFragment.from(
  `function execute(bytes proof, bytes32[] publicInputs, ${BUNDLE_CALL_TUPLE} boundCalls, uint256 deadline, address[] trackedAssets, address[] recipients)`,
);
