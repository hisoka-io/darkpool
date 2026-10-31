# shellcheck shell=bash disable=SC2034
# Exact test counts the CI step scripts enforce. A suite that gains, loses or skips a test fails CI until its number
# here changes in the same reviewed commit, so a dropped or skipped test cannot pass silently.

# vitest suites, by directory under packages/ (scripts/ci/test-package.sh).
declare -A VITEST_PASSED=(
  [howl-protocol]=276
  [wallets]=417
  [adaptors]=67
  [prover]=77
  [howl-e2e]=15
  [wallet-runtime]=206
  [pss-client]=206
  [pss-server]=103
)
# The prover skips are opt-in suites: the native-bb Kage gate (two tests, run by kage-native.sh) and the Kage golden
# generator (one, GEN_KAGE_GOLDEN=1).
declare -A VITEST_SKIPPED=(
  [prover]=3
)
PSS_INTEGRATION_TESTS=19
# The test plus the pss-client, pss-server, wallets, howl-protocol, wallet-runtime and adaptors builds.
PSS_INTEGRATION_TASKS=7
# Eight typecheck tasks plus the builds their ^build dependency pulls in.
TYPECHECK_TASKS=15
KAGE_NATIVE_TESTS=2

# nargo test in packages/circuits, by workspace crate (scripts/ci/circuits-test.sh).
declare -A NARGO_CRATE_TESTS=(
  [shared]=69
  [deposit]=21
  [withdraw]=30
  [transfer]=50
  [split]=40
  [join]=43
  [public_claim]=34
  [withdraw_multisig]=38
  [transfer_multisig]=55
  [split_multisig]=48
  [join_multisig]=60
  [kage_lib]=90
  [swap_intent]=1
  [swap_settle]=1
)
EDWARDS_TESTS=20
# Witness-injection harnesses under packages/prover/test-harness (scripts/run-forgery-harnesses.sh).
declare -A HARNESS_TESTS=(
  [frost-forgery]=8
  [psi-cek-forgery]=11
  [leaf-index-forgery]=7
)
# One native-bb verified proof per harness accept path.
FORGERY_VERIFIED_PROOFS=3

# evm-contracts mocha suites (scripts/ci/evm-suite.sh).
declare -A EVM_PASSING=(
  [test:fast]=689
  [test:slow]=2
)
# Gas benches in run order, each with its passing count (scripts/ci/evm-gas.sh).
GAS_BENCHES=(
  test/benchmark/Gas.bench.ts
  test/kage/KageSettlementGas.bench.ts
  test/benchmark/FrontierParity.bench.ts
)
declare -A GAS_BENCH_PASSING=(
  [test/benchmark/Gas.bench.ts]=11
  [test/kage/KageSettlementGas.bench.ts]=1
  [test/benchmark/FrontierParity.bench.ts]=1
)
FORGE_INVARIANT_TESTS=7
