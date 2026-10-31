import { Interface } from "ethers";

/**
 * The DarkPool surface the runtime reads, as human-readable fragments. Inlined rather than imported from
 * evm-contracts (CommonJS, Hardhat). Event layouts are frozen with the pool; `EVENT_TOPICS` pins them.
 */
export const DARK_POOL_FRAGMENTS = [
  "function getNextLeafIndex() view returns (uint256)",
  "function getCurrentRoot() view returns (bytes32)",
  "function isKnownRoot(bytes32 _root) view returns (bool)",
  "function complianceKey() view returns (uint256 x, uint256 y, uint256 version)",
  "function deposit(bytes _proof, bytes32[] _publicInputs)",
  "function withdraw(bytes _proof, bytes32[] _publicInputs)",
  "function privateTransfer(bytes _proof, bytes32[] _publicInputs)",
  "function split(bytes _proof, bytes32[] _publicInputs)",
  "function join(bytes _proof, bytes32[] _publicInputs)",
  "function publicClaim(bytes _proof, bytes32[] _publicInputs)",
  "event LeafInserted(uint256 indexed leafIndex, bytes32 leaf, bytes32 newRoot)",
  "event RootSaved(bytes32 indexed root)",
  "event NewNote(uint256 indexed leafIndex, bytes32 indexed commitment, uint256 ephemeralPK_x, bytes32[7] packedCiphertext)",
  "event NewPrivateMemo(uint256 indexed leafIndex, bytes32 indexed commitment, uint256 indexed tag, uint256 ephemeralPK_x, uint256 cekWrap, bytes32[7] packedCiphertext)",
  "event NewPublicMemo(bytes32 indexed memoId, address asset, uint256 value, uint256 timelock, uint256 salt)",
  "event NullifierSpent(bytes32 indexed nullifierHash)",
  "event PublicMemoSpent(bytes32 indexed memoId)",
  "event ComplianceKeyRotated(uint256 oldVersion, uint256 newVersion, uint256 newX, uint256 newY)",
  "event GenesisSeeded(uint256 indexed chainId, bytes32 genesisLeaf)",
  "error InvalidInputsLength()",
  "error InvalidProof()",
  "error InvalidRoot()",
  "error TimestampInvalid()",
  "error NullifierAlreadySpent()",
  "error ValueZero()",
  "error ValueTooLarge()",
  "error TimelockTooLarge()",
  "error MemoCollision()",
  "error MemoSpent()",
  "error MemoInvalid()",
  "error FeeOnTransferUnsupported()",
  "error RecipientRejectedWithdraw(address recipient)",
  "error RecipientCannotAcceptWithdraw(address recipient)",
  "error UnknownCircuitId()",
  "error VerifierHasNoCode()",
  "error VerifierUnset(uint256 circuitId)",
  "error InvalidComplianceKeyPoint()",
  "error InvalidMemoOwnerPoint()",
  "error ReentrancyGuardReentrantCall()",
  "error ComplianceKeyStale(uint256 currentVersion, uint256 currentX, uint256 currentY)",
  "error NonCanonicalField()",
  "error EnforcedPause()",
] as const;

export const DARK_POOL_INTERFACE = new Interface(DARK_POOL_FRAGMENTS);

/** The one ERC20 call the runtime makes: an exact approval of the deposit amount to the pool. */
export const ERC20_INTERFACE = new Interface([
  "function approve(address spender, uint256 amount) returns (bool)",
]);

/** topic0 of every event above, as literals so a fragment edit cannot silently move a log filter. */
export const EVENT_TOPICS = {
  LeafInserted:
    "0x2d3c13ae449947e04070bf2ac89327dc1fc56f31042172f3c9fdceb8f51c90e6",
  RootSaved:
    "0xa55369296f4adc70a8d99192608e0c4d18f10f343890264bc50b59981afdec51",
  NewNote: "0xf908f59e72bf09167999004bbfe849fd507952d06581f7e70134588458700854",
  NewPrivateMemo:
    "0x7a202c1f6029a8f736ab7bb5da53a4930c10ccb35effa9881ece389ad9bd2544",
  NewPublicMemo:
    "0x55ab54025db51da4c6f9511101ebf0e0f60cf2171427b607a142348656fe8898",
  NullifierSpent:
    "0x2d8b76eb247945151bd870d531c84c5420f53e3cb9c0ab3b350f46bb09362096",
  PublicMemoSpent:
    "0x142b563796c862a1fb294596318cb4ce9492eed8f1b25bbf2ea2aa96d9f05bb3",
  ComplianceKeyRotated:
    "0xa9279e08847efe2bd488e211363a7bc5fd413e506b6a325134cec43f64946007",
  GenesisSeeded:
    "0x707c829c9689eb6b774ddf7479ad4c494581c7b5b36237f80738895c016166d9",
} as const;

export type DarkPoolEvent = keyof typeof EVENT_TOPICS;
