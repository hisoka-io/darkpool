// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {DarkPool} from "../../contracts/DarkPool.sol";
import {MockERC20} from "../../contracts/mocks/MockERC20.sol";
import {MockFeeOnTransferERC20} from "../../contracts/mocks/MockFeeOnTransferERC20.sol";
import {StubVerifier} from "../../contracts/mocks/StubVerifier.sol";
import {Poseidon2} from "../../contracts/Poseidon/Poseidon2.sol";
import {Field} from "../../contracts/Poseidon/Field.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

uint256 constant FEE_TOKEN_BPS = 50;

/**
 * @dev Drives every DarkPool entry point that moves value or burns a nullifier, behind a verifier that accepts
 *      unconditionally. Per-note value conservation is a circuit property and is therefore out of reach here;
 *      what is in reach is the contract's own ledger discipline, so the handler mirrors the three ERC20 sites
 *      (deposit in, publicTransfer in, withdraw out) into ghost totals the invariants reconcile against the
 *      real token balance.
 */
contract DarkPoolHandler {
    uint256 internal constant FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// @dev Canonical BabyJubJub Base8; the only point initialize() and _verifyComplianceKey() will accept here.
    uint256 internal constant BASE8_X =
        5299619240641551281634865583518297030282874472190772894086521144482721001553;
    uint256 internal constant BASE8_Y =
        16950150798460657717958625567821834550301663161624707787222815936182638968203;

    // Nullifiers and memo salts are drawn from deliberately tiny spaces so the fuzzer collides inside a single
    // run; a wide space would make a replay attempt statistically unreachable and the double-spend invariants
    // vacuous.
    uint256 internal constant NULLIFIER_SPACE = 48;
    uint256 internal constant MEMO_SALT_SPACE = 16;
    uint256 internal constant MAX_VALUE = 1e21;
    uint256 internal constant MIN_FEE_VALUE = 10_000 / FEE_TOKEN_BPS;

    address internal constant RECIPIENT_A = address(0xA11CE);
    address internal constant RECIPIENT_B = address(0xB0B);
    address internal constant RECIPIENT_C = address(0xCA11);

    DarkPool public immutable pool;
    MockERC20 public immutable tokenA;
    MockERC20 public immutable tokenB;
    MockFeeOnTransferERC20 public immutable feeToken;

    mapping(address => uint256) public valueIn;
    mapping(address => uint256) public valueOut;

    bytes32[] public spentNullifiers;
    mapping(bytes32 => bool) internal nullifierRecorded;
    bool public doubleSpendObserved;

    bytes32[] public claimedMemos;
    mapping(bytes32 => bool) internal memoClaimRecorded;
    bool public doubleClaimObserved;

    bytes32[] internal openMemos;
    uint256 public feeTokenDepositsAccepted;

    constructor(
        DarkPool _pool,
        MockERC20 _tokenA,
        MockERC20 _tokenB,
        MockFeeOnTransferERC20 _feeToken
    ) {
        pool = _pool;
        tokenA = _tokenA;
        tokenB = _tokenB;
        feeToken = _feeToken;
    }

    function deposit(
        uint256 valueSeed,
        uint256 leafSeed,
        bool useTokenB
    ) external {
        MockERC20 token = useTokenB ? tokenB : tokenA;
        uint256 value = (valueSeed % MAX_VALUE) + 1;
        token.mint(address(this), value);
        token.approve(address(pool), value);

        bytes32[] memory pi = _base(13);
        pi[0] = bytes32(BASE8_X);
        pi[1] = bytes32(BASE8_Y);
        pi[2] = _leaf(leafSeed);
        pi[3] = _leaf(leafSeed + 1);
        pi[4] = bytes32(value);
        pi[5] = bytes32(uint256(uint160(address(token))));

        try pool.deposit("", pi) {
            valueIn[address(token)] += value;
        } catch {
            token.approve(address(pool), 0);
        }
    }

    /// @dev Floored at MIN_FEE_VALUE so `value * feeBps / 10000` never rounds to zero; below that floor the mock
    ///      charges no fee and the deposit is a legitimate full-value transfer, not a guard bypass.
    function depositFeeOnTransfer(
        uint256 valueSeed,
        uint256 leafSeed
    ) external {
        uint256 value = (valueSeed % MAX_VALUE) + MIN_FEE_VALUE;
        feeToken.mint(address(this), value);
        feeToken.approve(address(pool), value);

        bytes32[] memory pi = _base(13);
        pi[0] = bytes32(BASE8_X);
        pi[1] = bytes32(BASE8_Y);
        pi[2] = _leaf(leafSeed);
        pi[3] = _leaf(leafSeed + 1);
        pi[4] = bytes32(value);
        pi[5] = bytes32(uint256(uint160(address(feeToken))));

        try pool.deposit("", pi) {
            feeTokenDepositsAccepted += 1;
            valueIn[address(feeToken)] += value;
        } catch {
            feeToken.approve(address(pool), 0);
        }
    }

    function withdraw(
        uint256 valueSeed,
        uint256 nullifierSeed,
        uint256 leafSeed,
        uint256 recipientSeed,
        bool useTokenB,
        bool multisig
    ) external {
        MockERC20 token = useTokenB ? tokenB : tokenA;
        uint256 held = token.balanceOf(address(pool));
        // Half the draws exceed the pool balance so the over-withdraw path is exercised, not just the happy one.
        uint256 value = valueSeed % (held * 2 + 1);
        bytes32 nullifier = _nullifier(nullifierSeed);

        bytes32[] memory pi = _base(17);
        pi[0] = bytes32(value);
        pi[1] = bytes32(uint256(uint160(_recipient(recipientSeed))));
        pi[2] = _leaf(leafSeed + 2);
        pi[3] = bytes32(BASE8_X);
        pi[4] = bytes32(BASE8_Y);
        pi[5] = nullifier;
        pi[6] = pool.getCurrentRoot();
        pi[7] = bytes32(uint256(uint160(address(token))));
        pi[8] = _leaf(leafSeed);
        pi[9] = _leaf(leafSeed + 1);

        if (multisig) {
            try pool.withdrawMultisig("", pi) {
                valueOut[address(token)] += value;
                _recordNullifier(nullifier);
            } catch {} // solhint-disable-line no-empty-blocks
        } else {
            try pool.withdraw("", pi) {
                valueOut[address(token)] += value;
                _recordNullifier(nullifier);
            } catch {} // solhint-disable-line no-empty-blocks
        }
    }

    function privateTransfer(
        uint256 nullifierSeed,
        uint256 leafSeed,
        bool multisig
    ) external {
        bytes32 nullifier = _nullifier(nullifierSeed);

        bytes32[] memory pi = _base(24);
        pi[0] = bytes32(BASE8_X);
        pi[1] = bytes32(BASE8_Y);
        pi[2] = nullifier;
        pi[3] = pool.getCurrentRoot();
        pi[4] = _leaf(leafSeed);
        pi[5] = _leaf(leafSeed + 1);
        pi[15] = _leaf(leafSeed + 2);
        pi[16] = _leaf(leafSeed + 3);

        if (multisig) {
            try pool.transferMultisig("", pi) {
                _recordNullifier(nullifier);
            } catch {} // solhint-disable-line no-empty-blocks
        } else {
            try pool.privateTransfer("", pi) {
                _recordNullifier(nullifier);
            } catch {} // solhint-disable-line no-empty-blocks
        }
    }

    function split(
        uint256 nullifierSeed,
        uint256 leafSeed,
        bool multisig
    ) external {
        bytes32 nullifier = _nullifier(nullifierSeed);

        bytes32[] memory pi = _base(22);
        pi[0] = bytes32(BASE8_X);
        pi[1] = bytes32(BASE8_Y);
        pi[2] = nullifier;
        pi[3] = pool.getCurrentRoot();
        pi[4] = _leaf(leafSeed);
        pi[5] = _leaf(leafSeed + 1);
        pi[13] = _leaf(leafSeed + 2);
        pi[14] = _leaf(leafSeed + 3);

        if (multisig) {
            try pool.splitMultisig("", pi) {
                _recordNullifier(nullifier);
            } catch {} // solhint-disable-line no-empty-blocks
        } else {
            try pool.split("", pi) {
                _recordNullifier(nullifier);
            } catch {} // solhint-disable-line no-empty-blocks
        }
    }

    function join(
        uint256 nullifierSeedA,
        uint256 nullifierSeedB,
        uint256 leafSeed,
        bool multisig
    ) external {
        bytes32 nullifierA = _nullifier(nullifierSeedA);
        bytes32 nullifierB = _nullifier(nullifierSeedB);

        bytes32[] memory pi = _base(14);
        pi[0] = bytes32(BASE8_X);
        pi[1] = bytes32(BASE8_Y);
        pi[2] = nullifierA;
        pi[3] = nullifierB;
        pi[4] = pool.getCurrentRoot();
        pi[5] = _leaf(leafSeed);
        pi[6] = _leaf(leafSeed + 1);

        if (multisig) {
            try pool.joinMultisig("", pi) {
                _recordNullifier(nullifierA);
                _recordNullifier(nullifierB);
            } catch {} // solhint-disable-line no-empty-blocks
        } else {
            try pool.join("", pi) {
                _recordNullifier(nullifierA);
                _recordNullifier(nullifierB);
            } catch {} // solhint-disable-line no-empty-blocks
        }
    }

    function kageSwap(
        uint256 nullifierSeedA,
        uint256 nullifierSeedB,
        uint256 leafSeed
    ) external {
        bytes32 takerNullifier = _nullifier(nullifierSeedA);
        bytes32 makerNullifier = _nullifier(nullifierSeedB);

        bytes32[] memory pi = _base(42);
        pi[0] = bytes32(BASE8_X);
        pi[1] = bytes32(BASE8_Y);
        pi[2] = bytes32(block.timestamp);
        pi[3] = takerNullifier;
        pi[4] = makerNullifier;
        pi[5] = pool.getCurrentRoot();
        pi[6] = _leaf(leafSeed);
        pi[7] = _leaf(leafSeed + 1);
        pi[15] = _leaf(leafSeed + 2);
        pi[16] = _leaf(leafSeed + 3);
        pi[24] = _leaf(leafSeed + 4);
        pi[25] = _leaf(leafSeed + 5);
        pi[33] = _leaf(leafSeed + 6);
        pi[34] = _leaf(leafSeed + 7);

        try pool.kageSwap("", pi) {
            _recordNullifier(takerNullifier);
            _recordNullifier(makerNullifier);
        } catch {} // solhint-disable-line no-empty-blocks
    }

    function publicTransfer(
        uint256 valueSeed,
        uint256 saltSeed,
        uint256 timelockSeed,
        bool useTokenB
    ) external {
        MockERC20 token = useTokenB ? tokenB : tokenA;
        uint256 value = (valueSeed % MAX_VALUE) + 1;
        uint256 salt = saltSeed % MEMO_SALT_SPACE;
        uint256 timelock = timelockSeed % MEMO_SALT_SPACE;
        token.mint(address(this), value);
        token.approve(address(pool), value);

        try
            pool.publicTransfer(
                BASE8_X,
                BASE8_Y,
                address(token),
                value,
                timelock,
                salt
            )
        {
            valueIn[address(token)] += value;
            openMemos.push(_memoId(value, address(token), timelock, salt));
        } catch {
            token.approve(address(pool), 0);
        }
    }

    function publicClaim(uint256 memoSeed, uint256 leafSeed) external {
        if (openMemos.length == 0) return;
        bytes32 memoId = openMemos[memoSeed % openMemos.length];

        bytes32[] memory pi = _base(13);
        pi[0] = memoId;
        pi[1] = bytes32(BASE8_X);
        pi[2] = bytes32(BASE8_Y);
        pi[3] = bytes32(block.timestamp);
        pi[4] = _leaf(leafSeed);
        pi[5] = _leaf(leafSeed + 1);

        try pool.publicClaim("", pi) {
            if (memoClaimRecorded[memoId]) {
                doubleClaimObserved = true;
            } else {
                memoClaimRecorded[memoId] = true;
                claimedMemos.push(memoId);
            }
        } catch {} // solhint-disable-line no-empty-blocks
    }

    function spentNullifierCount() external view returns (uint256) {
        return spentNullifiers.length;
    }

    function claimedMemoCount() external view returns (uint256) {
        return claimedMemos.length;
    }

    function _recordNullifier(bytes32 nullifier) internal {
        if (nullifierRecorded[nullifier]) {
            doubleSpendObserved = true;
            return;
        }
        nullifierRecorded[nullifier] = true;
        spentNullifiers.push(nullifier);
    }

    /// @dev Non-zero and in-field: MerkleTreeLib rejects the zero leaf and Field.toField rejects >= FIELD, so a
    ///      raw seed would revert at the tree instead of reaching the effects under test.
    function _leaf(uint256 seed) internal pure returns (bytes32) {
        return
            bytes32((uint256(keccak256(abi.encode(seed))) % (FIELD - 1)) + 1);
    }

    function _nullifier(uint256 seed) internal pure returns (bytes32) {
        return bytes32((seed % NULLIFIER_SPACE) + 1);
    }

    function _recipient(uint256 seed) internal pure returns (address) {
        uint256 which = seed % 3;
        if (which == 0) return RECIPIENT_A;
        if (which == 1) return RECIPIENT_B;
        return RECIPIENT_C;
    }

    function _base(uint256 length) internal pure returns (bytes32[] memory pi) {
        pi = new bytes32[](length);
        for (uint256 i = 0; i < length; i++) {
            pi[i] = bytes32(uint256(i) + 1);
        }
    }

    function _memoId(
        uint256 value,
        address asset,
        uint256 timelock,
        uint256 salt
    ) internal pure returns (bytes32) {
        Field.Type[] memory inputs = new Field.Type[](6);
        inputs[0] = Field.toField(value);
        inputs[1] = Field.toField(uint256(uint160(asset)));
        inputs[2] = Field.toField(timelock);
        inputs[3] = Field.toField(BASE8_X);
        inputs[4] = Field.toField(BASE8_Y);
        inputs[5] = Field.toField(salt);
        return Field.toBytes32(Poseidon2.hash(inputs));
    }
}

contract DarkPoolInvariant {
    uint256 internal constant BASE8_X =
        5299619240641551281634865583518297030282874472190772894086521144482721001553;
    uint256 internal constant BASE8_Y =
        16950150798460657717958625567821834550301663161624707787222815936182638968203;

    DarkPoolHandler internal handler;
    DarkPool internal pool;
    MockERC20 internal tokenA;
    MockERC20 internal tokenB;
    MockFeeOnTransferERC20 internal feeToken;

    function setUp() public {
        tokenA = new MockERC20("A", "A", 18);
        tokenB = new MockERC20("B", "B", 6);
        feeToken = new MockFeeOnTransferERC20("F", "F", 18, FEE_TOKEN_BPS);

        address stub = address(new StubVerifier());
        DarkPool.InitParams memory p = DarkPool.InitParams({
            depositVerifier: stub,
            withdrawVerifier: stub,
            transferVerifier: stub,
            joinVerifier: stub,
            splitVerifier: stub,
            publicClaimVerifier: stub,
            withdrawMultisigVerifier: stub,
            transferMultisigVerifier: stub,
            splitMultisigVerifier: stub,
            joinMultisigVerifier: stub,
            kageVerifier: stub,
            compliancePkX: BASE8_X,
            compliancePkY: BASE8_Y,
            initialAdminDelay: 0,
            initialAdmin: address(this),
            pauser: address(this),
            upgrader: address(this)
        });

        address impl = address(new DarkPool());
        pool = DarkPool(
            address(
                new ERC1967Proxy(impl, abi.encodeCall(DarkPool.initialize, (p)))
            )
        );
        handler = new DarkPoolHandler(pool, tokenA, tokenB, feeToken);
    }

    /// @dev The tokens expose a permissionless mint(), so the fuzzer must be confined to the handler or it would
    ///      credit the pool behind the ledger's back and the balance equality below would be meaningless.
    function targetContracts() public view returns (address[] memory targets) {
        targets = new address[](1);
        targets[0] = address(handler);
    }

    function invariant_poolSolvency() public view {
        _assertSolvent(address(tokenA));
        _assertSolvent(address(tokenB));
        _assertSolvent(address(feeToken));
    }

    function invariant_noValueMint() public view {
        require(
            handler.valueOut(address(tokenA)) <=
                handler.valueIn(address(tokenA)),
            "tokenA paid out more than came in"
        );
        require(
            handler.valueOut(address(tokenB)) <=
                handler.valueIn(address(tokenB)),
            "tokenB paid out more than came in"
        );
        require(
            handler.valueOut(address(feeToken)) <=
                handler.valueIn(address(feeToken)),
            "feeToken paid out more than came in"
        );
    }

    function invariant_noNullifierDoubleSpend() public view {
        require(
            !handler.doubleSpendObserved(),
            "a spent nullifier was accepted twice"
        );
        uint256 n = handler.spentNullifierCount();
        for (uint256 i = 0; i < n; i++) {
            require(
                pool.isNullifierSpent(handler.spentNullifiers(i)),
                "a spent nullifier was un-marked"
            );
        }
    }

    function invariant_noPublicMemoDoubleClaim() public view {
        require(
            !handler.doubleClaimObserved(),
            "a public memo was claimed twice"
        );
        uint256 n = handler.claimedMemoCount();
        for (uint256 i = 0; i < n; i++) {
            require(
                pool.isPublicMemoSpent(handler.claimedMemos(i)),
                "a claimed public memo was un-marked"
            );
        }
    }

    function invariant_feeOnTransferNeverCredited() public view {
        require(
            handler.feeTokenDepositsAccepted() == 0,
            "fee-on-transfer deposit was credited"
        );
    }

    function _assertSolvent(address token) internal view {
        require(
            MockERC20(token).balanceOf(address(pool)) ==
                handler.valueIn(token) - handler.valueOut(token),
            "pool balance diverged from the deposited-minus-withdrawn ledger"
        );
    }
}
