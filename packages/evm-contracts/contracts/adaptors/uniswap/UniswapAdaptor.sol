// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {ISwapRouter} from "@uniswap/v3-periphery/contracts/interfaces/ISwapRouter.sol";
import {IDarkPool} from "../../interfaces/IDarkPool.sol";
import {Poseidon2} from "../../Poseidon/Poseidon2.sol";
import {Field} from "../../Poseidon/Field.sol";

contract UniswapAdaptor is ReentrancyGuard {
    using SafeERC20 for IERC20;

    error ZeroAddress();
    error InvalidProofRecipient();
    error AssetMismatch();
    error WithdrawAmountMismatch();
    error UnsupportedSwapType();
    error PathTooShort();

    address public immutable DARK_POOL;
    ISwapRouter public immutable UNISWAP_ROUTER;

    uint256 constant PRIME =
        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

    enum SwapType {
        ExactInputSingle,
        ExactInput,
        ExactOutputSingle,
        ExactOutput
    }

    struct RecipientIdentity {
        uint256 ownerX;
        uint256 ownerY;
    }

    struct ExactInputSingleParams {
        address assetIn;
        address assetOut;
        uint24 fee;
        RecipientIdentity recipient;
        uint256 amountOutMin;
        uint256 salt;
    }
    struct ExactInputParams {
        bytes path;
        RecipientIdentity recipient;
        uint256 amountOutMin;
        uint256 salt;
    }
    struct ExactOutputSingleParams {
        address assetIn;
        address assetOut;
        uint24 fee;
        RecipientIdentity recipient;
        uint256 amountOut;
        uint256 amountInMaximum;
        uint256 salt;
    }
    struct ExactOutputParams {
        bytes path;
        RecipientIdentity recipient;
        uint256 amountOut;
        uint256 amountInMaximum;
        uint256 salt;
    }

    constructor(address _darkPool, address _uniswapRouter) {
        if (_darkPool == address(0)) revert ZeroAddress();
        if (_uniswapRouter == address(0)) revert ZeroAddress();
        DARK_POOL = _darkPool;
        UNISWAP_ROUTER = ISwapRouter(_uniswapRouter);
    }

    function executeSwap(
        bytes calldata proof,
        bytes32[] memory publicInputs,
        SwapType swapType,
        bytes calldata encodedParams
    ) external nonReentrant {
        bytes32 intentHash = _calculateIntentHash(swapType, encodedParams);

        address proofRecipient = address(uint160(uint256(publicInputs[1])));
        if (proofRecipient != address(this)) revert InvalidProofRecipient();

        // Bind swap to proof: overwrite withdraw intent_hash (index 2); a tampered swap fails verification.
        publicInputs[2] = intentHash;

        IDarkPool(DARK_POOL).withdraw(proof, publicInputs);

        uint256 withdrawnAmount = uint256(publicInputs[0]);
        address withdrawnAsset = address(uint160(uint256(publicInputs[7])));
        uint256 balPreSwap = IERC20(withdrawnAsset).balanceOf(address(this));

        address outAsset;
        uint256 outPreBal;
        if (swapType == SwapType.ExactInputSingle) {
            (outAsset, outPreBal) = _handleExactInputSingle(
                withdrawnAmount,
                withdrawnAsset,
                encodedParams
            );
        } else if (swapType == SwapType.ExactInput) {
            (outAsset, outPreBal) = _handleExactInput(
                withdrawnAmount,
                withdrawnAsset,
                encodedParams
            );
        } else if (swapType == SwapType.ExactOutputSingle) {
            (outAsset, outPreBal) = _handleExactOutputSingle(
                withdrawnAmount,
                withdrawnAsset,
                encodedParams
            );
        } else if (swapType == SwapType.ExactOutput) {
            (outAsset, outPreBal) = _handleExactOutput(
                withdrawnAmount,
                withdrawnAsset,
                encodedParams
            );
        } else {
            revert UnsupportedSwapType();
        }

        if (
            IERC20(withdrawnAsset).balanceOf(address(this)) !=
            balPreSwap - withdrawnAmount
        ) revert AssetMismatch();
        // Skip when output == input asset: the assetIn check above already
        // governs that balance and a separate net-zero check would false-revert.
        if (
            outAsset != withdrawnAsset &&
            IERC20(outAsset).balanceOf(address(this)) != outPreBal
        ) revert AssetMismatch();
    }

    function _handleExactInputSingle(
        uint256 amountIn,
        address withdrawnAsset,
        bytes calldata encoded
    ) internal returns (address outAsset, uint256 outPreBal) {
        ExactInputSingleParams memory p = abi.decode(
            encoded,
            (ExactInputSingleParams)
        );
        if (p.assetIn != withdrawnAsset) revert AssetMismatch();
        outAsset = p.assetOut;
        outPreBal = IERC20(outAsset).balanceOf(address(this));
        IERC20(p.assetIn).forceApprove(address(UNISWAP_ROUTER), amountIn);
        ISwapRouter.ExactInputSingleParams memory params = ISwapRouter
            .ExactInputSingleParams({
                tokenIn: p.assetIn,
                tokenOut: p.assetOut,
                fee: p.fee,
                recipient: address(this),
                deadline: block.timestamp,
                amountIn: amountIn,
                amountOutMinimum: p.amountOutMin,
                sqrtPriceLimitX96: 0
            });
        uint256 amountOut = UNISWAP_ROUTER.exactInputSingle(params);
        _returnFunds(p.recipient, p.assetOut, amountOut, p.salt);
    }

    function _handleExactInput(
        uint256 amountIn,
        address withdrawnAsset,
        bytes calldata encoded
    ) internal returns (address outAsset, uint256 outPreBal) {
        ExactInputParams memory p = abi.decode(encoded, (ExactInputParams));
        address tokenIn = BytesLib.toAddress(p.path, 0);
        if (tokenIn != withdrawnAsset) revert AssetMismatch();

        // Path: TokenIn -> ... -> TokenOut
        address tokenOut = _getLastToken(p.path);
        outAsset = tokenOut;
        outPreBal = IERC20(tokenOut).balanceOf(address(this));

        IERC20(tokenIn).forceApprove(address(UNISWAP_ROUTER), amountIn);
        ISwapRouter.ExactInputParams memory params = ISwapRouter
            .ExactInputParams({
                path: p.path,
                recipient: address(this),
                deadline: block.timestamp,
                amountIn: amountIn,
                amountOutMinimum: p.amountOutMin
            });
        uint256 amountOut = UNISWAP_ROUTER.exactInput(params);
        _returnFunds(p.recipient, tokenOut, amountOut, p.salt);
    }

    function _handleExactOutputSingle(
        uint256 amountInMax,
        address withdrawnAsset,
        bytes calldata encoded
    ) internal returns (address outAsset, uint256 outPreBal) {
        ExactOutputSingleParams memory p = abi.decode(
            encoded,
            (ExactOutputSingleParams)
        );
        if (amountInMax != p.amountInMaximum) revert WithdrawAmountMismatch();
        if (p.assetIn != withdrawnAsset) revert AssetMismatch();
        outAsset = p.assetOut;
        outPreBal = IERC20(outAsset).balanceOf(address(this));
        IERC20(p.assetIn).forceApprove(address(UNISWAP_ROUTER), amountInMax);
        ISwapRouter.ExactOutputSingleParams memory params = ISwapRouter
            .ExactOutputSingleParams({
                tokenIn: p.assetIn,
                tokenOut: p.assetOut,
                fee: p.fee,
                recipient: address(this),
                deadline: block.timestamp,
                amountOut: p.amountOut,
                amountInMaximum: amountInMax,
                sqrtPriceLimitX96: 0
            });
        uint256 amountInActual = UNISWAP_ROUTER.exactOutputSingle(params);
        IERC20(p.assetIn).forceApprove(address(UNISWAP_ROUTER), 0);
        _returnFunds(p.recipient, p.assetOut, p.amountOut, p.salt);
        if (amountInActual < amountInMax) {
            _returnFunds(
                p.recipient,
                p.assetIn,
                amountInMax - amountInActual,
                p.salt
            );
        }
    }

    function _handleExactOutput(
        uint256 amountInMax,
        address withdrawnAsset,
        bytes calldata encoded
    ) internal returns (address outAsset, uint256 outPreBal) {
        ExactOutputParams memory p = abi.decode(encoded, (ExactOutputParams));
        if (amountInMax != p.amountInMaximum) revert WithdrawAmountMismatch();

        // Path: TokenOut -> ... -> TokenIn (Reversed)
        address tokenIn = _getLastToken(p.path);
        if (tokenIn != withdrawnAsset) revert AssetMismatch();
        address tokenOut = BytesLib.toAddress(p.path, 0);
        outAsset = tokenOut;
        outPreBal = IERC20(tokenOut).balanceOf(address(this));

        IERC20(tokenIn).forceApprove(address(UNISWAP_ROUTER), amountInMax);
        ISwapRouter.ExactOutputParams memory params = ISwapRouter
            .ExactOutputParams({
                path: p.path,
                recipient: address(this),
                deadline: block.timestamp,
                amountOut: p.amountOut,
                amountInMaximum: amountInMax
            });
        uint256 amountInActual = UNISWAP_ROUTER.exactOutput(params);
        IERC20(tokenIn).forceApprove(address(UNISWAP_ROUTER), 0);
        _returnFunds(p.recipient, tokenOut, p.amountOut, p.salt);
        if (amountInActual < amountInMax) {
            _returnFunds(
                p.recipient,
                tokenIn,
                amountInMax - amountInActual,
                p.salt
            );
        }
    }

    function _returnFunds(
        RecipientIdentity memory r,
        address asset,
        uint256 amount,
        uint256 salt
    ) internal {
        if (amount == 0) return;
        IERC20(asset).forceApprove(DARK_POOL, amount);
        IDarkPool(DARK_POOL).publicTransfer(
            r.ownerX,
            r.ownerY,
            asset,
            amount,
            0,
            salt
        );
    }

    function _getLastToken(bytes memory path) internal pure returns (address) {
        uint256 len = path.length;
        if (len < 20) revert PathTooShort();
        address token;
        assembly {
            // Last 20 bytes of path, in the word's high bytes, so shift right 96 bits.
            let ptr := add(add(path, 32), sub(len, 20))
            let loaded := mload(ptr)
            token := shr(96, loaded)
        }
        return token;
    }

    function _calculateIntentHash(
        SwapType sType,
        bytes calldata encoded
    ) internal pure returns (bytes32) {
        if (sType == SwapType.ExactInputSingle) {
            ExactInputSingleParams memory p = abi.decode(
                encoded,
                (ExactInputSingleParams)
            );
            return
                _hash6(
                    uint256(sType),
                    uint256(uint160(p.assetIn)),
                    uint256(uint160(p.assetOut)),
                    uint256(p.fee),
                    p.amountOutMin,
                    p.recipient,
                    p.salt
                );
        } else if (sType == SwapType.ExactInput) {
            ExactInputParams memory p = abi.decode(encoded, (ExactInputParams));
            uint256 pathHash = uint256(keccak256(p.path)) % PRIME;
            return
                _hash5(
                    uint256(sType),
                    pathHash,
                    p.amountOutMin,
                    p.recipient,
                    p.salt
                );
        } else if (sType == SwapType.ExactOutputSingle) {
            ExactOutputSingleParams memory p = abi.decode(
                encoded,
                (ExactOutputSingleParams)
            );
            return
                _hash8(
                    uint256(sType),
                    uint256(uint160(p.assetIn)),
                    uint256(uint160(p.assetOut)),
                    uint256(p.fee),
                    p.amountOut,
                    p.amountInMaximum,
                    p.recipient,
                    p.salt
                );
        } else if (sType == SwapType.ExactOutput) {
            ExactOutputParams memory p = abi.decode(
                encoded,
                (ExactOutputParams)
            );
            uint256 pathHash = uint256(keccak256(p.path)) % PRIME;
            return
                _hashExactOutputHelper(
                    uint256(sType),
                    pathHash,
                    p.amountOut,
                    p.amountInMaximum,
                    p.recipient,
                    p.salt
                );
        }
        revert UnsupportedSwapType();
    }

    function _hash6(
        uint256 a,
        uint256 b,
        uint256 c,
        uint256 d,
        uint256 e,
        RecipientIdentity memory r,
        uint256 salt
    ) internal pure returns (bytes32) {
        Field.Type[] memory f = new Field.Type[](8);
        f[0] = Field.toField(a);
        f[1] = Field.toField(b);
        f[2] = Field.toField(c);
        f[3] = Field.toField(d);
        f[4] = Field.toField(e);
        f[5] = Field.toField(r.ownerX);
        f[6] = Field.toField(r.ownerY);
        f[7] = Field.toField(salt);
        return Field.toBytes32(Poseidon2.hash(f));
    }
    function _hash5(
        uint256 a,
        uint256 b,
        uint256 c,
        RecipientIdentity memory r,
        uint256 salt
    ) internal pure returns (bytes32) {
        Field.Type[] memory f = new Field.Type[](6);
        f[0] = Field.toField(a);
        f[1] = Field.toField(b);
        f[2] = Field.toField(c);
        f[3] = Field.toField(r.ownerX);
        f[4] = Field.toField(r.ownerY);
        f[5] = Field.toField(salt);
        return Field.toBytes32(Poseidon2.hash(f));
    }
    function _hash8(
        uint256 a,
        uint256 b,
        uint256 c,
        uint256 d,
        uint256 e,
        uint256 f,
        RecipientIdentity memory r,
        uint256 salt
    ) internal pure returns (bytes32) {
        Field.Type[] memory arr = new Field.Type[](9);
        arr[0] = Field.toField(a);
        arr[1] = Field.toField(b);
        arr[2] = Field.toField(c);
        arr[3] = Field.toField(d);
        arr[4] = Field.toField(e);
        arr[5] = Field.toField(f);
        arr[6] = Field.toField(r.ownerX);
        arr[7] = Field.toField(r.ownerY);
        arr[8] = Field.toField(salt);
        return Field.toBytes32(Poseidon2.hash(arr));
    }
    function _hashExactOutputHelper(
        uint256 a,
        uint256 b,
        uint256 c,
        uint256 d,
        RecipientIdentity memory r,
        uint256 salt
    ) internal pure returns (bytes32) {
        Field.Type[] memory f = new Field.Type[](7);
        f[0] = Field.toField(a);
        f[1] = Field.toField(b);
        f[2] = Field.toField(c);
        f[3] = Field.toField(d);
        f[4] = Field.toField(r.ownerX);
        f[5] = Field.toField(r.ownerY);
        f[6] = Field.toField(salt);
        return Field.toBytes32(Poseidon2.hash(f));
    }
}

library BytesLib {
    error PathOutOfBounds();

    function toAddress(
        bytes memory _bytes,
        uint256 _start
    ) internal pure returns (address) {
        if (_bytes.length < _start + 20) revert PathOutOfBounds();
        address tempAddress;
        assembly {
            let ptr := add(add(_bytes, 32), _start)
            let loaded := mload(ptr)
            tempAddress := shr(96, loaded)
        }
        return tempAddress;
    }
}
