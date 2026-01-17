// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.20;

import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";

/**
 * @title ERC-1271 Magic Values
 * @dev Library that defines constants for ERC-1271 related magic values.
 */
library ERC1271Constants {
    /**
     * @notice ERC-1271 magic value returned on valid signatures.
     * @dev Value is derived from `bytes4(keccak256("isValidSignature(bytes32,bytes)")`.
     */
    bytes4 internal constant MAGIC_VALUE = 0x1626ba7e;

    /**
     * @notice Legacy EIP-1271 magic value returned on valid signatures.
     * @dev This value was used in previous drafts of the EIP-1271 standard, but replaced by
     * {MAGIC_VALUE} in the final version.
     *
     * Value is derived from `bytes4(keccak256("isValidSignature(bytes,bytes)")`.
     */
    bytes4 internal constant LEGACY_MAGIC_VALUE = 0x20c13b0b;
}

/**
 * @title Signature Validator Base Contract
 * @dev A interface for smart contract Safe owners that supports multiple ERC-1271 `isValidSignature` versions.
 */
abstract contract SignatureValidator is IERC1271 {


    /**
     * @dev Validates the signature for the given data.
     * @param data The signed data bytes.
     * @param signature The signature to be validated.
     * @return magicValue The magic value indicating the validity of the signature.
     */
    function isValidSignature(bytes memory data, bytes calldata signature) external view returns (bytes4 magicValue) {
        if (_verifySignature(keccak256(data), signature)) {
            magicValue = ERC1271Constants.LEGACY_MAGIC_VALUE;
        }
    }

    /**
     * @dev Validates the signature for a given data hash.
     * @param hash The signed hash.
     * @param signature The signature to be validated.
     * @return magicValue The magic value indicating the validity of the signature.
     */
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4 magicValue) {
        if (_verifySignature(hash, signature)) {
            magicValue = ERC1271Constants.MAGIC_VALUE;
        }
    }

    /**
     * @dev Verifies a signature.
     * @param hash The signed hash.
     * @param signature The signature to be validated.
     * @return success Whether the signature is valid.
     */
    function _verifySignature(bytes32 hash, bytes calldata signature) internal view virtual returns (bool success);
}