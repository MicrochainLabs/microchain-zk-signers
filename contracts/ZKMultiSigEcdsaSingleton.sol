// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.20;

import {SignatureValidator} from "./ERC1271/SignatureValidator.sol";
import {IERC8039, ERC8039Constants} from "./interfaces/IERC8039.sol";

/**
 * @title ZK MultiSig ECDSA Singleton (Proof-System Agnostic)
 * @dev A singleton contract that implements ZK proof-based multi-signature verification.
 * This singleton contract must be used with the specialized proxy {ZKMultiSigEcdsaProxy},
 * as it encodes the configuration (stateRoot and verifier address) in calldata.
 * 
 * Now uses IERC8039 interface for proof-system agnostic verification
 * Supports any proof system (Honk, Circom, SP1, Risc0, etc.) through a standard interface
 * 
 */
contract ZKMultiSigEcdsaSingleton is SignatureValidator {
    /**
     * @inheritdoc SignatureValidator
     * @dev Verifies a ZK proof for multi-signature validation.
     * The configuration (stateRoot and verifier address) is read from the end of calldata.
     */
    function _verifySignature(
        bytes32 hash,
        bytes calldata signature
    ) internal view virtual override returns (bool success) {
        // Get configuration from end of calldata (appended by proxy)
        (bytes32 stateRoot, address verifierAddress) = getConfiguration();

        // Construct the public inputs for the circuit
        bytes32[] memory publicInputs = new bytes32[](32 + 1);

        // Each byte of the transaction hash is given as a separate uint256 value.
        // TODO: this is super inefficient, fix by making the circuit take compressed inputs.
        for (uint256 i = 0; i < 32; i++) {
            publicInputs[i] = bytes32(uint256(uint8(hash[i])));
        }

        // stateRoot
        publicInputs[32] = stateRoot;

        // Encode public inputs for the proof verifier
        bytes memory publicSignals = abi.encode(publicInputs);

        // Use the IERC8039 interface for verification (proof-system agnostic!)
        IERC8039 verifier = IERC8039(verifierAddress);
        
        bytes4 result = verifier.verifyProof(
            publicSignals,  // Public signals first (the data)
            signature       // Proof second (the evidence)
        );

        // Check if verification succeeded
        success = (result == ERC8039Constants.PROOF_MAGIC_VALUE);
    }

    /**
     * @notice Returns the stateRoot and verifier address used for ZK proof validation.
     * The values are expected to be appended to calldata by the caller.
     * See the {ZKMultiSigEcdsaProxy} contract implementation.
     * @return stateRoot The Merkle root of authorized signers.
     * @return verifierAddress The address of the IERC8039 contract.
     */
    function getConfiguration() public pure returns (bytes32 stateRoot, address verifierAddress) {
        // solhint-disable-next-line no-inline-assembly
        assembly ("memory-safe") {
            // Configuration is appended to calldata:
            // - Last 52 bytes contain: stateRoot (32 bytes) + verifierAddress (20 bytes)
            // Read stateRoot from calldatasize - 52
            stateRoot := calldataload(sub(calldatasize(), 52))
            // Read verifierAddress from calldatasize - 20, shift right by 96 bits (12 bytes)
            verifierAddress := shr(96, calldataload(sub(calldatasize(), 20)))
        }
    }
}
