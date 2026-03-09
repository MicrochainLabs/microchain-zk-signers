// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { IERC8039, ERC8039Constants } from "../../../../contracts/ERC8039/IERC8039.sol";

/**
 * @title MockZKVerifier
 * @notice Mock implementation of IERC8039 for testing
 * @dev This mock verifier can be configured to return success or failure for testing purposes
 */
contract MockZKVerifier is IERC8039 {
    /// @notice If true, all proofs will be considered valid
    bool public alwaysValid;
    
    /// @notice Proof type identifier
    bytes32 public immutable proofType;
    
    /// @notice Statement metadata
    string public statementMetadata;

    constructor(bool _alwaysValid, bytes32 _proofType, string memory _metadata) {
        alwaysValid = _alwaysValid;
        proofType = _proofType;
        statementMetadata = _metadata;
    }

    /**
     * @notice Verifies a zero-knowledge proof
     * @dev Returns PROOF_MAGIC_VALUE if alwaysValid is true, 0x00000000 otherwise
     */
    function verifyProof(
        bytes calldata /* publicInputs */,
        bytes calldata /* proof */
    ) external view override returns (bytes4 magicValue) {
        if (alwaysValid) {
            return ERC8039Constants.PROOF_MAGIC_VALUE;
        }
        return bytes4(0);
    }

    /**
     * @notice Returns the proof type this verifier supports
     */
    function getProofType() external view override returns (bytes32) {
        return proofType;
    }

    /**
     * @notice Returns human-readable metadata about the statement
     */
    function metadata() external view override returns (string memory) {
        return statementMetadata;
    }

    /**
     * @notice Allows changing the verification behavior during tests
     */
    function setAlwaysValid(bool _alwaysValid) external {
        alwaysValid = _alwaysValid;
    }
}
