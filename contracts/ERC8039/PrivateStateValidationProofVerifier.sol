// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.20;

import {IERC8039, ProofTypes, ERC8039Constants} from "../interfaces/IERC8039.sol";
import {IERC165} from "@openzeppelin/contracts/interfaces/IERC165.sol";
import {HonkVerifier} from "../../noir/target/zk_multi_sig_ecdsa_private_state_validation.sol";

/**
 * @title Private State Validator Proof Verifier Adapter
 * @dev Adapts the HonkVerifier for private state validation to the IERC8039 interface
 * This allows the factory to verify private state validity proof before deployment
 * of a private multi-signature contract.
 */
contract PrivateStateValidationProofVerifier is IERC8039 {
    /**
     * @notice The underlying Honk verifier contract for private state validation
     */
    HonkVerifier public immutable honkVerifier;

    /**
     * @notice Creates a new Private State Validator proof verifier adapter
     * @param _honkVerifier The HonkVerifier contract for state validation
     */
    constructor(HonkVerifier _honkVerifier) {
        require(address(_honkVerifier) != address(0), "Invalid verifier address");
        honkVerifier = _honkVerifier;
    }

    /**
     * @notice Verifies a private state validation proof
     * @dev Decodes public signals and verifies the proof using the HonkVerifier
     * 
     * The public signals contain the state root that was computed in the circuit.
     * 
     * @param publicSignals The public inputs (encoded as bytes32[])
     * @param proof The ZK proof bytes
     * @return magicValue PROOF_MAGIC_VALUE if valid, 0x00000000 otherwise
     */
    function verifyProof(
        bytes calldata publicSignals,
        bytes calldata proof
    ) external view returns (bytes4 magicValue) {
        // Decode public signals to bytes32[] array (expected by HonkVerifier)
        bytes32[] memory publicInputs = abi.decode(publicSignals, (bytes32[]));

        // Ensure we have exactly 1 public input (state root)
        require(publicInputs.length == 1, "Invalid public inputs length");

        // Verify the proof using HonkVerifier
        bool isValid = honkVerifier.verify(proof, publicInputs);

         // Return magic value if valid
        if (isValid) {
            magicValue = ERC8039Constants.PROOF_MAGIC_VALUE;
        }
    }

    /**
     * @notice Returns the proof type this verifier supports
     * @dev Implementation of IERC8039 interface
     * @return proofType The proof type identifier (HONK-noir for private state validation)
     */
    function getProofType() external view override returns (bytes32 proofType) {
        return ProofTypes.HONK_NOIR;
    }

    /**
     * @notice Returns human-readable metadata describing the statement being proven
     * @dev Implementation of IERC8039 interface
     * @return metadata Human-readable description
     */
    function metadata() external view override returns (string memory metadata) {
        return "ZK MultiSig Private State Validation v0.1.0 - Proves valid private state configuration (signers + threshold)";
    }

    /**
     * @notice Checks if this contract implements an interface
     * @param interfaceId The interface identifier
     * @return True if the interface is supported
     */
    function supportsInterface(bytes4 interfaceId) external view override returns (bool) {
        return interfaceId == type(IERC8039).interfaceId || 
               interfaceId == type(IERC165).interfaceId;
    }
}

