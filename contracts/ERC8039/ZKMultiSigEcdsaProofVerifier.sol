// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.20;

import {IERC8039, ProofTypes, ERC8039Constants} from "../interfaces/IERC8039.sol";
import {IERC165} from "@openzeppelin/contracts/interfaces/IERC165.sol";
import {HonkVerifier} from "../../noir/target/zk_multi_sig_ecdsa.sol";

/**
 * @title Honk Proof Verifier Adapter
 * @dev Adapts the HonkVerifier to the IERC8039 interface
 * 
 */
contract ZKMultiSigEcdsaProofVerifier is IERC8039 {
    /**
     * @notice The underlying Honk verifier contract
     */
    HonkVerifier public immutable honkVerifier;

    /**
     * @notice Creates a new Honk proof verifier adapter
     * @param _honkVerifier The address of the HonkVerifier contract
     */
    constructor(address _honkVerifier) {
        require(_honkVerifier != address(0), "HonkProofVerifier: Invalid verifier address");
        honkVerifier = HonkVerifier(_honkVerifier);
    }

    /**
     * @inheritdoc IERC8039
     * @dev Simple interface - no proof type parameter needed
     */
    function verifyProof(
        bytes calldata publicSignals,
        bytes calldata proof
    ) external view override returns (bytes4 magicValue) {
        // Decode public signals to bytes32[] array (expected by HonkVerifier)
        bytes32[] memory publicInputs = abi.decode(publicSignals, (bytes32[]));

        // Ensure we have exactly 33 public input (state root)
        require(publicInputs.length == 33, "Invalid public inputs length");

        // Verify the proof using HonkVerifier
        bool isValid = honkVerifier.verify(proof, publicInputs);

        // Return magic value if valid
        if (isValid) {
            magicValue = ERC8039Constants.PROOF_MAGIC_VALUE;
        }
    }

    /**
     * @inheritdoc IERC8039
     * @dev Returns the proof type this verifier supports
     */
    function getProofType() external view override returns (bytes32) {
        return ProofTypes.HONK_NOIR;
    }

     /**
     * @notice Returns human-readable metadata describing the statement being proven
     * @dev Implementation of IERC8039 interface
     * @return metadata Human-readable description
     */
    function metadata() external view override returns (string memory metadata) {
        return "ZK MultiSig Validator v0.1.0 - Proves valid multisig signature";
    }

    /**
     * @notice Query if this contract implements a given interface (ERC-165)
     * @dev Returns true if this contract implements the interface defined by interfaceId
     * @param interfaceId The interface identifier, as specified in ERC-165
     * @return true if the contract implements interfaceId
     */
    function supportsInterface(bytes4 interfaceId) external view override returns (bool) {
        return 
            interfaceId == type(IERC8039).interfaceId ||
            interfaceId == 0x01ffc9a7; // ERC-165 interface ID
    }
}
