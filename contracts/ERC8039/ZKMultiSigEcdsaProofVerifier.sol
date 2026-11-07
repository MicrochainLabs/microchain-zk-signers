// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {IERC8039, ProofTypes, ERC8039Constants} from "./IERC8039.sol";
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
     * @dev Never reverts (ERC-8039 requirement): malformed inputs or a reverting
     *      underlying verifier yield `bytes4(0)`.
     */
    function verifyProof(
        bytes calldata publicInputs,
        bytes calldata proof
    ) external view override returns (bytes4 magicValue) {
        // Ensure the ABI-encoded bytes32[] carries exactly 33 public inputs (32 hash bytes + state root).
        // Checking offset and length up-front guarantees `abi.decode` cannot revert.
        if (
            publicInputs.length != 32 * (2 + 33) ||
            uint256(bytes32(publicInputs[0:32])) != 0x20 ||
            uint256(bytes32(publicInputs[32:64])) != 33
        ) {
            return bytes4(0);
        }
        bytes32[] memory decodedInputs = abi.decode(publicInputs, (bytes32[]));

        try honkVerifier.verify(proof, decodedInputs) returns (bool isValid) {
            if (isValid) {
                magicValue = ERC8039Constants.PROOF_MAGIC_VALUE;
            }
        } catch {
            magicValue = bytes4(0);
        }
    }

    /**
     * @inheritdoc IERC8039
     * @dev Returns the proof type this verifier supports
     */
    function getProofType() external view override returns (bytes32) {
        return ProofTypes.HONK_BARRETENBERG;
    }

     /**
     * @notice Returns human-readable metadata describing the statement being proven
     * @dev Implementation of IERC8039 interface
     * @return metadata Human-readable description
     */
    function metadata() external view override returns (string memory) {
        return "ZK MultiSig Validator v0.1.0 - Proves valid multisig signature";
    }
}
