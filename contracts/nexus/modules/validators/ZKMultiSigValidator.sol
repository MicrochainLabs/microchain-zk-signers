// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

// ZK MultiSig Validator: Privacy-preserving multi-signature validator using zero-knowledge proofs
// Developed by Microchain Labs

import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";
import { IValidator } from "@biconomy/nexus/interfaces/modules/IValidator.sol";
import { MODULE_TYPE_VALIDATOR, VALIDATION_SUCCESS, VALIDATION_FAILED, ERC1271_MAGICVALUE, ERC1271_INVALID } from "@biconomy/nexus/types/Constants.sol";
import { IERC8039, ERC8039Constants } from "../../../ERC8039/IERC8039.sol";

/// @title ZKMultiSigValidator
/// @notice Validator module for Nexus smart accounts using ZK proofs for private multi-signature verification
/// @dev Implements privacy-preserving M-of-N threshold signatures where signer identities remain private.
///      Only a cryptographic commitment (state root) to the authorized signers is stored on-chain.
///      This validator uses zero-knowledge proofs to verify that sufficient signatures were provided
///      without revealing which specific signers approved the transaction.
/// @author Microchain Labs
contract ZKMultiSigValidator is IValidator {
    /*//////////////////////////////////////////////////////////////////////////
                            CONSTANTS & STORAGE
    //////////////////////////////////////////////////////////////////////////*/

    /// @notice The off-chain state validation proof verifier
    address public immutable stateValidator;

    /// @notice The user operation validation proof verifier
    address public immutable userOpValidator;

    /// @notice State for each smart account's ZK multi-sig setup
    /// @notice Mapping from smart account to state root
    /// @dev A non-zero value indicates the module is initialized for that account
    mapping(address => bytes32) public accountStateRoots;

    /// @notice Event emitted when a ZK multi-sig off-chain state is set
    event ZKMultiSigConfigured(address indexed smartAccount, bytes32 stateRoot);

    /// @notice Error thrown when proof verification fails during initialization
    error InvalidOffChainState();

    /// @notice Error thrown when invalid data is provided
    error InvalidData();

    /// @notice Error thrown when zero address is provided for verifier
    error ZeroAddressNotAllowed();

    /// @notice Error when the module is already initialized for an account
    error ModuleAlreadyInitialized();

    /// @notice Error when the state root is zero (invalid)
    error ZeroStateRootNotAllowed();

    /// @notice Error when attempting to use an uninitialized module
    error ModuleNotInitialized();


    /**
     * @notice Constructor to set immutable ZK proof verifier addresses
     * @param _stateValidator The address of the state validation proof verifier
     * @param _userOpValidator The address of the proof verifier for user operations
     */
    constructor(address _stateValidator, address _userOpValidator) {
        if (_stateValidator == address(0)) revert ZeroAddressNotAllowed();
        if (_userOpValidator == address(0)) revert ZeroAddressNotAllowed();
        stateValidator = _stateValidator;
        userOpValidator = _userOpValidator;
    }

    /*//////////////////////////////////////////////////////////////////////////
                                     CONFIG
    ////////////////////////////////////////////////////////////////////////////

    /**
     * @notice Initialize the module with ZK multi-sig off-chain state
     * @dev stateRoot is the cryptographic commitment(Instance/Public input) to the signer set + threshold + salt
     */
    function onInstall(bytes calldata data) external override {
        require(data.length != 0, InvalidData());
        require(!_isInitialized(msg.sender), ModuleAlreadyInitialized());

          // Decode initialization data
        (bytes32 stateRoot, bytes memory stateValidationProof) = abi.decode(
            data,
            (bytes32, bytes)
        );
        
        if (stateRoot == bytes32(0)) revert ZeroStateRootNotAllowed();

        if (!_verifyZKProofForOffChainStateValidation(stateRoot, stateValidationProof)) revert InvalidOffChainState();

         // Store state root (non-zero value indicates initialized)
        accountStateRoots[msg.sender] = stateRoot;

        emit ZKMultiSigConfigured(msg.sender, stateRoot);
    }

    /**
     * @notice De-initialize the module
     * @dev Removes the ZK multi-sig for the calling account
     */
    function onUninstall(bytes calldata) external override {
        delete accountStateRoots[msg.sender];
        emit ZKMultiSigConfigured(msg.sender, bytes32(0));
    }

    /**
     * @notice Update the ZK multi-sig off-chain state
     * @param newStateRoot New cryptographic commitment to the signer set
     * @param stateValidationProof ZK proof validating the new state 
     * @dev Can only be called by the smart account itself
     */
    function updateStateRoot(bytes32 newStateRoot, bytes calldata stateValidationProof) external {
        require(_isInitialized(msg.sender), ModuleNotInitialized());
        require(newStateRoot != bytes32(0), ZeroStateRootNotAllowed());

        // Verify the new off-chain state with a proof
        if (!_verifyZKProofForOffChainStateValidation(newStateRoot, stateValidationProof)) revert InvalidOffChainState();

        // Update the state root
        accountStateRoots[msg.sender] = newStateRoot;

        emit ZKMultiSigConfigured(msg.sender, newStateRoot);
    }

    /**
     * @notice Check if the module is initialized for a smart account
     * @param smartAccount The smart account address to check
     * @return True if initialized, false otherwise
     */
    function isInitialized(address smartAccount) external view returns (bool) {
        return _isInitialized(smartAccount);
    }

    /**
     * @notice Get the ZK multi-sig off-chain state root for a smart account
     * @param smartAccount The smart account address
     * @return stateRoot The cryptographic commitment to the signer set
     */
    function getStateRoot(address smartAccount) external view returns (bytes32 stateRoot) {
        return accountStateRoots[smartAccount];
    }



    /*//////////////////////////////////////////////////////////////////////////
                                     MODULE LOGIC
    //////////////////////////////////////////////////////////////////////////*/

    
    /**
     * @notice Validates a user operation using a ZK proof
     * @dev The signature field must contain a valid ZK proof that proves the transaction is authorized by the required signers without revealing their identities.
     * @param userOp The user operation to validate
     * @param userOpHash The hash of the user operation
     * @return validationData Packed validation result (0 for success, 1 for failure)
     */
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) external override returns (uint256) {
        // Get state root for this account
        bytes32 stateRoot = accountStateRoots[userOp.sender];

        if (stateRoot == bytes32(0)) {
            return VALIDATION_FAILED;
        }

        // Verify the ZK proof with transaction details
        bool isValid = _verifyZKProofForUserOpValidation(
            stateRoot,
            userOpHash,
            userOp.signature
        );

        if (!isValid) {
            return VALIDATION_FAILED;
        }

        return VALIDATION_SUCCESS;
    }

    /**
     * @notice Validates a signature for ERC-1271 compatibility
     * @dev Verifies that a ZK proof authorizes the given hash for the sender
     * @param sender The smart account address
     * @param hash The hash being signed
     * @param data The ZK proof data
     * @return magicValue ERC1271_MAGICVALUE if valid, ERC1271_INVALID otherwise
     */
    function isValidSignatureWithSender(
        address sender,
        bytes32 hash,
        bytes calldata data
    ) external view override returns (bytes4) {
        // Get state root for this account
        bytes32 stateRoot = accountStateRoots[sender];

        if (stateRoot == bytes32(0)) {
            return ERC1271_INVALID;
        }

        // Verify the ZK proof
        bool isValid = _verifyZKProofForUserOpValidation(stateRoot, hash, data);

        if (!isValid) {
            return ERC1271_INVALID;
        }

        return ERC1271_MAGICVALUE;
    }

    /*//////////////////////////////////////////////////////////////////////////
                                     METADATA
    //////////////////////////////////////////////////////////////////////////*/

    /// @notice Returns the name of the module
    function name() external pure returns (string memory) {
        return "ZKMultiSigValidator";
    }

    /// @notice Returns the version of the module
    function version() external pure returns (string memory) {
        return "0.0.1";
    }

    /// @notice Checks if the module is of the specified type
    /// @param typeId The type ID to check
    /// @return True if the module is a validator type
    function isModuleType(uint256 typeId) external pure returns (bool) {
        return typeId == MODULE_TYPE_VALIDATOR;
    }

    /*//////////////////////////////////////////////////////////////////////////
                                     INTERNAL
    //////////////////////////////////////////////////////////////////////////*/

    /**
     * @dev Verifies a ZK proof
     * @param stateRoot The state root commitment
     * @param hash The hash to verify (transaction or message hash)
     * @param zkProof The zero-knowledge proof
     * @return True if the proof is valid
     */
    function _verifyZKProofForUserOpValidation(
        bytes32 stateRoot,
        bytes32 hash,
        bytes calldata zkProof
    ) 
        internal 
        view 
        returns (bool) 
    {
       // Construct public inputs for the ZK circuit
        // The circuit expects: [txn_hash[0], txn_hash[1], ..., txn_hash[31], state_root]
        bytes32[] memory publicInputs = new bytes32[](33);
        
        // Split the hash into individual bytes (circuit requirement)
        for (uint256 i = 0; i < 32; i++) {
            publicInputs[i] = bytes32(uint256(uint8(hash[i])));
        }
        
        // Add state root as the last public input
        publicInputs[32] = stateRoot;

        // Encode public signals for verification
        bytes memory encodedPublicInputs = abi.encode(publicInputs);

        // Verify using ERC8039 interface (proof-system agnostic)
        IERC8039 verifier = IERC8039(userOpValidator);
        
        try verifier.verifyProof(encodedPublicInputs, zkProof) returns (bytes4 magicValue) {
            return magicValue == ERC8039Constants.PROOF_MAGIC_VALUE;
        } catch {
            return false;
        }
    }

    /**
     * @notice Internal function to validate off-chain state
     * @param stateRoot The state root to validate
     * @param stateValidationProof The ZK proof of valid off-chain state
     * @return True if the proof is valid
     */
    function _verifyZKProofForOffChainStateValidation(
        bytes32 stateRoot,
        bytes memory stateValidationProof
    ) internal view returns (bool) {
        // Prepare public inputs for state validation (only stateRoot is public)
        bytes32[] memory publicInputs = new bytes32[](1);
        publicInputs[0] = stateRoot;
        bytes memory encodedPublicInputs = abi.encode(publicInputs);

        // Verify the state validation proof using ERC-8039 interface
        IERC8039 stateVerifier = IERC8039(stateValidator);
        
        try stateVerifier.verifyProof(encodedPublicInputs, stateValidationProof) returns (bytes4 magicValue) {
            return magicValue == ERC8039Constants.PROOF_MAGIC_VALUE;
        } catch {
            return false;
        }
    }

        /// @notice Checks if the module is initialized for a smart account
    /// @param smartAccount The address of the smart account
    /// @return True if initialized (stateRoot is non-zero), false otherwise
    function _isInitialized(address smartAccount) private view returns (bool) {
        return accountStateRoots[smartAccount] != bytes32(0);
    }

}
