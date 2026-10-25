// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

// ZK MultiSig Validator: Privacy-preserving multi-signature validator using zero-knowledge proofs
// Developed by Microchain Labs

import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";
import { IValidator } from "@biconomy/nexus/interfaces/modules/IValidator.sol";
import { MODULE_TYPE_VALIDATOR, VALIDATION_SUCCESS, VALIDATION_FAILED, ERC1271_MAGICVALUE, ERC1271_INVALID } from "@biconomy/nexus/types/Constants.sol";
import { ERC7739Validator } from "erc7739Validator/ERC7739Validator.sol";
import { IERC8039, ERC8039Constants } from "../../../ERC8039/IERC8039.sol";

/// @title ZKMultiSigValidator
/// @notice Validator module for Nexus smart accounts using ZK proofs for private multi-signature verification
/// @dev Implements privacy-preserving M-of-N threshold signatures where signer identities remain private.
///      Only a cryptographic commitment (state root) to the authorized signers is stored on-chain.
///      This validator uses zero-knowledge proofs to verify that sufficient signatures were provided
///      without revealing which specific signers approved the transaction.
///
///      ERC-1271 validation follows ERC-7739 (nested EIP-712): the signers sign a digest that is
///      wrapped with the account's EIP-712 domain, so a proof produced for one account cannot be
///      replayed against another account (or chain) sharing the same signer set.
///      The ERC-1271 `signature` is `zkProof ‖ APP_DOMAIN_SEPARATOR ‖ contents ‖ contentsDescription ‖ uint16(len)`
///      for the `TypedDataSign` flow, or just `zkProof` for the `PersonalSign` flow.
/// @author Microchain Labs
contract ZKMultiSigValidator is IValidator, ERC7739Validator {
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
     * @dev stateRoot is the cryptographic commitment(Instance/Public input) to the signer set + threshold + salt.
     *      The configuration is keyed by `msg.sender` (the smart account); every account can only ever
     *      configure its own slot, so this function needs no additional access control.
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
        // The smart account is always the caller of a validator module (ERC-7579);
        // `msg.sender == userOp.sender` under the EntryPoint, but `msg.sender` is canonical.
        bytes32 stateRoot = accountStateRoots[msg.sender];

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
     * @notice Validates a signature for ERC-1271 compatibility (ERC-7739 nested EIP-712 flow)
     * @dev The smart account is `msg.sender`; `sender` is the original requester of the ERC-1271 call
     *      (e.g. a dApp contract) and is only used to decide whether the nested EIP-712 wrapping may
     *      be skipped (see {_erc1271CallerIsSafe}).
     * @param sender The original ERC-1271 requester (forwarded by the account)
     * @param hash The hash being signed
     * @param data The ZK proof, optionally followed by the ERC-7739 `TypedDataSign` suffix
     * @return magicValue ERC1271_MAGICVALUE if valid, ERC1271_INVALID otherwise, or 0x77390001 for
     *         the ERC-7739 support-detection request
     */
    function isValidSignatureWithSender(
        address sender,
        bytes32 hash,
        bytes calldata data
    ) external view override returns (bytes4) {
        return _erc1271IsValidSignatureWithSender(sender, hash, _erc1271UnwrapSignature(data));
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
        return "0.0.2";
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
     * @dev ERC-7739 entry point. Overridden because the base implementation performs an ECDSA
     *      low-`s` malleability check on `signature[32:64]`, which is meaningless for (and would
     *      randomly reject) ZK proof bytes. Everything else mirrors {ERC7739Validator}.
     */
    function _erc1271IsValidSignatureWithSender(
        address sender,
        bytes32 hash,
        bytes calldata signature
    ) internal view override returns (bytes4) {
        // ERC-7739 support detection request: empty signature and hash == 0x7739...7739
        if (signature.length == 0 && uint256(hash) == ~uint256(0) / 0xffff * 0x7739) {
            return SUPPORTS_ERC7739_V1;
        }

        bool success = _erc1271IsValidSignatureViaSafeCaller(sender, hash, signature)
            || _erc1271IsValidSignatureViaNestedEIP712(hash, signature)
            || _erc1271IsValidSignatureViaRPC(hash, signature);

        return success ? ERC1271_MAGICVALUE : ERC1271_INVALID;
    }

    /**
     * @dev Called by the ERC-7739 machinery with the final (account-bound) digest and the raw ZK proof.
     *      The smart account is `msg.sender`.
     */
    function _erc1271IsValidSignatureNowCalldata(
        bytes32 hash,
        bytes calldata signature
    ) internal view override returns (bool) {
        bytes32 stateRoot = accountStateRoots[msg.sender];
        if (stateRoot == bytes32(0)) {
            return false;
        }
        return _verifyZKProofForUserOpValidation(stateRoot, hash, signature);
    }

    /**
     * @dev Callers for which the raw `hash` already commits to the account, so the nested
     *      EIP-712 wrapping can be skipped. Mirrors Nexus' K1Validator.
     *      - `MulticallerWithSigner` includes the account in the signed hash.
     *      - The account itself (`sender == msg.sender`), e.g. Nexus enable-mode signatures.
     */
    function _erc1271CallerIsSafe(address sender) internal view override returns (bool) {
        return sender == 0x000000000000D9ECebf3C23529de49815Dac1c4c || sender == msg.sender;
    }

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
