// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

// ZK MultiSig Validator Factory: Privacy-preserving multi-signature validator factory
// Developed by Microchain Labs

import { NexusBootstrap } from "@biconomy/nexus/utils/NexusBootstrap.sol";
import { ProxyLib } from "@biconomy/nexus/lib/ProxyLib.sol";

/// @title ZKMultiSigValidatorFactory for Nexus Account
/// @notice Factory for creating Nexus accounts with ZK multi-signature validator
/// @dev Creates Nexus accounts pre-configured with the ZKMultiSigValidator module
/// @author Microchain Labs
contract ZKMultiSigValidatorFactory {
    /// @notice Stores the implementation contract address for Nexus accounts
    /// @dev Set once upon deployment and cannot be changed afterwards
    address public immutable ACCOUNT_IMPLEMENTATION;

    /// @notice Stores the ZK MultiSig Validator module address
    /// @dev Set once upon deployment and cannot be changed afterwards
    address public immutable ZK_MULTISIG_VALIDATOR;

    /// @notice Stores the Bootstrapper module address
    /// @dev Set once upon deployment and cannot be changed afterwards
    NexusBootstrap public immutable BOOTSTRAPPER;

    /// @notice Emitted when a new Nexus account with ZK MultiSig validator is created
    event ZKMultiSigAccountCreated(
        address indexed account, 
        bytes32 indexed stateRoot, 
        uint256 index
    );

    /// @notice Error thrown when a zero address is provided
    error ZeroAddressNotAllowed();

    /// @notice Error thrown when invalid state root is provided
    error InvalidStateRoot();

    /// @notice Error thrown when invalid data is provided
    error InvalidData();

    /**
     * @notice Constructor to set immutable variables
     * @param implementation The address of the Nexus implementation
     * @param zkMultiSigValidator The address of the ZK MultiSig Validator module
     * @param bootstrapper The address of the Bootstrapper module
     */
    constructor(
        address implementation,
        address zkMultiSigValidator,
        NexusBootstrap bootstrapper
    ) {
        require(
            implementation != address(0) && 
            zkMultiSigValidator != address(0) && 
            address(bootstrapper) != address(0),
            ZeroAddressNotAllowed()
        );
        
        ACCOUNT_IMPLEMENTATION = implementation;
        ZK_MULTISIG_VALIDATOR = zkMultiSigValidator;
        BOOTSTRAPPER = bootstrapper;
    }

    /**
     * @notice Creates a new Nexus account with ZK MultiSig validator
     * @param stateRoot The cryptographic commitment to the signer set (hash of signers + threshold + salt)
     * @param stateValidationProof The ZK proof validating the initial off-chain state
     * @param index Unique index for deterministic address generation
     * @return account The address of the newly created Nexus account
     * @dev Uses CREATE2 for deterministic deployment
     */
    function createAccount(
        bytes32 stateRoot,
        bytes calldata stateValidationProof,
        uint256 index
    ) 
        external 
        payable 
        returns (address payable account) 
    {
        require(stateRoot != bytes32(0), InvalidStateRoot());
        require(stateValidationProof.length > 0, InvalidData());

        // Compute deterministic salt
        bytes32 salt = keccak256(abi.encodePacked(stateRoot, keccak256(stateValidationProof), index));

        // Prepare validator initialization data: abi.encode(stateRoot, stateValidationProof)
        bytes memory validatorInitData = abi.encode(stateRoot, stateValidationProof);

        // Create initialization data for NexusBootstrap
        bytes memory initData = abi.encode(
            address(BOOTSTRAPPER),
            abi.encodeCall(
                BOOTSTRAPPER.initNexusWithSingleValidatorNoRegistry,
                (
                    ZK_MULTISIG_VALIDATOR,
                    validatorInitData
                )
            )
        );

        // Deploy the Nexus account using ProxyLib
        bool alreadyDeployed;
        (alreadyDeployed, account) = ProxyLib.deployProxy(ACCOUNT_IMPLEMENTATION, salt, initData);
        
        if (!alreadyDeployed) {
            emit ZKMultiSigAccountCreated(account, stateRoot, index);
        }
        
        return account;
    }

    /**
     * @notice Computes the expected address of a Nexus account
     * @param stateRoot The cryptographic commitment to the signer set
     * @param stateValidationProof The ZK proof validating the initial off-chain state
     * @param index Unique index for deterministic address generation
     * @return expectedAddress The deterministic address where the account will be deployed
     * @dev Useful for computing account addresses before deployment
     */
    function computeAccountAddress(
        bytes32 stateRoot,
        bytes calldata stateValidationProof,
        uint256 index
    )
        external
        view
        returns (address payable expectedAddress)
    {
        // Compute the same salt used in createAccount
        bytes32 salt = keccak256(abi.encodePacked(stateRoot, keccak256(stateValidationProof), index));

        // Prepare the same initialization data
        bytes memory validatorInitData = abi.encode(stateRoot, stateValidationProof);

        bytes memory initData = abi.encode(
            address(BOOTSTRAPPER),
            abi.encodeCall(
                BOOTSTRAPPER.initNexusWithSingleValidatorNoRegistry,
                (
                    ZK_MULTISIG_VALIDATOR,
                    validatorInitData
                )
            )
        );

        // Compute predicted address
        return ProxyLib.predictProxyAddress(ACCOUNT_IMPLEMENTATION, salt, initData);
    }
}
