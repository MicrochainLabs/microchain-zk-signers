// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.20;

import {ZKMultiSigEcdsaProxy} from "./ZKMultiSigEcdsaProxy.sol";
import {ZKMultiSigEcdsaSingleton} from "./ZKMultiSigEcdsaSingleton.sol";
import {IERC8039, ERC8039Constants} from "./interfaces/IERC8039.sol";

/**
 * @title ZK MultiSig ECDSA Factory
 * @dev A factory contract for creating ZK multi-signature signers. Additionally, the factory
 * supports signature verification without deploying signer proxies.
 * @custom:security-contact bounty@safe.global
 */
contract ZKMultiSigEcdsaFactory {
    /**
     * @notice The {ZKMultiSigEcdsaSingleton} implementation that is used for signature
     * verification by this contract and any proxies it deploys.
     */
    ZKMultiSigEcdsaSingleton public immutable SINGLETON;

    /**
     * @notice The private state validator ZK verifier contract used to validate state configurations.
     * @dev This is set once during deployment and used for all signer creations.
     */
    address public immutable STATE_VALIDATOR;

    /**
     * @notice Emitted when a new signer proxy is created.
     * @param signer The address of the created signer proxy.
     * @param stateRoot The Merkle root of authorized signers for this instance.
     * @param zkMultiSigEcdsaVerifier The address of the TX validator ZK verifier address used by this instance.
     */
    event SignerCreated(address indexed signer, bytes32 indexed stateRoot, address indexed zkMultiSigEcdsaVerifier);

    /**
     * @notice Creates a new ZK MultiSig ECDSA factory contract.
     * @dev The {ZKMultiSigEcdsaSingleton} singleton implementation is created as part of
     * this constructor. This ensures that the singleton contract is known, and lets us make
     * certain assumptions about how it works.
     * @param stateValidator The address of the state validator verifier contract.
     */
    constructor(address stateValidator) {
        require(stateValidator != address(0), "Invalid state validator address");
        SINGLETON = new ZKMultiSigEcdsaSingleton();
        STATE_VALIDATOR = stateValidator;
    }

    /**
     * @notice Computes the deterministic address for a signer proxy.
     * @dev Uses CREATE2 to calculate the address where a proxy would be deployed.
     * @param stateRoot The Merkle root of authorized signers.
     * @param zkMultiSigEcdsaVerifier The address of the ZK Multi-Sig ECDSA Verifier contract.
     * @return signer The deterministic address of the signer proxy.
     */
    function getSigner(bytes32 stateRoot, address zkMultiSigEcdsaVerifier) public view returns (address signer) {
        bytes32 codeHash = keccak256(
            abi.encodePacked(
                type(ZKMultiSigEcdsaProxy).creationCode,
                uint256(uint160(address(SINGLETON))),
                stateRoot,
                uint256(uint160(zkMultiSigEcdsaVerifier))
            )
        );
        signer = address(
            uint160(uint256(keccak256(abi.encodePacked(hex"ff", address(this), bytes32(0), codeHash))))
        );
    }

    /**
     * @notice Creates a new ZK MultiSig signer proxy with state validation.
     * @dev Verifies the state configuration proof before deploying the proxy.
     * If a proxy already exists at the computed address, this function does nothing.
     * Uses CREATE2 with salt=0 for deterministic deployment.
     * @param stateRoot The Merkle root of authorized signers (also serves as public input to state validation).
     * @param zkMultiSigEcdsaVerifier The address of the ZK Multi-Sig ECDSA Verifier contract for signature verification.
     * @param privateStateValidationProof The ZK proof proving the state configuration is valid.
     * @return signer The address of the signer proxy (existing or newly created).
     */
    function createSigner(
        bytes32 stateRoot,
        address zkMultiSigEcdsaVerifier,
        bytes calldata privateStateValidationProof
    ) external returns (address signer) {
        // Prepare public inputs for state validation (only stateRoot is public)
        bytes32[] memory publicInputs = new bytes32[](1);
        publicInputs[0] = stateRoot;
        bytes memory encodedPublicInputs = abi.encode(publicInputs);
        
        // Verify the state validation proof using ERC8039 interface
        bytes4 magicValue = IERC8039(STATE_VALIDATOR).verifyProof(
            encodedPublicInputs,
            privateStateValidationProof
        );
        
        require(
            magicValue == ERC8039Constants.PROOF_MAGIC_VALUE,
            "State validation proof verification failed"
        );

        // Proceed with proxy deployment
        signer = getSigner(stateRoot, zkMultiSigEcdsaVerifier);

        if (_hasNoCode(signer)) {
            ZKMultiSigEcdsaProxy created = new ZKMultiSigEcdsaProxy{salt: bytes32(0)}(
                address(SINGLETON),
                stateRoot,
                zkMultiSigEcdsaVerifier
            );
            assert(address(created) == signer);
            emit SignerCreated(signer, stateRoot, zkMultiSigEcdsaVerifier);
        }
    }

    /**
     * @notice Verifies a signature for a given signer configuration without deploying a proxy.
     * @dev This is useful for verifying signatures before deployment or for one-time verification.
     * Performs a staticcall to the singleton with the configuration appended to calldata.
     * @param message The message hash that was signed.
     * @param signature The ZK proof signature to verify.
     * @param stateRoot The Merkle root of authorized signers.
     * @param verifier The address of the HonkVerifier contract.
     * @return magicValue The ERC-1271 magic value (0x1626ba7e) if valid, 0x00000000 otherwise.
     */
    function isValidSignatureForSigner(
        bytes32 message,
        bytes calldata signature,
        bytes32 stateRoot,
        address verifier
    ) external view returns (bytes4 magicValue) {
        address singleton = address(SINGLETON);
        bytes memory data = abi.encodePacked(
            abi.encodeWithSignature("isValidSignature(bytes32,bytes)", message, signature),
            stateRoot,
            verifier
        );

        // solhint-disable-next-line no-inline-assembly
        assembly ("memory-safe") {
            // staticcall to the singleton contract with return size given as 32 bytes. The
            // singleton contract is known and immutable so it is safe to specify return size.
            if staticcall(gas(), singleton, add(data, 0x20), mload(data), 0, 32) {
                magicValue := mload(0)
            }
        }
    }

    /**
     * @dev Checks if the provided account has no code.
     * @param account The address of the account to check.
     * @return result True if the account has no code, false otherwise.
     */
    function _hasNoCode(address account) internal view returns (bool result) {
        // solhint-disable-next-line no-inline-assembly
        assembly ("memory-safe") {
            result := iszero(extcodesize(account))
        }
    }
}

