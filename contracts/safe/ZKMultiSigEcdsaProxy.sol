// SPDX-License-Identifier: LGPL-3.0-only
/* solhint-disable no-complex-fallback */
pragma solidity ^0.8.20;

/**
 * @title ZK MultiSig ECDSA Proxy
 * @dev A specialized proxy to a {ZKMultiSigEcdsaSingleton} signature validator implementation.
 * Using a proxy pattern for the signature validator greatly reduces deployment gas costs.
 */
contract ZKMultiSigEcdsaProxy {
    /**
     * @notice The {ZKMultiSigEcdsaSingleton} implementation to proxy to.
     */
    address internal immutable _SINGLETON;

    /**
     * @notice The Merkle root of authorized signers for this multisig instance.
     */
    bytes32 internal immutable _STATE_ROOT;

    /**
     * @notice The IERC8039 contract address used for ZK proof verification.
     */
    address internal immutable _VERIFIER;

    /**
     * @notice Creates a new ZK MultiSig ECDSA Proxy.
     * @param singleton The {ZKMultiSigEcdsaSingleton} implementation to proxy to.
     * @param stateRoot The Merkle root of authorized signers.
     * @param verifier The address of the IERC8039-HonkVerifier contract.
     */
    constructor(address singleton, bytes32 stateRoot, address verifier) {
        require(singleton != address(0), "ZK MultiSig: Invalid singleton address");
        require(stateRoot != bytes32(0), "ZK MultiSig: Invalid state root");
        require(verifier != address(0), "ZK MultiSig: Invalid verifier address");

        _SINGLETON = singleton;
        _STATE_ROOT = stateRoot;
        _VERIFIER = verifier;
    }

    /**
     * @dev Fallback function forwards all transactions and returns all received return data.
     * Appends the configuration (stateRoot and verifier) to calldata before delegating.
     */
    fallback() external payable {
        address singleton = _SINGLETON;
        bytes32 stateRoot = _STATE_ROOT;
        address verifier = _VERIFIER;

        // Note that we **intentionally** do not mark this assembly block as memory Safe even if it
        // is, as doing so causes the optimizer to behave sub-optimally. The proxy seems to be
        // compiled in its own compilation unit anyway, so it does not affect optimizations to the
        // rest of the contracts (in particular, {ZKMultiSigEcdsaFactory}).
        // solhint-disable-next-line no-inline-assembly
        assembly /* ("memory-safe") */ {
            // Forward the call to the singleton implementation. We append the configuration to the
            // calldata instead of having the singleton implementation read it from storage. This is
            // both more gas efficient and required for ERC-4337 compatibility.
            // This computes `data` to be `abi.encodePacked(msg.data, stateRoot, verifier)`.
            let ptr := mload(0x40)

            // Copy original calldata
            calldatacopy(ptr, 0x00, calldatasize())

            // Append stateRoot (32 bytes) at position: ptr + calldatasize()
            mstore(add(ptr, calldatasize()), stateRoot)

            // Append verifier address (20 bytes, left-padded to 32 bytes)
            // at position: ptr + calldatasize() + 32
            mstore(add(ptr, add(calldatasize(), 0x20)), shl(96, verifier))

            // Total calldata size = original + 52 bytes (32 for stateRoot + 20 for verifier)
            let success := delegatecall(gas(), singleton, ptr, add(calldatasize(), 0x34), 0, 0)

            returndatacopy(ptr, 0x00, returndatasize())
            if success {
                return(ptr, returndatasize())
            }
            revert(ptr, returndatasize())
        }
    }
}

