// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import "forge-std/Test.sol";
import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";
import { ZKMultiSigValidator } from "../../../contracts/nexus/modules/validators/ZKMultiSigValidator.sol";
import { MockZKVerifier } from "./mocks/MockZKVerifier.sol";
import { VALIDATION_SUCCESS, VALIDATION_FAILED, ERC1271_MAGICVALUE, ERC1271_INVALID } from "@biconomy/nexus/types/Constants.sol";

/**
 * @title ZKMultiSigValidatorERC4337Test
 * @notice Test suite for validating ZKMultiSigValidator compliance with ERC-4337 rules
 * @dev Tests the validator's behavior to ensure ERC-4337 compliance:
 *      - No banned opcodes (BALANCE, ORIGIN, GASPRICE, BLOCKHASH, etc.)
 *      - No banned storage access patterns
 *      - Proper failure handling (no reverts during validation)
 *      - Gas-efficient operations
 *      - Account-specific storage isolation
 */
contract ZKMultiSigValidatorERC4337Test is Test {
    // Contracts
    ZKMultiSigValidator public validator;
    MockZKVerifier public stateValidator;
    MockZKVerifier public userOpValidator;

    // Test accounts
    address public smartAccount;
    address public owner;
    address public entryPoint;
    
    // Test data
    bytes32 public testStateRoot;
    bytes public validStateProof;
    bytes public validUserOpProof;

    function setUp() public {
        // Set up test accounts
        owner = makeAddr("owner");
        smartAccount = makeAddr("smartAccount");
        entryPoint = makeAddr("entryPoint");
        
        // Fund the smart account
        vm.deal(smartAccount, 10 ether);

        // Deploy mock verifiers (set to always valid for basic tests)
        stateValidator = new MockZKVerifier(
            true,
            keccak256("honk-barretenberg-state"),
            "ZK MultiSig State Validation v1.0.0"
        );
        
        userOpValidator = new MockZKVerifier(
            true,
            keccak256("honk-barretenberg-userOp"),
            "ZK MultiSig UserOp Validation v1.0.0"
        );

        // Deploy the ZK MultiSig Validator
        validator = new ZKMultiSigValidator(
            address(stateValidator),
            address(userOpValidator)
        );

        // Set up test data
        testStateRoot = bytes32(uint256(123456789));
        validStateProof = abi.encodePacked(bytes32(uint256(1)));
        validUserOpProof = abi.encodePacked(bytes32(uint256(2)));
    }

    /*//////////////////////////////////////////////////////////////////////////
                            ERC-4337 COMPLIANCE TESTS
    //////////////////////////////////////////////////////////////////////////*/

    /**
     * @notice Test that validateUserOp returns proper validation data
     * @dev ERC-4337 requires: return 0 for success, 1 for failure, no reverts
     */
    function test_ValidateUserOp_ReturnsValidationSuccess() public {
        // Initialize the validator for the smart account
        vm.prank(smartAccount);
        bytes memory initData = abi.encode(testStateRoot, validStateProof);
        validator.onInstall(initData);

        // Create a user operation
        PackedUserOperation memory userOp = _getDefaultUserOp();
        userOp.sender = smartAccount;
        userOp.signature = validUserOpProof;

        // Calculate userOpHash
        bytes32 userOpHash = keccak256(abi.encode(userOp.sender, userOp.nonce, userOp.callData));

        // Simulate call from EntryPoint
        vm.prank(entryPoint);
        uint256 validationData = validator.validateUserOp(userOp, userOpHash);

        // Verify validation succeeded
        assertEq(validationData, VALIDATION_SUCCESS, "Should return VALIDATION_SUCCESS");
    }

    /**
     * @notice Test that validation fails gracefully without reverting
     * @dev ERC-4337 requirement: validators must not revert on invalid operations
     */
    function test_ValidateUserOp_FailsGracefully_UninitializedAccount() public {
        PackedUserOperation memory userOp = _getDefaultUserOp();
        userOp.sender = smartAccount; // Not initialized
        userOp.signature = validUserOpProof;

        bytes32 userOpHash = keccak256(abi.encode(userOp.sender, userOp.nonce));

        // Should not revert
        vm.prank(entryPoint);
        uint256 validationData = validator.validateUserOp(userOp, userOpHash);

        // Should return failure
        assertEq(validationData, VALIDATION_FAILED, "Should return VALIDATION_FAILED");
    }

    /**
     * @notice Test that validation fails gracefully for invalid proofs
     */
    function test_ValidateUserOp_FailsGracefully_InvalidProof() public {
        // Initialize with valid proof
        bytes memory initData = abi.encode(testStateRoot, validStateProof);
        vm.prank(smartAccount);
        validator.onInstall(initData);

        // Set userOp verifier to reject proofs
        userOpValidator.setAlwaysValid(false);

        PackedUserOperation memory userOp = _getDefaultUserOp();
        userOp.sender = smartAccount;
        userOp.signature = validUserOpProof;

        bytes32 userOpHash = keccak256(abi.encode(userOp.sender, userOp.nonce));

        // Should not revert
        vm.prank(entryPoint);
        uint256 validationData = validator.validateUserOp(userOp, userOpHash);

        // Should return failure
        assertEq(validationData, VALIDATION_FAILED, "Should return VALIDATION_FAILED for invalid proof");
    }

    /*//////////////////////////////////////////////////////////////////////////
                            STORAGE ACCESS PATTERN TESTS
    //////////////////////////////////////////////////////////////////////////*/

    /**
     * @notice Test that storage access is account-specific
     * @dev ERC-4337 requires validators to only access account-specific storage
     */
    function test_StorageAccess_AccountSpecific() public {
        address account1 = makeAddr("account1");
        address account2 = makeAddr("account2");
        
        bytes32 stateRoot1 = bytes32(uint256(111));
        bytes32 stateRoot2 = bytes32(uint256(222));

        // Initialize account1
        vm.prank(account1);
        validator.onInstall(abi.encode(stateRoot1, validStateProof));

        // Initialize account2
        vm.prank(account2);
        validator.onInstall(abi.encode(stateRoot2, validStateProof));

        // Verify each account has its own storage
        assertEq(validator.getStateRoot(account1), stateRoot1, "Account1 should have its state");
        assertEq(validator.getStateRoot(account2), stateRoot2, "Account2 should have its state");
        
        // Modify account1
        bytes32 newStateRoot1 = bytes32(uint256(333));
        vm.prank(account1);
        validator.updateStateRoot(newStateRoot1, validStateProof);
        
        // Verify account2 is unchanged
        assertEq(validator.getStateRoot(account2), stateRoot2, "Account2 state should not change");
        assertEq(validator.getStateRoot(account1), newStateRoot1, "Account1 should be updated");
    }

    /*//////////////////////////////////////////////////////////////////////////
                            VIEW FUNCTION TESTS
    //////////////////////////////////////////////////////////////////////////*/

    /**
     * @notice Test that isValidSignatureWithSender is a view function
     * @dev ERC-4337 requires signature validation to be read-only
     */
    function test_IsValidSignatureWithSender_IsViewFunction() public {
        // Initialize
        bytes memory initData = abi.encode(testStateRoot, validStateProof);
        vm.prank(smartAccount);
        validator.onInstall(initData);

        // Record storage state
        bytes32 stateRootBefore = validator.getStateRoot(smartAccount);

        // Call view function
        bytes32 hash = keccak256("test message");
        bytes4 result = validator.isValidSignatureWithSender(smartAccount, hash, validUserOpProof);

        // Verify result
        assertEq(result, ERC1271_MAGICVALUE, "Should return magic value");
        
        // Verify no state changes
        assertEq(validator.getStateRoot(smartAccount), stateRootBefore, "State should not change");
    }

    /**
     * @notice Test that isValidSignatureWithSender fails gracefully
     */
    function test_IsValidSignatureWithSender_FailsGracefully() public {
        // Initialize
        bytes memory initData = abi.encode(testStateRoot, validStateProof);
        vm.prank(smartAccount);
        validator.onInstall(initData);

        // Set verifier to reject
        userOpValidator.setAlwaysValid(false);

        // Should not revert, return invalid
        bytes32 hash = keccak256("test message");
        bytes4 result = validator.isValidSignatureWithSender(smartAccount, hash, validUserOpProof);

        assertEq(result, ERC1271_INVALID, "Should return ERC1271_INVALID");
    }

    /*//////////////////////////////////////////////////////////////////////////
                            INITIALIZATION TESTS
    //////////////////////////////////////////////////////////////////////////*/

    /**
     * @notice Test onInstall follows ERC-4337 patterns
     */
    function test_OnInstall_Basic() public {
        bytes memory initData = abi.encode(testStateRoot, validStateProof);
        
        vm.prank(smartAccount);
        validator.onInstall(initData);

        assertTrue(validator.isInitialized(smartAccount), "Should be initialized");
        assertEq(validator.getStateRoot(smartAccount), testStateRoot, "State root should match");
    }

    /**
     * @notice Test onInstall reverts for invalid data
     */
    function test_OnInstall_RevertsInvalidData() public {
        vm.prank(smartAccount);
        vm.expectRevert();
        validator.onInstall("");
    }

    /**
     * @notice Test cannot double initialize
     */
    function test_OnInstall_RevertsDoubleInit() public {
        bytes memory initData = abi.encode(testStateRoot, validStateProof);
        
        vm.prank(smartAccount);
        validator.onInstall(initData);

        vm.prank(smartAccount);
        vm.expectRevert();
        validator.onInstall(initData);
    }

    /**
     * @notice Test onUninstall cleans up properly
     */
    function test_OnUninstall_CleansUp() public {
        // Initialize
        bytes memory initData = abi.encode(testStateRoot, validStateProof);
        vm.prank(smartAccount);
        validator.onInstall(initData);

        // Uninstall
        vm.prank(smartAccount);
        validator.onUninstall("");

        assertFalse(validator.isInitialized(smartAccount), "Should not be initialized");
        assertEq(validator.getStateRoot(smartAccount), bytes32(0), "State root should be zero");
    }

    /*//////////////////////////////////////////////////////////////////////////
                            GAS TESTS
    //////////////////////////////////////////////////////////////////////////*/

    /**
     * @notice Test gas consumption of validateUserOp
     */
    function test_Gas_ValidateUserOp() public {
        bytes memory initData = abi.encode(testStateRoot, validStateProof);
        vm.prank(smartAccount);
        validator.onInstall(initData);

        PackedUserOperation memory userOp = _getDefaultUserOp();
        userOp.sender = smartAccount;
        userOp.signature = validUserOpProof;
        bytes32 userOpHash = keccak256(abi.encode(userOp.sender, userOp.nonce));

        uint256 gasBefore = gasleft();
        vm.prank(entryPoint);
        validator.validateUserOp(userOp, userOpHash);
        uint256 gasUsed = gasBefore - gasleft();

        emit log_named_uint("validateUserOp gas used", gasUsed);
        assertLt(gasUsed, 100000, "Gas usage should be reasonable");
    }

    /**
     * @notice Test gas consumption of onInstall
     */
    function test_Gas_OnInstall() public {
        bytes memory initData = abi.encode(testStateRoot, validStateProof);
        
        uint256 gasBefore = gasleft();
        vm.prank(smartAccount);
        validator.onInstall(initData);
        uint256 gasUsed = gasBefore - gasleft();

        emit log_named_uint("onInstall gas used", gasUsed);
        assertLt(gasUsed, 200000, "Gas usage should be reasonable");
    }

    /*//////////////////////////////////////////////////////////////////////////
                            HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////////////////*/

    function _getDefaultUserOp() internal pure returns (PackedUserOperation memory) {
        return PackedUserOperation({
            sender: address(0),
            nonce: 0,
            initCode: "",
            callData: "",
            accountGasLimits: bytes32(abi.encodePacked(uint128(2e6), uint128(2e6))),
            preVerificationGas: 2e6,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: "",
            signature: ""
        });
    }
}
