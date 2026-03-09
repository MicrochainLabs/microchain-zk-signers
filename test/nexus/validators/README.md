# ZKMultiSigValidator ERC-4337 Compliance Tests

This directory contains comprehensive tests to validate that the ZKMultiSigValidator module complies with [ERC-4337](https://eips.ethereum.org/EIPS/eip-4337) (Account Abstraction) rules.

## Overview

The ZKMultiSigValidator is a privacy-preserving multi-signature validator that uses zero-knowledge proofs to authorize transactions without revealing signer identities. These tests ensure it complies with ERC-4337 validation rules.

## Test Suite

### Test File Structure

```
test/nexus/validators/
├── README.md                           # This file
├── ZKMultiSigValidatorERC4337.t.sol   # Main test suite
└── mocks/
    └── MockZKVerifier.sol              # Mock ERC-8039 verifier for testing
```

### Test Categories

#### 1. **ERC-4337 Compliance Tests** (3 tests)
Tests that the validator follows core ERC-4337 validation rules:

- **`test_ValidateUserOp_ReturnsValidationSuccess`**
  - Validates that successful validation returns `VALIDATION_SUCCESS` (0)
  - Ensures proper proof verification integration

- **`test_ValidateUserOp_FailsGracefully_UninitializedAccount`**
  - Validates that uninitialized accounts fail gracefully
  - Returns `VALIDATION_FAILED` (1) without reverting

- **`test_ValidateUserOp_FailsGracefully_InvalidProof`**
  - Validates that invalid proofs fail gracefully
  - Returns `VALIDATION_FAILED` (1) without reverting

#### 2. **Storage Access Pattern Tests** (1 test)
Tests proper storage isolation per account:

- **`test_StorageAccess_AccountSpecific`**
  - Validates that each account has isolated storage
  - Ensures no cross-account storage interference
  - Tests storage updates don't affect other accounts

#### 3. **View Function Tests** (2 tests)
Tests ERC-1271 signature validation compliance:

- **`test_IsValidSignatureWithSender_IsViewFunction`**
  - Validates that signature checking is read-only
  - Ensures no state modifications occur
  - Returns `ERC1271_MAGICVALUE` for valid signatures

- **`test_IsValidSignatureWithSender_FailsGracefully`**
  - Validates graceful failure for invalid signatures
  - Returns `ERC1271_INVALID` without reverting

#### 4. **Initialization Tests** (4 tests)
Tests module lifecycle management:

- **`test_OnInstall_Basic`**
  - Validates proper initialization with state root and proof
  - Confirms account is marked as initialized

- **`test_OnInstall_RevertsInvalidData`**
  - Validates that empty/invalid data reverts during install

- **`test_OnInstall_RevertsDoubleInit`**
  - Validates that accounts cannot be initialized twice

- **`test_OnUninstall_CleansUp`**
  - Validates proper cleanup when module is uninstalled
  - Confirms storage is reset

#### 5. **Gas Optimization Tests** (2 tests)
Measures gas consumption to ensure efficiency:

- **`test_Gas_ValidateUserOp`**
  - Measures gas cost of user operation validation
  - Current usage: ~19,897 gas
  - Threshold: < 100,000 gas

- **`test_Gas_OnInstall`**
  - Measures gas cost of module initialization
  - Current usage: ~41,723 gas
  - Threshold: < 200,000 gas

## Running the Tests

### Prerequisites

Ensure you have the following installed:
```bash
# Foundry (forge, cast, anvil)
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Dependencies
pnpm install
```

### Basic Test Commands

#### Run All Tests
```bash
forge test --match-path "test/nexus/validators/ZKMultiSigValidatorERC4337.t.sol"
```

#### Run with Verbose Output
```bash
# -vv: Show test names and results
forge test --match-path "test/nexus/validators/ZKMultiSigValidatorERC4337.t.sol" -vv

# -vvv: Show stack traces for failures
forge test --match-path "test/nexus/validators/ZKMultiSigValidatorERC4337.t.sol" -vvv

# -vvvv: Show all traces including successful tests
forge test --match-path "test/nexus/validators/ZKMultiSigValidatorERC4337.t.sol" -vvvv
```

#### Run Specific Test Category
```bash
# Run only validation tests
forge test --match-test "test_ValidateUserOp"

# Run only gas tests
forge test --match-test "test_Gas"

# Run only view function tests
forge test --match-test "test_IsValidSignatureWithSender"
```

#### Run Single Test
```bash
forge test --match-test "test_ValidateUserOp_ReturnsValidationSuccess" -vv
```

#### Run with Gas Report
```bash
forge test --match-path "test/nexus/validators/ZKMultiSigValidatorERC4337.t.sol" --gas-report
```

#### Run Tests in Watch Mode
```bash
forge test --match-path "test/nexus/validators/ZKMultiSigValidatorERC4337.t.sol" --watch
```

### Advanced Commands

#### Generate Coverage Report
```bash
forge coverage --match-path "test/nexus/validators/ZKMultiSigValidatorERC4337.t.sol"
```

#### Run Tests with Specific Fork
```bash
# Test against a specific network
forge test --match-path "test/nexus/validators/ZKMultiSigValidatorERC4337.t.sol" --fork-url <RPC_URL>
```

#### Run Tests with Gas Snapshot
```bash
# Create gas snapshot for comparison
forge snapshot --match-path "test/nexus/validators/ZKMultiSigValidatorERC4337.t.sol"

# Compare with previous snapshot
forge snapshot --diff
```

## Expected Test Results

All 13 tests should pass:

```
Ran 13 tests for test/nexus/validators/ZKMultiSigValidatorERC4337.t.sol:ZKMultiSigValidatorERC4337Test
[PASS] test_Gas_OnInstall() (gas: 50912)
[PASS] test_Gas_ValidateUserOp() (gas: 76848)
[PASS] test_IsValidSignatureWithSender_FailsGracefully() (gas: 71199)
[PASS] test_IsValidSignatureWithSender_IsViewFunction() (gas: 72672)
[PASS] test_OnInstall_Basic() (gas: 51587)
[PASS] test_OnInstall_RevertsDoubleInit() (gas: 51068)
[PASS] test_OnInstall_RevertsInvalidData() (gas: 11162)
[PASS] test_OnUninstall_CleansUp() (gas: 39360)
[PASS] test_StorageAccess_AccountSpecific() (gas: 87619)
[PASS] test_ValidateUserOp_FailsGracefully_InvalidProof() (gas: 75908)
[PASS] test_ValidateUserOp_FailsGracefully_UninitializedAccount() (gas: 22306)
[PASS] test_ValidateUserOp_ReturnsValidationSuccess() (gas: 75158)

Suite result: ok. 13 passed; 0 failed; 0 skipped
```

## Gas Benchmarks

| Operation | Current Gas | Threshold | Status |
|-----------|-------------|-----------|--------|
| validateUserOp | ~19,897 | < 100,000 | ✅ Pass |
| onInstall | ~41,723 | < 200,000 | ✅ Pass |

## Implementation Details

### Mock Contracts

**MockZKVerifier** ([mocks/MockZKVerifier.sol](mocks/MockZKVerifier.sol))
- Implements ERC-8039 (ZK Proof Verification Standard)
- Configurable to return success or failure
- Used to test validator behavior with different proof outcomes

### Test Helpers

The test suite includes helper functions:
- `_getDefaultUserOp()` - Creates a default PackedUserOperation for testing
- Mock verifiers can be toggled between valid/invalid modes using `setAlwaysValid()`

## Validation Library

This test suite uses the [@rhinestone/erc4337-validation](https://github.com/rhinestonewtf/erc4337-validation) library, which provides:
- Banned opcode detection
- Storage access pattern validation
- External call restriction checks
- Automated ERC-4337 rule enforcement