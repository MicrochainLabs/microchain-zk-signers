# ZK MultiSig ECDSA Contracts

This directory contains a gas-efficient ZK proof-based multi-signature verification system using the **proxy pattern**. The implementation enables multiple multisig instances (with different signer sets) while minimizing deployment costs.

## Architecture Overview

The system uses a **proxy pattern** where:
- **Singleton** = Shared ZK verification logic (deployed once)
- **Proxy** = Lightweight instances with unique configuration (deployed per signer set)
- **Factory** = Manages proxy creation and provides utilities

```
┌─────────────────────────────────────────────────────────────┐
│               ZKMultiSigEcdsaFactory                        │
│  - Deploys singleton once in constructor                   │
│  - Creates proxies with CREATE2 (deterministic addresses)  │
│  - Can verify signatures without deploying                 │
└─────────────────────────────────────────────────────────────┘
                    │                           │
                    │ creates                   │ calls
                    ▼                           ▼
    ┌───────────────────────────┐   ┌──────────────────────────┐
    │  ZKMultiSigEcdsaProxy     │   │ZKMultiSigEcdsaSingleton  │
    │ - Stores config immutably │   │ - ZK proof verification  │
    │ - Appends to calldata     │   │ - Reads config from      │
    │ - Delegates to singleton  │───│   end of calldata        │
    └───────────────────────────┘   └──────────────────────────┘
              delegatecall
```

---

## Contract Descriptions

### 1. ZKMultiSigEcdsaSingleton.sol

**Purpose**: The shared implementation contract that performs ZK proof verification for multi-signature validation.

**Key Features**:
- Contains the core `_verifySignature` function that validates ZK proofs
- Retrieves configuration (stateRoot and verifier address) from the **end of calldata** (not storage!)
- Inherits from `SignatureValidator` to provide EIP-1271 signature validation

**Configuration Reading**:

The singleton expects the proxy to append 52 bytes of configuration to the calldata:
- **Last 52 bytes**: `stateRoot` (32 bytes) + `verifierAddress` (20 bytes)

```solidity
function getConfiguration() public pure returns (bytes32 stateRoot, address verifierAddress) {
    assembly ("memory-safe") {
        // Read stateRoot from calldatasize - 52
        stateRoot := calldataload(sub(calldatasize(), 52))
        // Read verifierAddress from calldatasize - 20, shift right by 96 bits
        verifierAddress := shr(96, calldataload(sub(calldatasize(), 20)))
    }
}
```

**Why read from calldata?**
- Avoids expensive storage reads (saves gas!)
- Required for ERC-4337 compatibility
- Enables stateless signature verification

**ZK Proof Verification**:

The contract constructs the public inputs for the circuit:
- First 32 positions: Each byte of the message hash (TODO: optimize this)
- Position 32: The `stateRoot` (Merkle root of authorized signers)

Then calls the configured `HonkVerifier` to verify the ZK proof.

---

### 2. ZKMultiSigEcdsaProxy.sol

**Purpose**: A lightweight proxy contract that stores the multisig configuration and delegates calls to the singleton.

**Key Features**:
- Stores configuration in **immutable variables** (very gas efficient, stored in bytecode)
- Minimal bytecode size = ~85% lower deployment costs
- Custom `fallback()` function that appends configuration to calldata before delegating

**Storage**:
```solidity
address internal immutable _SINGLETON;     // Address of the singleton implementation
bytes32 internal immutable _STATE_ROOT;    // Merkle root of authorized signers
address internal immutable _VERIFIER;      // HonkVerifier contract address
```

**How the Proxy Works**:

1. Any call to the proxy triggers the `fallback()` function
2. The function loads the immutable configuration values
3. It constructs new calldata: `original_calldata + stateRoot + verifier`
4. Performs `delegatecall` to the singleton with the modified calldata
5. Returns the result to the caller

```solidity
fallback() external payable {
    // Load configuration from immutables
    address singleton = _SINGLETON;
    bytes32 stateRoot = _STATE_ROOT;
    address verifier = _VERIFIER;

    assembly {
        // Copy original calldata
        calldatacopy(ptr, 0x00, calldatasize())
        
        // Append stateRoot (32 bytes)
        mstore(add(ptr, calldatasize()), stateRoot)
        
        // Append verifier address (20 bytes, left-padded)
        mstore(add(ptr, add(calldatasize(), 0x20)), shl(96, verifier))
        
        // Delegate to singleton with extended calldata (original + 52 bytes)
        let success := delegatecall(gas(), singleton, ptr, add(calldatasize(), 0x34), 0, 0)
        // ...
    }
}
```

**Gas Optimization**:
- Immutable variables are stored in bytecode (no SLOAD needed)
- Calldata append pattern avoids storage entirely
- Proxy bytecode is minimal (constructor args + fallback logic only)

---

### 3. ZKMultiSigEcdsaFactory.sol

**Purpose**: Factory contract that deploys proxies and provides signature verification utilities.

**Key Features**:
- Deploys the singleton once in its constructor
- Creates proxy instances using CREATE2 (deterministic addresses)
- Provides signature verification without needing to deploy a proxy
- Emits events for tracking signer creation

**Main Functions**:

#### `getSigner(bytes32 stateRoot, address verifier)`

Computes the deterministic address where a proxy would be deployed using CREATE2.

```solidity
function getSigner(bytes32 stateRoot, address verifier) 
    public view returns (address signer) 
{
    bytes32 codeHash = keccak256(
        abi.encodePacked(
            type(ZKMultiSigEcdsaProxy).creationCode,
            uint256(uint160(address(SINGLETON))),
            stateRoot,
            uint256(uint160(verifier))
        )
    );
    signer = address(uint160(uint256(
        keccak256(abi.encodePacked(hex"ff", address(this), bytes32(0), codeHash))
    )));
}
```

**Use case**: Check if a signer exists, or get its address before deployment.

#### `createSigner(bytes32 stateRoot, address verifier)`

Deploys a new proxy if one doesn't already exist at the computed address.

```solidity
function createSigner(bytes32 stateRoot, address verifier) 
    external returns (address signer) 
{
    signer = getSigner(stateRoot, verifier);

    if (_hasNoCode(signer)) {
        ZKMultiSigEcdsaProxy created = new ZKMultiSigEcdsaProxy{salt: bytes32(0)}(
            address(SINGLETON),
            stateRoot,
            verifier
        );
        assert(address(created) == signer);
        emit SignerCreated(signer, stateRoot, verifier);
    }
}
```

**Features**:
- Idempotent (safe to call multiple times)
- Uses CREATE2 with salt=0 for deterministic deployment
- Emits `SignerCreated` event on successful deployment

#### `isValidSignatureForSigner(bytes32 message, bytes calldata signature, bytes32 stateRoot, address verifier)`

Verifies a signature **without deploying a proxy**. This is useful for checking signatures before deployment or for one-time verification.

```solidity
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

    assembly ("memory-safe") {
        // staticcall to singleton with appended configuration
        if staticcall(gas(), singleton, add(data, 0x20), mload(data), 0, 32) {
            magicValue := mload(0)
        }
    }
}
```

**Use case**: Verify signatures without the gas cost of deploying a proxy.

---

## How They Work Together

### Deployment Flow

1. **Deploy Factory**: `new ZKMultiSigEcdsaFactory()`
   - Factory's constructor automatically deploys the singleton
2. **Create Signer**: `factory.createSigner(stateRoot, verifierAddress)`
   - Provide the Merkle root of authorized signers
   - Provide the HonkVerifier contract address
3. **Get Address**: The proxy is deployed to a deterministic CREATE2 address
4. **Use Signer**: The proxy address can now be used as a Safe module/owner

### Signature Verification Flow

When verifying a signature through a deployed proxy:

1. **Caller** → calls `proxy.isValidSignature(message, zkProof)`
2. **Proxy** → loads immutable config (stateRoot, verifier) and appends to calldata
3. **Proxy** → `delegatecall` to singleton with extended calldata
4. **Singleton** → reads config from end of calldata using `getConfiguration()`
5. **Singleton** → constructs public inputs (message bytes + stateRoot)
6. **Singleton** → calls `HonkVerifier.verify(zkProof, publicInputs)`
7. **Singleton** → returns magic value (0x1626ba7e) if valid
8. **Proxy** → forwards return value to caller

### Signature Verification Without Deployment

For verification before deployment or one-time checks:

1. **Caller** → calls `factory.isValidSignatureForSigner(message, zkProof, stateRoot, verifier)`
2. **Factory** → constructs calldata with config appended
3. **Factory** → `staticcall` directly to singleton
4. **Singleton** → verifies ZK proof
5. **Factory** → returns magic value if valid

---

## Key Benefits

### 1. **Massive Gas Savings**
- **Legacy (monolithic)**: Each deployment = ~500k+ gas
- **New (proxy pattern)**: 
  - Singleton deployment = ~500k gas (once)
  - Each proxy = ~50-80k gas (85% savings!)
- **Example**: 10 multisigs = 5M gas (legacy) vs 900k gas (proxy) = **82% total savings**

### 2. **Perfect for Multiple Signer Sets**
Ideal if you need multiple multisig configurations:
- Different teams with different authorized signers
- Multiple DAOs with unique governance structures
- Gradual migration of signer sets over time

### 3. **Deterministic Addresses**
- CREATE2 enables predictable proxy addresses
- Can compute address before deployment
- Useful for counterfactual deployments and account abstraction
- Can fund or interact with an address before deployment

### 4. **ERC-4337 Compatible**
- Configuration in calldata (not storage) meets ERC-4337 requirements
- No storage access during validation phase
- Enables use in account abstraction scenarios
- Compatible with ERC-4337 bundlers

### 5. **Flexible Verifier Selection**
Different proxies can use different verifier implementations:
- Test verifier vs production verifier
- Different circuit versions
- Upgrade verification logic without redeploying proxies
- Support multiple proof systems simultaneously

### 6. **Stateless Verification**
- Factory can verify signatures without deployment
- Useful for checking proofs before committing to deployment
- Enables off-chain verification simulations
- Gas-free signature checks via `staticcall`

---

## Usage Examples

### Example 1: Deploy Factory and Create Signer

```solidity
// 1. Deploy the factory (done once)
ZKMultiSigEcdsaFactory factory = new ZKMultiSigEcdsaFactory();

// 2. Prepare configuration
bytes32 stateRoot = 0x1234...; // Merkle root of authorized signers
address verifierAddress = 0x5678...; // HonkVerifier contract address

// 3. Create a signer proxy
address signerProxy = factory.createSigner(stateRoot, verifierAddress);

// 4. Use the signer proxy as a Safe owner or module
safe.addOwner(signerProxy);
```

### Example 2: Verify Signature Through Proxy

```solidity
// Prepare the message and ZK proof
bytes32 messageHash = keccak256("Transfer 100 tokens to Alice");
bytes memory zkProof = /* ZK proof generated off-chain */;

// Verify through the deployed proxy
bytes4 result = ISignatureValidator(signerProxy).isValidSignature(
    messageHash, 
    zkProof
);

if (result == 0x1626ba7e) {
    // Signature is valid!
}
```

### Example 3: Verify Without Deployment

```solidity
// Verify a signature without deploying a proxy first
bytes32 messageHash = keccak256("Emergency action");
bytes memory zkProof = /* ZK proof */;
bytes32 stateRoot = 0xabcd...;
address verifier = 0xef01...;

bytes4 result = factory.isValidSignatureForSigner(
    messageHash,
    zkProof,
    stateRoot,
    verifier
);

if (result == 0x1626ba7e) {
    // Valid! Now you can decide whether to deploy
    address futureAddress = factory.getSigner(stateRoot, verifier);
    // Deploy later: factory.createSigner(stateRoot, verifier);
}
```

### Example 4: Multiple Multisigs (Gas Comparison)

```solidity
// Scenario: 5 different teams need multisigs

// LEGACY APPROACH (monolithic contract):
// Deploy 5 separate ZKMultiSigEcdsaLegacy contracts
// Total gas: 5 × 500k = 2,500,000 gas

// NEW APPROACH (proxy pattern):
ZKMultiSigEcdsaFactory factory = new ZKMultiSigEcdsaFactory();
// Factory deployment: ~600k gas (includes singleton)

address team1 = factory.createSigner(stateRoot1, verifier); // ~60k gas
address team2 = factory.createSigner(stateRoot2, verifier); // ~60k gas
address team3 = factory.createSigner(stateRoot3, verifier); // ~60k gas
address team4 = factory.createSigner(stateRoot4, verifier); // ~60k gas
address team5 = factory.createSigner(stateRoot5, verifier); // ~60k gas

// Total gas: 600k + 5 × 60k = 900,000 gas
// SAVINGS: 1,600,000 gas (64% reduction!)
```

---

## State Root Management

### Immutable State Root (Current Design)

The current implementation uses an **immutable** `stateRoot`:

**Pros**:
- Maximum security (cannot be tampered with)
- Gas efficient (no storage)
- ERC-4337 compatible
- Simple and predictable

**Cons**:
- To change signers, must deploy a new proxy
- Each signer set has a unique address

**When to use**:
- Signer sets that rarely change
- Maximum security is required
- Cost of redeployment is acceptable

### Upgradeable State Root (Alternative)

If you need to update the `stateRoot` without redeploying, you could modify the proxy to:
- Store `stateRoot` in storage (mutable)
- Add an `updateStateRoot()` function with access control
- Accept slightly higher gas costs per verification

**Trade-offs**:
- Less gas efficient (SLOAD vs immutable)
- May affect ERC-4337 compatibility
- Adds complexity and potential security risks
- Address stays the same when signers change

---

## Security Considerations

### 1. **Immutability**
Once deployed, a proxy's configuration cannot be changed. If a `stateRoot` is compromised or needs updating, deploy a new proxy with a new configuration.

### 2. **Singleton Trust**
All proxies trust the singleton implementation. Ensure:
- The singleton address is correct and verified
- The singleton is deployed with correct bytecode
- The factory creates the singleton (guarantees known code)

### 3. **Verifier Trust**
The `HonkVerifier` contract must be trusted and audited:
- Ensure the verifier address is correct
- Different proxies can use different verifiers if needed
- Verify the verifier implements the expected circuit logic

### 4. **State Root Integrity**
The `stateRoot` is a Merkle root of authorized signers:
- Ensure the state root is computed correctly off-chain
- The ZK circuit must verify Merkle proofs against this root
- Compromised state root = compromised multisig

### 5. **ERC-4337 Validation**
During ERC-4337 validation, avoid storage access:
- This implementation uses calldata (compliant ✓)
- Don't modify the proxy to read from storage during verification
- Test with actual ERC-4337 bundlers

### 6. **CREATE2 Salt**
Current implementation uses `salt=0`:
- Simple and predictable
- Each `(stateRoot, verifier)` pair has one unique address
- If you need multiple proxies with same config, modify the salt

---

## Migration from Legacy Contract

If you have existing `ZKMultiSigEcdsaLegacy` deployments:

### Option 1: Fresh Start
- Deploy new factory
- Create new proxies with proxy pattern
- Update references to use new addresses

### Option 2: Gradual Migration
- Keep legacy contracts running
- Deploy new proxies for new multisigs
- Migrate old multisigs by:
  1. Creating equivalent proxy
  2. Updating Safe owners/modules
  3. Deprecating legacy instance

### Compatibility
Both implementations share:
- Same `SignatureValidator` base contract
- Same ERC-1271 interface
- Same ZK verification logic
- Can coexist in the same system

---

## Circuit Requirements

The ZK circuit must:
1. Accept the message hash (32 bytes, currently as 32 separate field elements)
2. Accept the `stateRoot` as a public input
3. Verify that the signers form a valid multisig according to the state tree
4. Output a valid proof if and only if the multisig is valid

**TODO**: The current implementation expands each message byte into a separate field element (32 → 32 elements). This is inefficient and should be optimized by making the circuit accept compressed inputs.

---

## Gas Cost Comparison

| Operation | Legacy (Monolithic) | Proxy Pattern | Savings |
|-----------|-------------------|---------------|---------|
| First deployment | ~500k gas | ~600k gas (factory+singleton) | -100k |
| Second deployment | ~500k gas | ~60k gas (proxy) | ~440k (88%) |
| Third deployment | ~500k gas | ~60k gas (proxy) | ~440k (88%) |
| **Total (3 deployments)** | **1,500k gas** | **720k gas** | **780k (52%)** |
| Signature verification | ~200k gas | ~200k gas | ~0 |
| Verification without deployment | Not possible | ~150k gas | N/A |

*Note: Actual gas costs may vary depending on Solidity version, optimizer settings, and network conditions.*

---

## Testing Recommendations

### Unit Tests
- Test singleton verification logic independently
- Test proxy correctly appends configuration to calldata
- Test factory creates proxies at correct addresses
- Test factory's stateless verification

### Integration Tests
- Deploy factory and create multiple signers
- Verify signatures through proxies
- Verify signatures through factory (stateless)
- Test with actual ZK proofs from your circuit

### Gas Tests
- Measure and compare deployment costs
- Measure verification costs (should be similar)
- Verify the proxy pattern saves expected gas

### Security Tests
- Ensure configuration cannot be tampered with
- Test with invalid verifier addresses
- Test with zero state roots
- Fuzz testing with random calldata

---

## Related Files

- `ZKMultiSigEcdsaSingleton.sol` - Singleton implementation (this pattern)
- `ZKMultiSigEcdsaProxy.sol` - Proxy contract (this pattern)
- `ZKMultiSigEcdsaFactory.sol` - Factory contract (this pattern)
- `ZKMultiSigEcdsaLegacy.sol` - Original monolithic implementation (backup)
- `SignatureValidator.sol` - Base contract providing EIP-1271 interface
- `ERC1271.sol` - EIP-1271 constants and interface
- `../noir/target/zk_multi_sig_ecdsa.sol` - HonkVerifier generated from Noir circuit

---

## References

- [EIP-1271: Standard Signature Validation](https://eips.ethereum.org/EIPS/eip-1271)
- [ERC-4337: Account Abstraction](https://eips.ethereum.org/EIPS/eip-4337)
- [CREATE2 Opcode](https://eips.ethereum.org/EIPS/eip-1014)
- [Noir ZK Language](https://noir-lang.org/)
- [Safe Contracts](https://docs.safe.global/)
- [Minimal Proxy (EIP-1167)](https://eips.ethereum.org/EIPS/eip-1167) - Different pattern, but related concept

---

## Future Improvements

1. **Optimize Circuit Input**: Compress the message hash input instead of passing 32 separate bytes
2. **Batch Verification**: Add factory function to verify multiple signatures in one call
3. **Event Indexing**: Add more detailed events for off-chain tracking
4. **State Root Updates**: Consider adding an upgradeable variant for mutable state roots
5. **Multi-Verifier Support**: Allow proxies to support multiple verifier implementations
6. **Gas Optimizations**: Further optimize the proxy fallback function assembly

---

## License

LGPL-3.0-only

