# Microchain ZK Signers

**Privacy-preserving multi-signature smart account using zero-knowledge proofs**

## Overview

Microchain ZK Signers is a protocol for creating privacy-preserving multi-signature smart account on Ethereum. It uses zero-knowledge proofs to enable threshold signature Validation while keeping the signer set completely private on-chain. Only a cryptographic commitment (Merkle root) to the authorized signers is stored publicly.

### Key Features

- 🔒 **Private Signers**: Authorized signers remain completely private - only a state root is stored on-chain
- 🎯 **Threshold Signatures**: Configurable M-of-N signature requirements (e.g., 2-of-3, 3-of-5)
- ⚡ **Zero-Knowledge Proofs**: Uses ZK proofs to prove Validation without revealing which signers approved
- 🔌 **Proof System Agnostic**: Supports multiple ZK proof systems (HONK, Groth16, PLONK, SP1, etc.) via ERC-8039
- 🏭 **Factory Pattern**: Deterministic deployment with CREATE2 for predictable addresses
- 🛡️ **ERC-1271 Compatible**: Standard signature validation interface for smart contract wallets
- ✅ **State Validation**: Cryptographic proof that initial configuration is valid before deployment

## Protocol Architecture

### Core Components

#### 1. **ZKMultiSigEcdsaSingleton**
The singleton implementation contract that handles signature verification logic. It uses ZK proofs to verify that:
- A threshold number of authorized signers approved the transaction
- The signers are part of the committed signer set (state root)
- Without revealing which specific signers approved

#### 2. **ZKMultiSigEcdsaProxy**
Minimal proxy contracts that store configuration (state root + verifier address) and delegate all calls to the singleton. Each proxy represents a unique multi-sig wallet with its own private signer set.

#### 3. **ZKMultiSigEcdsaFactory**
Factory contract for deterministic deployment of signer proxies with state validation. Ensures only valid configurations can be deployed by verifying a ZK proof of the initial state.

#### 4. **IERC8039 - Proof Verification Standard**
A standardized interface for ZK proof verification that makes the protocol proof-system agnostic. Any proof system can be supported by deploying a compliant verifier adapter.

#### 5. **Verifier Adapters**
Contracts that adapt specific proof system verifiers (HONK, Groth16, etc.) to the IERC8039 interface:
- `ZKMultiSigEcdsaProofVerifier`: Verifies transaction Validation proofs
- `PrivateStateValidationProofVerifier`: Verifies initial state configuration proofs

### How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                    Transaction Flow                              │
└─────────────────────────────────────────────────────────────────┘

1. Setup Phase:
   ┌──────────────┐
   │ Signers pick │──────► Generate state root = Hash(Hash(signers + threshold), salt)
   │ M-of-N setup │         ↑ Salt prevents brute-force attacks
   └──────────────┘
                             ↓
                    Generate ZK proof of valid state
                    (proves signers + threshold + salt → state root)
                             ↓
                    Deploy proxy via factory
                             ↓
                    ┌─────────────────┐
                    │ Proxy deployed  │
                    │ State: 0xabc... │ ← Only hash stored, signers + salt private
                    └─────────────────┘

2. Transaction Execution:
   ┌─────────────┐
   │ M signers   │──────► Sign transaction hash off-chain
   │ approve tx  │
   └─────────────┘
                             ↓
                    Generate ZK proof of Validation
                    (proves M valid signatures without revealing signers)
                             ↓
                    Submit: transaction + ZK proof
                             ↓
                    ┌──────────────────┐
                    │ Singleton verify │──► ERC8039 verifier
                    │ - State root     │
                    │ - TX hash        │
                    │ - ZK proof       │
                    └──────────────────┘
                             ↓
                    ✅ Execute if proof valid
```

### Circuit Design

The protocol uses two Noir circuits implemented with UltraHonk proof system:

#### 1. Private State Validation Circuit (Deployment Time)

**Purpose**: Proves that a state root corresponds to a valid multi-sig configuration before deployment.

```
┌──────────────────────────────────────────────────────────────┐
│           Priavte State Validation Circuit                            │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  Private Inputs:                                             │
│    • signers_root: Field         (Merkle root of signers)   │
│    • threshold: u8                (M-of-N threshold)         │
│    • salt: Field                  (Privacy protection)       │
│                                                               │
│  Public Inputs:                                              │
│    • state_root: Field            (On-chain commitment)      │
│                                                               │
│  ─────────────────────────────────────────────────────────  │
│                                                               │
│  Constraints & Validation:                                   │
│                                                               │
│  1. Validate inputs are non-zero:                            │
│     assert(signers_root != 0)                               │
│     assert(salt != 0)                                        │
│                                                               │
│  2. Validate threshold bounds:                               │
│     assert(threshold > 0)                                    │
│     assert(threshold <= MAX_THRESHOLD)                       │
│     assert(threshold <= MAX_SIGNERS)                         │
│                                                               │
│  3. Compute preliminary state root:                          │
│     threshold_hash = Poseidon1([threshold])                  │
│     preliminary_root = MerkleRoot([                          │
│         signers_root,                                        │
│         threshold_hash                                       │
│     ])                                                       │
│                                                               │
│  4. Mix in salt for final state root:                        │
│     final_state_root = Poseidon2([preliminary_root, salt])   │
│                                                               │
│  5. Assert correctness:                                      │
│     assert(final_state_root == state_root)                   │
│                                                               │
└──────────────────────────────────────────────────────────────┘
                           │
                           ▼
              Verified by Factory Contract
                           │
                           ▼
              Deploy Proxy if Valid ✅
```

#### 2. Transaction Validation Circuit (Execution Time)

**Purpose**: Proves that sufficient valid signatures were provided without revealing signer identities.

```
┌──────────────────────────────────────────────────────────────┐
│        Transaction Validation Circuit                      │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  Private Inputs:                                             │
│    • signers: [PubKey; MAX_SIGNERS]  (ECDSA public keys)    │
│    • signatures: [Signature; MAX_SIGNERS]  (ECDSA sigs)     │
│    • merkle_proof_length: [u32; MAX_SIGNERS]                │
│    • merkle_proof_indices: [[u1; DEPTH]; MAX_SIGNERS]       │
│    • merkle_proof_siblings: [[Field; DEPTH]; MAX_SIGNERS]   │
│    • signers_root: Field                                     │
│    • threshold: u8                                           │
│    • salt: Field                                             │
│                                                               │
│  Public Inputs:                                              │
│    • txn_hash: [u8; 32]          (Transaction hash to sign) │
│    • state_root: Field            (On-chain commitment)      │
│                                                               │
│  ─────────────────────────────────────────────────────────  │
│                                                               │
│  For each signer slot (up to MAX_SIGNERS):                   │
│                                                               │
│  1. Skip if NIL (generator point marker):                    │
│     if (pubkey == G) continue                                │
│                                                               │
│  2. Verify ECDSA signature:                                  │
│     assert(ecdsa_secp256k1_verify(                          │
│         public_key: signers[i],                             │
│         signature: signatures[i],                            │
│         message: txn_hash                                    │
│     ))                                                       │
│                                                               │
│  3. Derive Ethereum address:                                 │
│     uncompressed_pubkey = concat(pubkey.x, pubkey.y)        │
│     pubkey_hash = keccak256(uncompressed_pubkey)            │
│     address = pubkey_hash[12..32]  // last 20 bytes         │
│                                                               │
│  4. Enforce signature uniqueness (sorted order):             │
│     assert(address > previous_address)                       │
│     // Prevents same signature being counted twice          │
│                                                               │
│  5. Verify signer is in authorized set:                      │
│     address_hash = Poseidon1([address_as_field])            │
│     computed_root = MerkleProof(                             │
│         leaf: address_hash,                                  │
│         proof: merkle_proof_siblings[i],                     │
│         indices: merkle_proof_indices[i]                     │
│     )                                                        │
│     assert(computed_root == signers_root)                    │
│                                                               │
│  6. Increment verified signature count                       │
│                                                               │
│  ─────────────────────────────────────────────────────────  │
│                                                               │
│  Final Validation:                                           │
│                                                               │
│  7. Assert threshold requirement met:                        │
│     assert(num_verified_signatures >= threshold)             │
│                                                               │
│  8. Reconstruct and verify state root:                       │
│     threshold_hash = Poseidon1([threshold])                  │
│     preliminary_root = MerkleRoot([                          │
│         signers_root,                                        │
│         threshold_hash                                       │
│     ])                                                       │
│     final_state_root = Poseidon2([preliminary_root, salt])   │
│     assert(final_state_root == state_root)                   │
│                                                               │
└──────────────────────────────────────────────────────────────┘
                           │
                           ▼
              Verified by Proxy's Verifier
                           │
                           ▼
              Execute Transaction ✅
```

**Key Implementation Details:**

- **NIL Values**: Uses secp256k1 generator point as a marker for empty slots (allows variable number of signers up to MAX)
- **Signature Ordering**: Requires addresses to be in strictly increasing order to prevent signature reuse (same approach as Safe contracts)
- **Address Derivation**: Follows Ethereum's address computation: `keccak256(uncompressed_pubkey)[12:32]`
- **Merkle Tree**: Uses Poseidon hash for ZK-friendly tree operations
- **Salt Protection**: Same salt used in both circuits to link configuration to execution while preventing brute-force attacks


### Privacy Properties

The protocol maintains complete privacy of:
- Individual signer identities and addresses
- Which specific signers authorized each transaction
- Total number of signers in the set
- The threshold requirement (M-of-N)
- The random salt value
- Historical signing patterns

**Only publicly visible:**
- The state root (cryptographic commitment to the entire configuration)
- That a valid proof was verified (without revealing any details)
- Transaction outcomes

## Technical Details

### State Root Construction

The state root is computed with a privacy-protecting salt to prevent brute-force attacks:

```
preliminary_state_root = MerkleRoot([signers_merkle_root, Hash(threshold)])
final_state_root = Hash(preliminary_state_root, salt)
```

Where:
- `signers_merkle_root` is the Merkle root of sorted signer public keys
- `threshold` is the M-of-N signature requirement
- `salt` is a random value that prevents attackers from brute-forcing the configuration

**Why salt at the state level?**

The salt is added **after** computing the preliminary state root rather than inside the signers tree. This design choice is critical because:

1. **Preserves signature verification**: The signature circuit needs the exact `signers_merkle_root` to verify Merkle proofs. Adding salt to the signers tree would break all Merkle proof validations.

2. **Separation of concerns**: 
   - Signers tree = identity (who can sign)
   - State root = configuration (signers + threshold + deployment salt)

3. **Single salt**: One salt protects both circuits without requiring modifications to signature verification logic.

4. **Prevents brute-force attacks**: Even with a known threshold and small signer set, attackers cannot reverse the state root without the random salt.


### Zero-Knowledge Circuits

The protocol uses two ZK circuits:

1. **State Validation Circuit**: Proves that a state root corresponds to a valid configuration
   - Public inputs: `state_root`
   - Private inputs: `signers[]`, `threshold`, `salt`
   - Proves: `state_root = Hash(Hash(MerkleRoot(signers), Hash(threshold)), salt)`
   - Validates: threshold bounds, non-zero signers root, non-zero salt

2. **Transaction Validation Circuit**: Proves sufficient signatures without revealing signers
   - Public inputs: `transaction_hash`, `state_root`
   - Private inputs: `signers[]`, `signatures[]`, `merkle_proofs[]`, `threshold`, `salt`
   - Proves: At least `threshold` valid ECDSA signatures from signers in the Merkle tree
   - Note: Uses the same salt to reconstruct state root for verification

### ERC-8039 Proof Verification Interface

The protocol implements ERC-8039 for proof-system agnostic verification:

```solidity
interface IERC8039 {
    function verifyProof(
        bytes calldata publicSignals,
        bytes calldata proof
    ) external view returns (bytes4 magicValue);
    
    function getProofType() external view returns (bytes32);
    function metadata() external view returns (string memory);
}
```

This allows swapping proof systems without changing the core protocol contracts.

## Getting Started

### Installation

```bash
pnpm install
```

### Compilation

Compile Noir circuits:
```bash
cd noir
nargo compile
```

Compile Solidity contracts:
```bash
npx hardhat compile
```

### Solidity Verifier Generation

```bash
cd noir
bb write_vk -b ./target/zk_multi_sig_ecdsa.json -o ./target/zk_multi_sig_ecdsa --oracle_hash keccak
bb write_vk -b ./target/zk_multi_sig_ecdsa_private_state_validation.json -o ./target/zk_multi_sig_ecdsa_private_state_validation --oracle_hash keccak
bb write_solidity_verifier -k ./target/zk_multi_sig_ecdsa/vk -o ./target/zk_multi_sig_ecdsa.sol
bb write_solidity_verifier -k ./target/zk_multi_sig_ecdsa_private_state_validation/vk -o ./target/zk_multi_sig_ecdsa_private_state_validation.sol
```

## Use Cases

- **Privacy-focused DAOs**: Multi-sig treasuries where signers want anonymity
- **Corporate Wallets**: Companies that don't want to expose their signers publicly
- **Whistleblower Protection**: Enable authorized actions without revealing identities
- **Regulatory Compliance**: Prove authorization requirements met without exposing individuals
- **High-security Wallets**: Reduce attack surface by hiding signer information

## Security Considerations

- The protocol assumes the ZK proof system is sound and secure
- State roots must be generated correctly off-chain before deployment
- Private keys must be managed securely as with any signature scheme
- Factory validates state before deployment to prevent invalid configurations

## Safe Integration

Microchain ZK Signers integrates seamlessly with [Safe](https://safe.global) (formerly Gnosis Safe) multi-signature wallets as **contract owners** via ERC-1271 signature validation. This enables Safe wallets to have privacy-preserving ZK-based signers instead of traditional EOA owners.

### Architecture

```
┌──────────────────┐
│   Safe Wallet    │
│                  │
│ Owners:          │
│ • 0xZKProxy1     │◄─── ZKMultiSigEcdsaProxy (ERC-1271 signer)
│ • 0xZKProxy2     │◄─── Another ZK MultiSig Proxy
│ • 0xEOA...       │     (Optional: Mix with regular EOAs)
│                  │
│ Threshold: 2/3   │
└──────────────────┘
        │
        │ When Safe validates signature:
        ▼
┌─────────────────────────────────┐
│  ZKMultiSigEcdsaProxy          │
│  (implements ERC-1271)         │
│                                 │
│  isValidSignature(hash, proof) │
│         │                       │
│         ├──► Delegate to        │
│         │    Singleton          │
│         │                       │
│         └──► Verify ZK proof    │
│              with state root    │
└─────────────────────────────────┘
```

### How It Works

1. **Safe Owner Setup**: Deploy a `ZKMultiSigEcdsaProxy` and add it as an owner to your Safe wallet
2. **Private Signers**: The proxy contains a state root committing to a private set of signers
3. **Transaction Signing**: 
   - Prepare a Safe transaction
   - Private signers sign the transaction hash off-chain
   - Generate a ZK proof of Validation
   - Submit the proof as the "signature" for that owner
4. **Validation**: Safe calls `isValidSignature()` on the proxy, which verifies the ZK proof

### Benefits

- 🔐 **Privacy**: Safe owners (the proxy addresses) are public, but the actual signers remain private
- 🎯 **Nested Multi-sig**: Safe's M-of-N threshold can include ZK multi-sig owners with their own M-of-N thresholds
- 🔄 **Flexibility**: Mix ZK signers with regular EOA owners in the same Safe
- 🛡️ **ERC-1271 Standard**: Works with any contract that supports smart contract signature validation

### Example: 2-of-3 Safe with ZK Signers

```
Safe Threshold: 2-of-3
├─ Owner 1: ZKMultiSigProxy (3-of-5 private signers) ← 5 people's identities private
├─ Owner 2: ZKMultiSigProxy (2-of-3 private signers) ← 3 people's identities private  
└─ Owner 3: 0xEOA... (traditional wallet)

To execute a Safe transaction:
- Any 2 out of these 3 owners must approve
- If using Owner 1: Generate ZK proof with 3+ of the 5 private signatures
- If using Owner 2: Generate ZK proof with 2+ of the 3 private signatures
- If using Owner 3: Standard EOA signature
```

### Code Example

```typescript
import Safe from '@safe-global/protocol-kit';
import { EthSafeSignature } from '@safe-global/protocol-kit';

// Initialize Safe with ZK MultiSig proxy as owner
const safe = await Safe.init({
    provider: rpcUrl,
    signer: deployerPrivateKey,
    safeAddress: safeAddress
});

// Prepare transaction
const safeTransactionData = {
    to: recipientAddress,
    value: parseEther("0.1"),
    data: "0x"
};

const safeTx = await safe.createTransaction({
    transactions: [safeTransactionData]
});

const safeTxHash = await safe.getTransactionHash(safeTx);

// Generate ZK proof (with private signers signing off-chain)
const zkProof = await generateZKProof(
    safeTxHash,
    privateSigners,
    signatures,
    stateRoot,
    salt
);

// Add ZK proof as signature for the proxy owner
const ethSafeSignature = new EthSafeSignature(
    zkMultiSigProxyAddress,  // The proxy owner address
    zkProof,                  // ZK proof as "signature"
    true                      // Contract signature flag
);
safeTx.addSignature(ethSafeSignature);

// Execute transaction
const executeTxResponse = await safe.executeTransaction(safeTx);
```

### Key Implementation Details

1. **ERC-1271 Compliance**: The `ZKMultiSigEcdsaSingleton` inherits from `SignatureValidator` which implements both:
   - `isValidSignature(bytes32 hash, bytes signature)` - Standard ERC-1271
   - `isValidSignature(bytes data, bytes signature)` - Legacy support

2. **Signature Format**: The "signature" parameter is actually the ZK proof bytes that prove Validation

3. **Configuration Passing**: The proxy appends its configuration (state root + verifier address) to calldata before delegating to the singleton

4. **Gas Efficiency**: The singleton pattern ensures ZK verification logic is deployed once and reused by all proxies

### Deployment Flow

```bash
# 1. Deploy factory (auto-deploys singleton and verifier)
npx hardhat ignition deploy ignition/modules/zkMultiSigEcdsaFactory.ts

# 2. Create ZK MultiSig proxy with state validation
const proxyAddress = await factory.createSigner(
    stateRoot,
    verifierAddress,
    stateValidationProof
);

# 3. Add proxy as Safe owner
await safe.addOwnerWithThreshold(proxyAddress, newThreshold);

# 4. Use Safe normally - when signing with ZK owner, provide ZK proof
```
### Usage

### Additional Resources

- [Safe Protocol Kit Documentation](https://docs.safe.global/sdk/protocol-kit)
- [ERC-1271 Specification](https://eips.ethereum.org/EIPS/eip-1271)

## Nexus Integration(ERC-7579 Module)

## License

LGPL-3.0-only - See [LICENSE.txt](./LICENSE.txt)

## Contributing

This is an experimental protocol under active development. Contributions, issues, and feedback are welcome.
