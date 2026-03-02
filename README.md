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

Clone the repository and install dependencies:

```bash
# Clone the repository
git clone https://github.com/microchainlabs/microchain-zk-signers.git
cd microchain-zk-signers

# Initialize Foundry dependencies (git submodules)
forge install

# Install npm dependencies
pnpm install
```

**Prerequisites:**
- [Node.js](https://nodejs.org/) v18 or later
- [pnpm](https://pnpm.io/) package manager
- [Foundry](https://book.getfoundry.sh/getting-started/installation) (for Solidity compilation)
- [Nargo](https://noir-lang.org/docs/getting_started/installation/) (for Noir circuit compilation)
- [Barretenberg](https://github.com/AztecProtocol/aztec-packages/tree/master/barretenberg) (`bb` CLI - for proof generation and verifier generation)

For detailed setup instructions, see [DEVELOPMENT_SETUP.md](DEVELOPMENT_SETUP.md).

### Compilation

**Important**: Compile in this order, as Solidity verifiers are generated from Noir circuits.

1. **Compile Noir circuits:**
```bash
cd noir
nargo compile
cd ..
```

2. **Generate Solidity verifiers** (optional - needed if circuits changed):
```bash
cd noir
bb write_vk -b ./target/zk_multi_sig_ecdsa.json -o ./target/zk_multi_sig_ecdsa --oracle_hash keccak
bb write_vk -b ./target/zk_multi_sig_ecdsa_private_state_validation.json -o ./target/zk_multi_sig_ecdsa_private_state_validation --oracle_hash keccak
bb write_solidity_verifier -k ./target/zk_multi_sig_ecdsa/vk -o ./target/zk_multi_sig_ecdsa.sol
bb write_solidity_verifier -k ./target/zk_multi_sig_ecdsa_private_state_validation/vk -o ./target/zk_multi_sig_ecdsa_private_state_validation.sol
cd ..
```

3. **Compile Solidity contracts:**
```bash
# Using Hardhat (recommended for development)
npx hardhat compile

# Or using Foundry (faster compilation)
forge build
```

The project uses both Hardhat and Foundry with shared `remappings.txt` for import resolution. See [DEVELOPMENT_SETUP.md](DEVELOPMENT_SETUP.md) for detailed setup instructions.

### Testing

Run tests with Hardhat:
```bash
npx hardhat test
```

Or with Foundry (faster):
```bash
forge test
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

### Command line usage

A set of Hardhat tasks are implemented for most common tasks, automate the usage of zkSafe.

#### Contracts deployments

Deploy a new instance of contracts(factory, verifiers):

```
npx hardhat --network <mainnet|sepolia|gnosis|etc> createFactory
```

#### Deploy new Safe owner

Deploy a new contract owner:

```
npx hardhat createPrivateMultiSignersProxyContract --network <mainnet|sepolia|gnosis|etc> --privatesigners <signer1>,<signer2>,<signer3> --privatethreshold <threshold value> --factoryaddress <owner factory contract address> --txvalidationverifieraddress <tx validator contract address>
```

#### Creating new Safe using the contract owner

```
npx hardhat createSafeWithinMicorchainProtocol --network <mainnet|sepolia|gnosis|etc> --owners <contract owner address> --threshold 1
```


#### Sign a new transaction

```
npx hardhat --network <mainnet|sepolia|gnosis|etc> sign --safe <safe address> --to <to-address> --value <to-value-in-wei> --data <calldata>
```

#### Proving the transaction

Having collected all the signatures, we need to generate a proof. This is done with the `prove` hardhat task.

```
npx hardhat --network <mainnet|sepolia|gnosis|etc>  prove --safe <safe address>  --signatures <signature1>,<signature2> <sinagure3> --txhash <txhash> --privatesigners <signer1>,<signer2>,<signer3> --privatethreshold <threshold value> --signersaddressesformat 0 --salt <salt value> 
```

Proving might take a couple of minutes, and would return a large hex string starting with 0x.  This is the prove that needs to be sent to zkSafe along with the transaction.

WARNING: Only up to 5 owners/signatures is supported at the moment. This limit can be increased.


#### Sending a proven transaction

Once we have the proof, we may send it. Proving and sending the transaction are separate steps, because they can be done by different entities. For instance, one can send the transaction from a relay.
Here is how one can use the hardhat task `zksend`.

```
npx hardhat --network  <mainnet|sepolia|gnosis|etc> zksend --safe <safe address>  --to <to-address> --value <to-value-in-wei> --data <calldata> --proof <proof hex string>
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

## Nexus Integration (ERC-7579 Module)

Microchain ZK Signers integrates with [Nexus](https://biconomy.io) smart accounts as an **ERC-7579 validator module**. This enables Nexus accounts to use privacy-preserving ZK multi-signature validation instead of traditional single-signer or public multi-sig validators.

### Architecture

```
┌──────────────────────────────────────────────────────────┐
│              Nexus Smart Account                          │
│           (ERC-7579 + ERC-4337)                          │
│                                                           │
│  Validators:                                             │
│  ├─ Default Validator (immutable)                       │
│  └─ ZKMultiSigValidator ◄── Privacy-preserving M-of-N   │
│                                                           │
│  Executors: [optional custom modules]                   │
│  Hooks: [optional custom modules]                       │
└──────────────────────────────────────────────────────────┘
                      │
                      │ Validates UserOps & Signatures
                      ▼
┌──────────────────────────────────────────────────────────┐
│         ZKMultiSigValidator Module                       │
│                                                           │
│  Configuration per account:                              │
│  • state_root: bytes32 (commitment to signers)          │
│  • verifier: address (ERC8039 proof verifier)           │
│                                                           │
│  Validation Methods:                                     │
│  • validateUserOp() - ERC-4337 validation               │
│  • isValidSignatureWithSender() - ERC-1271 validation   │
└──────────────────────────────────────────────────────────┘
                      │
                      │ Verifies ZK proofs
                      ▼
┌──────────────────────────────────────────────────────────┐
│      ERC8039 Proof Verifier                              │
│   (ZKMultiSigEcdsaProofVerifier)                        │
│                                                           │
│  Verifies that:                                          │
│  • M-of-N signers approved the transaction              │
│  • All signers are in authorized set (state_root)       │
│  • Without revealing which signers approved             │
└──────────────────────────────────────────────────────────┘
```

### How It Works

The ZKMultiSigValidator module allows Nexus accounts to validate transactions using zero-knowledge proofs:

1. **Module Installation**: Install the `ZKMultiSigValidator` module on a Nexus account with configuration:
   - `stateRoot`: Cryptographic commitment to your private signer set + threshold + salt
   - `verifierAddress`: ERC8039 proof verifier contract

2. **UserOperation Validation**: When submitting a UserOp:
   - Specify the ZKMultiSigValidator in the nonce
   - Include a ZK proof in the signature field
   - The proof demonstrates M-of-N signers approved without revealing identities

3. **ERC-1271 Signing**: The Nexus account can sign arbitrary messages:
   - Generate ZK proof of multi-sig approval
   - Off-chain signatures remain private
   - On-chain verification via `isValidSignature()`

### Key Features

- 🎯 **Modular Integration**: Works alongside other Nexus validators and modules
- 🔐 **Privacy-First**: Signer identities never revealed on-chain
- ⚡ **ERC-4337 Compatible**: Full Account Abstraction support with gas sponsorship
- 🔌 **Proof System Agnostic**: Uses ERC8039 interface for any ZK proof system
- 🛡️ **Battle-Tested**: Builds on Biconomy's audited Nexus framework
- 🔄 **Upgradeable**: Change state root to rotate signers without deploying new account

### Deployment Options

#### Option 1: Factory Deployment (Recommended)

Use `ZKMultiSigValidatorFactory` to deploy a Nexus account with ZK validator pre-installed:

```typescript
import { ZKMultiSigValidatorFactory } from "./contracts/factory/ZKMultiSigValidatorFactory";

// 1. Deploy factory (once)
const factory = await ethers.deployContract("ZKMultiSigValidatorFactory", [
    nexusImplementation,
    factoryOwner,
    zkMultiSigValidator,
    bootstrapper,
    registry  // optional, can be address(0)
]);

// 2. Generate state root from your private configuration
const stateRoot = computeStateRoot(signers, threshold, salt);

// 3. Create Nexus account with ZK validator
const accountAddress = await factory.createAccount(
    stateRoot,
    verifierAddress,
    0,  // index
    [],  // attesters (empty if no registry)
    0   // threshold (0 if no registry)
);
```

#### Option 2: Install on Existing Nexus

Install the ZK validator on an existing Nexus account:

```solidity
// From the Nexus account (via UserOp)
bytes memory validatorInitData = abi.encode(stateRoot, verifierAddress);

nexusAccount.installModule(
    MODULE_TYPE_VALIDATOR,  // Type 1
    zkMultiSigValidatorAddress,
    validatorInitData
);
```

### Usage Examples

#### Example 1: Create ZK Multi-Sig Nexus Account

```typescript
import { generateStateRoot, generateStateValidationProof } from "./zkUtils";

// Define your private signers (off-chain only)
const privateSigners = [
    "0x1234...5678",  // Signer 1 address
    "0xabcd...efgh",  // Signer 2 address
    "0x9876...5432"   // Signer 3 address
];
const threshold = 2;  // 2-of-3 required
const salt = randomBytes(32);  // Privacy protection

// Generate state root commitment
const stateRoot = await generateStateRoot(privateSigners, threshold, salt);

// Deploy Nexus account via factory
const nexusAccount = await factory.createAccount(
    stateRoot,
    zkProofVerifier,
    0,  // index for first account
    [], // no registry attesters
    0   // no registry threshold
);

console.log("Nexus account deployed:", nexusAccount);
console.log("Private signers:", privateSigners, "(never revealed on-chain!)");
```

#### Example 2: Submit UserOperation with ZK Proof

```typescript
import { generateTransactionProof } from "./zkUtils";

// 1. Prepare execution parameters
const to = "0xRecipientAddress";
const value = ethers.parseEther("0.01"); // 0.01 POL
const data = "0x"; // Empty calldata for simple transfer

// 2. Encode execution (ERC-7579 format)
// ExecutionMode: 0x00 (SINGLE) + 0x00 (REVERT) + zeros
const executionMode = "0x0000000000000000000000000000000000000000000000000000000000000000";

// ExecutionCalldata: Simple concatenation for SINGLE mode
const executionCalldata = ethers.concat([
    to,                           // address (20 bytes)
    ethers.toBeHex(value, 32),   // value (32-byte big-endian)
    data                          // calldata
]);

// 3. Build UserOperation
const callData = ethers.concat([
    "0xe9ae5c53", // execute(bytes32,bytes) selector
    ethers.AbiCoder.defaultAbiCoder().encode(
        ["bytes32", "bytes"],
        [executionMode, executionCalldata]
    )
]);

const userOp = {
    sender: nexusAccount,
    nonce: encodeNonce(0, zkMultiSigValidatorAddress),  // Use ZK validator
    callData: callData,
    accountGasLimits: packGasLimits(10000000n, 3000000n), // verification, call gas
    preVerificationGas: 300000n,
    gasFees: packGasFees(maxPriorityFee, maxFee),
    paymasterAndData: "0x",
    signature: "0x"  // Will be filled with ZK proof
};

// 4. Get UserOp hash
const userOpHash = await entryPoint.getUserOpHash(userOp);

// 5. Collect private signatures (off-chain)
const sig1 = await signer1.signMessage(ethers.getBytes(userOpHash));
const sig2 = await signer2.signMessage(ethers.getBytes(userOpHash));

// 6. Generate ZK proof
const zkProof = await generateTransactionProof({
    txHash: userOpHash,
    privateSigners: privateSigners,
    signatures: [sig1, sig2, nullSignature],  // Fill unused slots with null
    threshold: threshold,
    salt: salt
});

// 7. Add proof as signature
userOp.signature = zkProof;

// 8. Submit to EntryPoint
await entryPoint.handleOps([userOp], beneficiary);
```

#### Example 3: Sign Message with ZK Multi-Sig (ERC-1271)

```typescript
// Off-chain message signing
const message = "Transfer ownership to 0x...";
const messageHash = ethers.utils.hashMessage(message);

// Collect signatures from private signers
const signatures = await Promise.all([
    signer1.signMessage(messageHash),
    signer2.signMessage(messageHash)
]);

// Generate ZK proof
const zkProof = await generateTransactionProof({
    txHash: messageHash,
    privateSigners: privateSigners,
    signatures: [...signatures, nullSignature],
    threshold: threshold,
    salt: salt
});

// Verify on-chain
const isValid = await nexusAccount.isValidSignature(messageHash, zkProof);
// Returns: 0x1626ba7e (ERC-1271 magic value) if valid
```

#### Example 4: Update Signer Set (Rotate Signers)

```typescript
// Generate new configuration with different signers
const newSigners = ["0xnew1...", "0xnew2...", "0xnew3..."];
const newThreshold = 2;
const newSalt = randomBytes(32);
const newStateRoot = await generateStateRoot(newSigners, newThreshold, newSalt);

// Prepare update call to validator
const updateCalldata = zkValidator.interface.encodeFunctionData(
    "updateConfiguration",
    [newStateRoot, verifierAddress]
);

// Execute through Nexus (must be authorized by CURRENT configuration)
// Use CALLTYPE_SINGLE (0x00)
const executionMode = "0x0000000000000000000000000000000000000000000000000000000000000000";
const executionCalldata = ethers.concat([
    await zkValidator.getAddress(),  // target
    ethers.toBeHex(0n, 32),         // value (0)
    updateCalldata                   // calldata
]);

const callData = ethers.concat([
    "0xe9ae5c53", // execute(bytes32,bytes)
    ethers.AbiCoder.defaultAbiCoder().encode(
        ["bytes32", "bytes"],
        [executionMode, executionCalldata]
    )
]);

// Submit via UserOp with OLD configuration proof
// After successful execution, use NEW configuration for future transactions
```

### Practical Implementation (Hardhat Tasks)

For production use, tested hardhat tasks are provided that handle all the complexity of ZK proof generation and UserOperation submission.

#### Sign UserOperation

Generate ZK proof for a transaction:

```bash
npx hardhat --network polygon signUserOp \
  --account 0xYourNexusAccount \
  --validator 0x6e48CaE2f383CB2982215adC04E5D9B72E6206f9 \
  --to 0xRecipientAddress \
  --value 0.01 \
  --data 0x
```

This task:
- Constructs the UserOperation with proper nonce encoding
- Collects signatures from private signers
- Generates ZK proof using Noir circuits
- Returns signatures and userOpHash for submission

#### Send UserOperation

Submit a signed UserOperation to the network:

```bash
npx hardhat --network polygon sendZKNexusUserOp \
  --account 0xYourNexusAccount \
  --validator 0x6e48CaE2f383CB2982215adC04E5D9B72E6206f9 \
  --to 0xRecipientAddress \
  --value 0.01 \
  --data 0x \
  --signatures "0x..." \
  --userhash "0x..."
```

**Implementation Details**: See [zknexus/zknexus.ts](zknexus/zknexus.ts) for the complete working implementation.

#### ExecutionMode Format

The `executionMode` parameter uses ERC-7579's structured encoding:

```
Byte Structure (32 bytes total):
┌─────────┬──────────┬───────────┬───────────┬──────────────┐
│ Byte 0  │ Byte 1   │ Bytes 2-5 │ Bytes 6-9 │ Bytes 10-31  │
│ CallType│ ExecType │ Unused    │ Selector  │ Context      │
└─────────┴──────────┴───────────┴───────────┴──────────────┘

CallType (Byte 0):
  0x00 = CALLTYPE_SINGLE      (single execution)
  0x01 = CALLTYPE_BATCH       (batch execution)
  0xFF = CALLTYPE_DELEGATECALL

ExecType (Byte 1):
  0x00 = EXECTYPE_DEFAULT (revert on failure)
  0x01 = EXECTYPE_TRY     (allow failure)

Example for single execution with revert on error:
0x0000000000000000000000000000000000000000000000000000000000000000
  ^^-- SINGLE
    ^^-- DEFAULT (revert)
```

#### ExecutionCalldata Encoding

For single executions, encode as simple hex concatenation:

```typescript
// Correct encoding for CALLTYPE_SINGLE (matches Rhinestone SDK)
const executionCalldata = ethers.concat([
    to,                              // address (20 bytes)
    ethers.toBeHex(valueInWei, 32), // value (32-byte big-endian)
    data                             // calldata
]);

// Then construct callData for Nexus.execute(bytes32,bytes)
const callData = ethers.concat([
    "0xe9ae5c53", // execute(bytes32,bytes) selector
    ethers.AbiCoder.defaultAbiCoder().encode(
        ["bytes32", "bytes"],
        [executionMode, executionCalldata]
    )
]);
```

**Important**: Do NOT use `abi.encode()` or `solidityPacked()` for executionCalldata - use simple concatenation as shown above.

#### Web Interface

A Next.js web interface is available for easier interaction:

```bash
cd zknexus-ui
pnpm install
pnpm dev
```

Features:
- View account information and balances
- Create new ZK MultiSig Nexus accounts
- Sign and send UserOperations (requires backend prover integration)
- Modern UI with wallet connection via RainbowKit

See [zknexus-ui/README.md](zknexus-ui/README.md) and [zknexus-ui/QUICKSTART.md](zknexus-ui/QUICKSTART.md) for setup instructions.

### Comparison: ZK Validator vs K1Validator

| Feature | K1Validator | ZKMultiSigValidator |
|---------|-------------|---------------------|
| **Signer Privacy** | Public (EOA address on-chain) | Private (only state root visible) |
| **Multi-Sig** | Single signer | M-of-N threshold |
| **Signature Type** | ECDSA | ZK Proof of ECDSA signatures |
| **Gas Cost** | ~50k gas | ~300-500k gas (proof verification) |
| **Setup Complexity** | Simple (just an address) | Requires circuit compilation |
| **Signer Identity** | Always visible | Never revealed |
| **Use Cases** | Personal accounts, simple wallets | DAOs, corporate treasuries, privacy |

### Advanced: Combining Validators

Nexus's modularity allows combining multiple validators:

```typescript
// Install both K1Validator and ZKMultiSigValidator
await nexusAccount.installModule(MODULE_TYPE_VALIDATOR, k1Validator, ownerAddress);
await nexusAccount.installModule(MODULE_TYPE_VALIDATOR, zkValidator, zkConfig);

// Use K1Validator for low-value transactions (cheaper)
const smallTxUserOp = {
    nonce: encodeNonce(0, k1ValidatorAddress),
    signature: eoaSignature,
    // ...
};

// Use ZK validator for high-value transactions (private)
const largeTxUserOp = {
    nonce: encodeNonce(1, zkMultiSigValidatorAddress),
    signature: zkProof,
    // ...
};
```

### Security Considerations

1. **State Root Generation**: Must be computed correctly off-chain with proper randomness for salt
2. **Proof Generation**: Requires secure environment to generate proofs with private signer keys
3. **Verifier Trust**: The ERC8039 verifier contract must be audited and trusted
4. **Gas Costs**: ZK proof verification is more expensive than simple ECDSA (~6-10x gas)
5. **Circuit Security**: The Noir circuits must be correctly implemented and audited

### Implementation Files

- **Validator Module**: [`nexus/contracts/modules/validators/ZKMultiSigValidator.sol`](nexus/contracts/modules/validators/ZKMultiSigValidator.sol)
- **Factory Contract**: [`nexus/contracts/factory/ZKMultiSigValidatorFactory.sol`](nexus/contracts/factory/ZKMultiSigValidatorFactory.sol)
- **Hardhat Tasks**: [`zknexus/zknexus.ts`](zknexus/zknexus.ts) - Complete working implementation
- **Web Interface**: [`zknexus-ui/`](zknexus-ui/) - Next.js UI for ZK Nexus accounts
- **Architecture Guide**: [`nexus/NEXUS_ARCHITECTURE.md`](nexus/NEXUS_ARCHITECTURE.md)
- **Detailed Integration Guide**: [`nexus/ZK_NEXUS_GUIDE.md`](nexus/ZK_NEXUS_GUIDE.md)

### Additional Resources

- [Nexus Documentation](https://docs.biconomy.io)
- [ERC-7579 Specification](https://eips.ethereum.org/EIPS/eip-7579)
- [ERC-4337 Account Abstraction](https://eips.ethereum.org/EIPS/eip-4337)
- [ERC-8039 Proof Verification](./contracts/interfaces/IERC8039.sol)

---

## License

LGPL-3.0-only - See [LICENSE.txt](./LICENSE.txt)

## Contributing

This is an experimental protocol under active development. Contributions, issues, and feedback are welcome.
