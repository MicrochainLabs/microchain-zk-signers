# Contributing to Microchain ZK Signers

Thank you for your interest in contributing! This protocol sits at the intersection of ZK cryptography, Solidity smart contracts, and account abstraction — all contributions are welcome.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Prerequisites](#prerequisites)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Making Changes](#making-changes)
- [Running Tests](#running-tests)
- [Submitting a Pull Request](#submitting-a-pull-request)
- [Good First Issues](#good-first-issues)

---

## Code of Conduct

Be respectful, constructive, and collaborative. Harassment of any kind is not tolerated.

---

## Prerequisites

Install the following tools before starting:

| Tool | Version | Purpose |
|---|---|---|
| [Node.js](https://nodejs.org/) | v18+ | TypeScript tooling |
| [pnpm](https://pnpm.io/) | latest | Package manager |
| [Foundry](https://book.getfoundry.sh/getting-started/installation) (`forge`, `cast`) | latest | Solidity compilation & testing |
| [Nargo](https://noir-lang.org/docs/getting_started/installation/) | compatible with `1.0.0-beta.18` | Noir circuit compilation |
| [Barretenberg CLI](https://github.com/AztecProtocol/aztec-packages/tree/master/barretenberg) (`bb`) | latest nightly | Proof generation & Solidity verifier generation |
| Git | any | Source control |

> **Note on Noir/bb versions**: The project uses `@noir-lang/noir_js@1.0.0-beta.18` and `@aztec/bb.js@3.0.0-nightly.20260102`. Use matching Nargo and `bb` CLI versions to avoid circuit compatibility issues.

---

## Development Setup

```bash
# 1. Clone the repository
git clone https://github.com/microchainlabs/microchain-zk-signers.git
cd microchain-zk-signers

# 2. Initialize Foundry submodules
forge install

# 3. Install Node.js dependencies
pnpm install

# 4. Compile Noir circuits
cd noir
nargo compile
cd ..

# 5. (Optional) Regenerate Solidity verifiers from circuits
#    Only needed if you modify the .nr circuit files
cd noir
bb write_vk -b ./target/zk_multi_sig_ecdsa.json \
            -o ./target/zk_multi_sig_ecdsa --oracle_hash keccak
bb write_vk -b ./target/zk_multi_sig_ecdsa_private_state_validation.json \
            -o ./target/zk_multi_sig_ecdsa_private_state_validation --oracle_hash keccak
bb write_solidity_verifier -k ./target/zk_multi_sig_ecdsa/vk \
                           -o ./target/zk_multi_sig_ecdsa.sol
bb write_solidity_verifier -k ./target/zk_multi_sig_ecdsa_private_state_validation/vk \
                           -o ./target/zk_multi_sig_ecdsa_private_state_validation.sol
cd ..

# 6. Compile Solidity contracts
npx hardhat compile
# or
forge build
```

---

## Project Structure

```
contracts/            Solidity smart contracts
  ERC1271/            Signature validation interface
  ERC8039/            Proof-system agnostic verifier adapters
  nexus/              Nexus/ERC-4337 module integration
  safe/               Safe wallet integration
noir/                 Noir ZK circuits
  zk_multi_sig_ecdsa/                  Transaction validation circuit
  zk_multi_sig_ecdsa_private_state_validation/  State validation circuit
lib/                  Foundry submodule dependencies
deploy/               Hardhat deployment scripts
ignition/             Hardhat Ignition deployment modules
zksafe/               Safe integration TypeScript utilities
zknexus/              Nexus integration TypeScript utilities
```

---

## Making Changes

### Solidity contracts

- Follow the existing style (no linter config yet — match surrounding code).
- All public/external functions should have corresponding tests.
- Do not change compiler version (`foundry.toml` / `hardhat.config.ts`) without discussion.

### Noir circuits (`noir/`)

- Changes to circuit logic **must** be accompanied by regenerated Solidity verifiers (see step 5 above).
- Circuit public inputs are part of the on-chain ABI — changes are breaking and require a discussion issue first.
- Test circuits with `nargo test` inside the circuit directory before opening a PR.

### TypeScript (`zksafe/`, `zknexus/`, `deploy/`)

- The project uses `viem` for Ethereum interactions — do not introduce `ethers.js`.
- Follow existing patterns in `zksafe/zksafe.ts` and `zknexus/zknexus.ts`.

### Adding a new ERC-8039 verifier adapter

This is one of the most impactful contributions. To add support for a new proof system (Groth16, PLONK, SP1, etc.):

1. Create `contracts/ERC8039/YourSystemProofVerifier.sol` implementing `IERC8039`.
2. Deploy and register the verifier address with the factory.
3. Add integration tests in `test/`.
4. Update `README.md` to list the new proof system.

---

## Running Tests

```bash
# Hardhat tests (TypeScript, full integration)
npx hardhat test

# Foundry tests (Solidity unit tests, faster)
forge test

# Noir circuit tests
cd noir/zk_multi_sig_ecdsa && nargo test
cd noir/zk_multi_sig_ecdsa_private_state_validation && nargo test
```

---

## Submitting a Pull Request

1. **Fork** the repository and create a branch from `main`:
   ```bash
   git checkout -b feat/your-feature-name
   ```
2. Make your changes and **commit with clear messages**.
3. Ensure **all tests pass** before opening a PR.
4. If you modified Noir circuits, include **regenerated Solidity verifiers** in the PR.
5. Open a PR against `main` and fill in the pull request template.
6. A maintainer will review and may request changes.

### Commit message conventions

```
feat: add Groth16 verifier adapter
fix: prevent duplicate signer addresses in circuit
docs: clarify state root construction
test: add threshold boundary tests
chore: update Noir dependencies
```

---

## Good First Issues

Look for issues labelled [`good first issue`](../../issues?q=label%3A%22good+first+issue%22) on GitHub. Some areas that are always welcome:

- Additional test coverage for edge cases in the Noir circuits
- CLI tooling to generate ZK proofs locally (wrapping `bb` and `nargo`)
- Testnet deployment scripts and documentation
- New ERC-8039 verifier adapters for additional proof systems
- Gas optimization in the Solidity verifier contracts
- Improving inline documentation

If you have an idea that doesn't have an issue yet, open one first to discuss before building.
