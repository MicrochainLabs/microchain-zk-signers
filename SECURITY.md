# Security Policy

## Supported Versions

Microchain ZK Signers is currently in pre-production development. Security fixes are applied to the latest version on `main`.

| Version | Supported |
|---------|-----------|
| `main` (latest) | ✅ |
| Older tagged releases | ❌ Upgrade to `main` |

---

## Scope

The following components are in scope for security reports:

- **Solidity contracts** (`contracts/`): logic bugs, access control issues, reentrancy, incorrect proof verification, state root manipulation
- **Noir circuits** (`noir/`): constraint soundness, under-constrained witnesses, signature malleability, Merkle proof forgery
- **ERC-8039 verifier adapters**: incorrect proof verification, magic value spoofing
- **TypeScript integration code** (`zksafe/`, `zknexus/`): issues that could cause incorrect proof generation or state root construction

The following are **out of scope**:

- Underlying cryptographic primitives (Barretenberg, UltraHonk, secp256k1) — report those to their respective upstream projects
- Third-party dependencies (Safe contracts, Nexus, OpenZeppelin) — report those upstream
- Issues that require the attacker to already control a majority of signers
- Theoretical attacks without a proof of concept

---

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please report security issues by emailing:

**security@microchainlabs.xyz**

Include the following in your report:

1. **Description**: A clear description of the vulnerability and its impact.
2. **Component**: Which contract, circuit, or module is affected.
3. **Steps to reproduce**: Minimal proof-of-concept or test case.
4. **Impact assessment**: What an attacker could achieve (e.g., bypass threshold, forge proof, drain funds).
5. **Suggested fix** (optional but appreciated).

### What to expect

- **Acknowledgement** within 48 hours.
- **Triage and severity assessment** within 5 business days.
- We will work with you on a coordinated disclosure timeline — typically 90 days from the initial report, or sooner if a fix is available.
- Public credit in the security advisory unless you prefer to remain anonymous.

---

## Security Considerations

The following known design trade-offs are by intent and are not vulnerabilities:

- **Off-chain proof generation**: The validity of the ZK proof depends on the prover correctly constructing the witness. Users must use trusted or audited tooling to generate proofs.
- **State root correctness**: The factory validates the initial state root on-chain, but signers must ensure their off-chain key management is secure.
- **Proof system trust**: The protocol inherits the soundness assumptions of the underlying proof system (currently UltraHonk / Barretenberg). A flaw in the proof system itself is not in scope for this repository.
- **Signature ordering**: The circuit enforces strictly increasing signer addresses to prevent signature reuse. Wallets must sort signers correctly before proof generation.

---

## Bug Bounty

There is currently no formal bug bounty program. However, we deeply appreciate responsible disclosures and will publicly acknowledge reporters (with permission) in any security advisory.
