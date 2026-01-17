import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

/**
 * Deployment module for the ZK MultiSig ECDSA Factory pattern
 * 
 * This module deploys:
 * 1. ERC-8039 compliant Honk verifiers for:
 *   - Private state validation
 *   - Transaction signature validation
 * 2. The Factory contract (which auto-deploys the Singleton)
 * The factory can then be used to deploy multiple ZK MultiSig ECDSA signers
 * with different state roots and verifiers.
 * 
 */
export default buildModule("ZKMultiSigEcdsaFactory_v1", (m) => {
  
  // Deploy the HonkVerifier for private state validation (different circuit than signature verification)
  // Using fully qualified name since both circuits export "HonkVerifier"
  const privateStateValidationHonkVerifier = m.contract(
    "noir/target/zk_multi_sig_ecdsa_private_state_validation.sol:HonkVerifier",
    [],
    {
      id: "privateStateValidationHonkVerifier"
    }
  );
  // Deploy the ERC-8039 adapter for private state validation
  const erc8039PrivateStateValidation = m.contract("PrivateStateValidationProofVerifier", [privateStateValidationHonkVerifier]);
  

  // Deploy the HonkVerifier for signature verification
  // Using fully qualified name to distinguish from state validation verifier
  const txValidationHonkVerifier = m.contract("noir/target/zk_multi_sig_ecdsa.sol:HonkVerifier", []);
  // Deploy the ERC-8039 adapter for transaction signature validation
  const erc8039TxValidation = m.contract("HonkProofVerifier", [txValidationHonkVerifier]);


  // Deploy the Factory (which deploys the Singleton in its constructor)
  const contractSignaturefactory = m.contract("ZKMultiSigEcdsaFactory", [erc8039PrivateStateValidation]);

  return { 
    txValidationHonkVerifier,
    erc8039TxValidation,
    privateStateValidationHonkVerifier,
    erc8039PrivateStateValidation,
    contractSignaturefactory
  };
});

/**
 * To deploy this module, run:
 * npx hardhat ignition deploy ignition/modules/zkMultiSigEcdsaFactory.ts
 */

