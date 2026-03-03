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
export default buildModule("ZKMultiSigEcdsaFactory_v4", (m) => {
  
  // ============================================================================
  // CONFIGURATION: Nexus deployed contracts
  // ============================================================================
  
  // Nexus account implementation address
  const NEXUS_IMPLEMENTATION_ADDRESS = "0x000000000032ddc454c3bdcba80484ad5a798705";
  
  // NexusBootstrap contract address
  const NEXUS_BOOTSTRAP_ADDRESS = "0x00000000006efb61d8c9546ff1b500de3f244ea7";
  
  // ============================================================================
  // Deploy verifiers and validator
  // ============================================================================
  
  // Deploy ZKTranscriptLib library required by HonkVerifier
  const zkTranscriptLib = m.library(
    "noir/target/zk_multi_sig_ecdsa_private_state_validation.sol:ZKTranscriptLib",
    {
      id: "zkTranscriptLib"
    }
  );

  // Deploy the HonkVerifier for private state validation
  // Using fully qualified name since both circuits export "HonkVerifier"
  const privateStateValidationHonkVerifier = m.contract(
    "noir/target/zk_multi_sig_ecdsa_private_state_validation.sol:HonkVerifier",
    [],
    {
      id: "privateStateValidationHonkVerifier",
      libraries: {
        ZKTranscriptLib: zkTranscriptLib
      }
    }
  );
  // Deploy the ERC-8039 adapter for private state validation
  const erc8039PrivateStateValidation = m.contract("PrivateStateValidationProofVerifier", [privateStateValidationHonkVerifier]);
  
  // Deploy ZKTranscriptLib library for transaction validation circuit
  const zkTranscriptLibTx = m.library(
    "noir/target/zk_multi_sig_ecdsa.sol:ZKTranscriptLib",
    {
      id: "zkTranscriptLibTx"
    }
  );

  // Deploy the HonkVerifier for signature verification
  // Using fully qualified name to distinguish from state validation verifier
  const txValidationHonkVerifier = m.contract(
    "noir/target/zk_multi_sig_ecdsa.sol:HonkVerifier", 
    [],
    {
      id: "txValidationHonkVerifier",
      libraries: {
        ZKTranscriptLib: zkTranscriptLibTx
      }
    }
  );
  // Deploy the ERC-8039 adapter for transaction signature validation
  const erc8039TxValidation = m.contract("ZKMultiSigEcdsaProofVerifier", [txValidationHonkVerifier]);

  // Deploy the ZK MultiSig Validator module
  const zkMultiSigValidator = m.contract("ZKMultiSigValidator", [
    erc8039PrivateStateValidation, 
    erc8039TxValidation
  ]);

  // Deploy the Factory with all required constructor parameters:
  // 1. implementation - Nexus account implementation address
  // 2. zkMultiSigValidator - ZK MultiSig Validator module address
  // 3. bootstrapper - NexusBootstrap address
  const zkMultiSigValidatorFactory = m.contract("ZKMultiSigValidatorFactory", [
    NEXUS_IMPLEMENTATION_ADDRESS,    // implementation
    zkMultiSigValidator,             // zkMultiSigValidator
    NEXUS_BOOTSTRAP_ADDRESS          // bootstrapper
  ]);

  return { 
    txValidationHonkVerifier,
    erc8039TxValidation,
    privateStateValidationHonkVerifier,
    erc8039PrivateStateValidation,
    zkMultiSigValidator,
    zkMultiSigValidatorFactory
  };
});

/**
 * To deploy this module, run:
 * npx hardhat ignition deploy ignition/modules/zkMultiSigEcdsaFactory.ts
 */

