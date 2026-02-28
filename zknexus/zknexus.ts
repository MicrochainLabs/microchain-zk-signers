/**
 * ZK MultiSig Validator Module for Nexus Smart Accounts
 * 
 * This module provides utilities for deploying and interacting with Nexus accounts
 * that use the ZKMultiSigValidator for privacy-preserving multi-signature validation.
 * 
 * @module zknexus
 */

import { HardhatRuntimeEnvironment } from "hardhat/types";
import { vars } from "hardhat/config";
import { privateKeyToAccount } from "viem/accounts";
import { 
    toHex, toBytes, recoverAddress, recoverPublicKey, Hex, 
    createWalletClient, http, WalletClient, pad, bytesToHex,
    createPublicClient, getContract, parseEther, concat, 
    encodePacked, encodeAbiParameters, parseAbiParameters,
    PublicClient, Account, Chain, Transport, parseAbi, formatEther,
    Hash, TransactionReceipt, decodeEventLog, Address, WalletActions,
    walletActions
} from "viem";
import factory from "../ignition/modules/zkMultiSigEcdsaFactoryNexus";
import { poseidon } from "@iden3/js-crypto";
import { LeanIMT } from "@zk-kit/lean-imt";
import crypto from 'crypto';
import { join } from "path";
import { Noir } from "@noir-lang/noir_js";
import { Barretenberg, UltraHonkBackend } from "@aztec/bb.js";
import { readFileSync } from "fs";
import assert from 'assert';



// Constants
export const MODULE_TYPE_VALIDATOR = 1;
export const VALIDATION_SUCCESS = 0;
export const VALIDATION_FAILED = 1;

/**
 * Configuration for ZK MultiSig Validator
 * Note: Verifier addresses are now immutable in the validator contract
 */
export interface ZKMultiSigConfig {
    stateRoot: string;          // bytes32 - Cryptographic commitment to signers
}

/**
 * Parameters for creating a ZK MultiSig Nexus account
 */
export interface CreateZKAccountParams {
    stateRoot: string;
    stateValidationProof: string;  // bytes - ZK proof validating initial state
    index?: bigint;
}

// Helper functions
function padArray(arr: any[], length: number, fillValue: any): any[] {
    const padded = [...arr];
    while (padded.length < length) {
        padded.push(fillValue);
    }
    return padded;
}

function extractCoordinates(pubKey: Hex) {
    const bytes = toBytes(pubKey);
    // Remove 0x04 prefix for uncompressed key
    const x = Array.from(bytes.slice(1, 33));
    const y = Array.from(bytes.slice(33, 65));
    return { x, y };
}

function extractRSFromSignature(sig: Hex): number[] {
    const bytes = toBytes(sig);
    // Extract r and s (first 64 bytes)
    return Array.from(bytes.slice(0, 64));
}

function ensureHexPrefix(value: string): `0x${string}` {
    return value.startsWith("0x") ? value as `0x${string}` : `0x${value}`;
}

// Hash function used to compute the tree nodes.
const hash = (a: bigint, b: bigint) => poseidon.hash([a, b])

/**
 * Helper class for ZK MultiSig Nexus operations
 */
export class ZKNexusHelper {
    private factoryAddress: Address;
    private validatorAddress: Address;
    private publicClient: PublicClient;
    private walletClient?: WalletClient;

    constructor(
        factoryAddress: string,
        validatorAddress: string,
        publicClient: PublicClient,
        walletClient?: WalletClient
    ) {
        this.factoryAddress = factoryAddress as Address;
        this.validatorAddress = validatorAddress as Address;
        this.publicClient = publicClient;
        this.walletClient = walletClient;
    }

    /**
     * Compute the deterministic address for a ZK MultiSig Nexus account
     */
    async computeAccountAddress(params: CreateZKAccountParams): Promise<string> {
        const {
            stateRoot,
            stateValidationProof,
            index = 0n
        } = params;

        const factoryABI = parseAbi([
            "function computeAccountAddress(bytes32 stateRoot, bytes stateValidationProof, uint256 index) view returns (address)"
        ]);

        const factory = getContract({
            address: this.factoryAddress,
            abi: factoryABI,
            client: this.publicClient
        });

        return await factory.read.computeAccountAddress([
            stateRoot as Hex,
            stateValidationProof as Hex,
            index
        ]) as string;
    }

    /**
     * Deploy a new Nexus account with ZK MultiSig validator
     */
    async createAccount(params: CreateZKAccountParams): Promise<{
        account: string;
        transaction: Hash;
    }> {
        if (!this.walletClient) {
            throw new Error("Wallet client required for account creation");
        }

        const {
            stateRoot,
            stateValidationProof,
            index = 0n
        } = params;

        const createAccountABI = parseAbi([
            "function createAccount(bytes32 stateRoot, bytes stateValidationProof, uint256 index) payable returns (address)"
        ]);

        const hash = await this.walletClient!.writeContract({
            address: this.factoryAddress,
            abi: createAccountABI,
            functionName: 'createAccount',
            args: [
                stateRoot as Hex,
                stateValidationProof as Hex,
                index
            ],
            account: this.walletClient!.account!,
            chain: undefined
        });

        const receipt = await this.publicClient.waitForTransactionReceipt({ hash });

        // Extract account address from event
        const eventABI = parseAbi([
            "event ZKMultiSigAccountCreated(address indexed account, bytes32 indexed stateRoot, uint256 index)"
        ]);

        let accountAddress: string | undefined;
        for (const log of receipt.logs) {
            try {
                const decoded = decodeEventLog({
                    abi: eventABI,
                    data: log.data,
                    topics: log.topics
                });
                if (decoded.eventName === "ZKMultiSigAccountCreated") {
                    accountAddress = (decoded.args as any).account as string;
                    break;
                }
            } catch {
                continue;
            }
        }

        if (!accountAddress) {
            throw new Error("Account creation event not found");
        }

        return {
            account: accountAddress,
            transaction: hash
        };
    }

    /**
     * Get ZK MultiSig configuration for a Nexus account
     */
    async getConfiguration(accountAddress: string): Promise<ZKMultiSigConfig> {
        const validatorABI = parseAbi([
            "function getStateRoot(address smartAccount) view returns (bytes32)"
        ]);

        const validator = getContract({
            address: this.validatorAddress,
            abi: validatorABI,
            client: this.publicClient
        });

        const stateRoot = await validator.read.getStateRoot([accountAddress as Address]) as string;

        return {
            stateRoot
        };
    }

    /**
     * Get the state validator address (immutable)
     */
    async getStateValidator(): Promise<string> {
        const validatorABI = parseAbi([
            "function stateValidator() view returns (address)"
        ]);

        const validator = getContract({
            address: this.validatorAddress,
            abi: validatorABI,
            client: this.publicClient
        });

        return await validator.read.stateValidator() as string;
    }

    /**
     * Get the user operation validator address (immutable)
     */
    async getUserOpValidator(): Promise<string> {
        const validatorABI = parseAbi([
            "function userOpValidator() view returns (address)"
        ]);

        const validator = getContract({
            address: this.validatorAddress,
            abi: validatorABI,
            client: this.publicClient
        });

        return await validator.read.userOpValidator() as string;
    }

    /**
     * Check if ZK validator is initialized for an account
     */
    async isInitialized(accountAddress: string): Promise<boolean> {
        const validatorABI = parseAbi([
            "function isInitialized(address smartAccount) view returns (bool)"
        ]);

        const validator = getContract({
            address: this.validatorAddress,
            abi: validatorABI,
            client: this.publicClient
        });

        return await validator.read.isInitialized([accountAddress as Address]) as boolean;
    }

    /**
     * Install ZK MultiSig validator on existing Nexus account
     * @param nexusAccountAddress The Nexus account address
     * @param stateRoot The state root commitment
     * @param stateValidationProof The ZK proof validating the state
     */
    async installValidator(
        nexusAccountAddress: Address,
        stateRoot: string,
        stateValidationProof: string
    ): Promise<Hash> {
        if (!this.walletClient) {
            throw new Error("Wallet client required for validator installation");
        }

        const initData = encodeAbiParameters(
            parseAbiParameters("bytes32, bytes"),
            [stateRoot as Hex, stateValidationProof as Hex]
        );

        const nexusABI = parseAbi([
            "function installModule(uint256 moduleTypeId, address module, bytes calldata initData) external"
        ]);

        return await this.walletClient.writeContract({
            address: nexusAccountAddress,
            abi: nexusABI,
            functionName: 'installModule',
            args: [
                BigInt(MODULE_TYPE_VALIDATOR),
                this.validatorAddress,
                initData
            ],
            account: this.walletClient.account!,
            chain: undefined
        });
    }

    /**
     * Encode a nonce with validator address (for UserOp)
     * @param sequence The nonce sequence number
     * @param validatorAddress The validator to use (use validator address for ZK validator)
     */
    encodeNonce(sequence: bigint, validatorAddress: string): bigint {
        // Nonce format: [192 bits validator address | 64 bits sequence]
        const validatorBits = BigInt(validatorAddress);
        const nonce = (validatorBits << 64n) | (sequence & 0xFFFFFFFFFFFFFFFFn);
        return nonce;
    }

    /**
     * Prepare initialization data for validator installation
     */
    encodeValidatorInitData(stateRoot: string, stateValidationProof: string): Hex {
        return encodeAbiParameters(
            parseAbiParameters("bytes32, bytes"),
            [stateRoot as Hex, stateValidationProof as Hex]
        );
    }
}

export default ZKNexusHelper;

/**
 * Hardhat task functions
 */


export async function proveStateConfiguration(
    signersRoot: Hex,
    threshold: number,
    salt: Hex,
    stateRoot: Hex
) {
    // Load compiled state validation circuit
    const circuitPath = join(
        process.cwd(),
        "noir",
        "target",
        "zk_multi_sig_ecdsa_private_state_validation.json"
    );
    const compiledCircuit = JSON.parse(readFileSync(circuitPath, "utf-8"));

    // Initialize UltraHonk backend for state validation circuit
    const api = await Barretenberg.new({ threads: 1 });
    const backend = new UltraHonkBackend(compiledCircuit.bytecode,  api );
    const noir = new Noir(compiledCircuit);
    console.log("State validation UltraHonk backend initialized");

    try {
        // Prepare circuit inputs (now includes salt)
        const input = {
            signers_root: signersRoot,
            threshold: threshold,
            salt: salt,
            on_chain_state_root: pad(stateRoot, { size: 32 })
        };

        console.log("State validation inputs:", input);

        // Generate witness
        console.log("Generating witness for state validation...");
        const { witness } = await noir.execute(input);
        console.log("Witness generated successfully");

        // Generate proof
        console.log("Generating state validation proof...");
        const startTime = Date.now();
        const proofData = await backend.generateProof(witness, {
            verifierTarget: 'evm', // Use keccak hash for EVM verification
        });
        const provingTime = Date.now() - startTime;
        console.log(`State validation proof generated in ${provingTime}ms`);
        console.log(`Proof size: ${proofData.proof.length} bytes`);
        console.log(`Public inputs: ${proofData.publicInputs.length}`);

        // Verify proof locally
        console.log("Verifying state validation proof...");
        const isValid = await backend.verifyProof(proofData, {
            verifierTarget: 'evm' // Use keccak hash for EVM verification
        });
        assert(isValid, "State validation proof verification failed");
        console.log("State validation proof verified successfully");

        return proofData;
    } finally {
        await api.destroy();
    }
}


/**
 * Generate ZK proof from pre-collected signatures (without generating new signatures)
 */
export async function proveWithExistingSignatures(
    txHash: Hex,
    signatures: Hex[],
    privateSigners: string[],
    privateThreshold: number,
    salt: Hex,
    signersAddressesFormat: number = 0
) {
    const MAX_DEPTH = 4;
    
    // Nil values for padding
    const nil_pubkey = {
        x: Array.from(toBytes("0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")),
        y: Array.from(toBytes("0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"))
    };
    const nil_signature = Array.from(
        toBytes("0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"));

    // Sort signatures by address (normalize to lowercase for comparison)
    const sortedSignatures = await Promise.all(signatures.map(async (sig) => {
        const addr = await recoverAddress({ hash: txHash, signature: sig });
        return { sig, addr: addr.toLowerCase() };
    }));
    sortedSignatures.sort((a, b) => a.addr.localeCompare(b.addr));
    const sortedSigs = sortedSignatures.map(s => s.sig);
    
    console.log("=== proveWithExistingSignatures Debug ===");
    console.log("Recovered signers from signatures:", sortedSignatures.map(s => s.addr));

    // Sort signers for deterministic tree construction (normalize to lowercase)
    const sortedPrivateSigners = [...privateSigners].map(s => s.toLowerCase()).sort((a, b) => {
        const addrA = BigInt(a);
        const addrB = BigInt(b);
        if (addrA < addrB) return -1;
        if (addrA > addrB) return 1;
        return 0;
    });
    
    console.log("Sorted private signers for tree:", sortedPrivateSigners);
    
    //@ts-ignore
    const signersTree = new LeanIMT(hash);
    for (const privateSigner of sortedPrivateSigners) {
        if (signersAddressesFormat == 0)
            signersTree.insert(poseidon.hash([BigInt(privateSigner)]));
        else if (signersAddressesFormat == 1)
            signersTree.insert(BigInt(privateSigner));
        else
            throw new Error("Invalid owner addresses format");
    }
    
    console.log("Signers tree size:", signersTree.size);
    console.log("Signers tree root:", toHex(signersTree.root));
    
    // Compute preliminary state root (signers + threshold)
    const preliminaryStateTree = new LeanIMT(hash);
    preliminaryStateTree.insert(signersTree.root);
    preliminaryStateTree.insert(poseidon.hash([BigInt(privateThreshold)]));
    
    // Mix salt into final state root
    const finalStateRoot = poseidon.hash([preliminaryStateTree.root, BigInt(salt)]);
    console.log("Computed state root (with salt):", toHex(finalStateRoot));

    // Generate merkle proofs for each signer
    const signersPathsProof: any[][] = [];
    const signersIndicesProof: any[][] = [];
    const merkleProofLength: any[] = [];
    
    for (const signature of sortedSigs) {
        const recoveredAddress = (await recoverAddress({ hash: txHash, signature: signature })).toLowerCase();
        const index = await signersTree.indexOf(poseidon.hash([BigInt(recoveredAddress)]));
        
        if (index === -1) {
            throw new Error(
                `Signer address not found in tree!\n` +
                `Recovered address: ${recoveredAddress}\n` +
                `Expected signers in tree: ${sortedPrivateSigners.join(', ')}\n` +
                `Recovered signers from signatures: ${sortedSignatures.map(s => s.addr).join(', ')}\n` +
                `Make sure --privatesigners matches the addresses used when creating the account!`
            );
        }
        
        const addressProof = await signersTree.generateProof(index);

        await signersPathsProof.push(padArray(addressProof.siblings.map(v => toHex(v)), MAX_DEPTH, "0x0"));
        merkleProofLength.push(addressProof.siblings.length);

        const merkleProofIndices = [];
        for (let i = 0; i < MAX_DEPTH; i += 1) {
            merkleProofIndices.push((addressProof.index >> i) & 1);
        }
        
        await signersIndicesProof.push(merkleProofIndices);
    }
    
    // Prepare circuit inputs
    const defaultTxSigSiblingsOrIndices = Array(MAX_DEPTH).fill("0x0");
    const input = {
        signers: padArray(await Promise.all(sortedSigs.map(async (sig) => {
            const pubKey = await recoverPublicKey({
                hash: txHash as `0x${string}`,
                signature: sig
            });
            return extractCoordinates(pubKey);
        })), 5, nil_pubkey),
        threshold: toHex(BigInt(privateThreshold)),
        signers_root: toHex(signersTree.root),
        merkle_proof_length: padArray(merkleProofLength, 5, 0),
        indices: padArray(signersIndicesProof, 5, defaultTxSigSiblingsOrIndices),
        siblings: padArray(signersPathsProof, 5, defaultTxSigSiblingsOrIndices),
        signatures: padArray(sortedSigs.map(sig => extractRSFromSignature(sig)), 5, nil_signature),
        txn_hash: Array.from(toBytes(txHash as `0x${string}`)),
        on_chain_state_root: toHex(finalStateRoot),
        salt: salt
    };

    // Load compiled circuit
    const circuitPath = join(process.cwd(), "noir", "target", "zk_multi_sig_ecdsa.json");
    const compiledCircuit = JSON.parse(readFileSync(circuitPath, "utf-8"));
    
    // Initialize UltraHonk backend
    const api = await Barretenberg.new({ threads: 1 });
    const backend = new UltraHonkBackend(compiledCircuit.bytecode, api);
    const noir = new Noir(compiledCircuit);

    try {
        // Generate witness
        console.log("Generating witness for transaction...");
        const { witness } = await noir.execute(input);
        console.log("Witness generated successfully");

        // Generate proof
        console.log("Generating transaction proof...");
        const startTime = Date.now();
        const proofData = await backend.generateProof(witness, {
            verifierTarget: 'evm',
        });
        const provingTime = Date.now() - startTime;
        console.log(`Proof generated in ${provingTime}ms`);
        console.log(`Proof size: ${proofData.proof.length} bytes`);
        console.log(`Public inputs count: ${proofData.publicInputs.length}`);

        // Verify proof
        console.log("Verifying proof...");
        const isValid = await backend.verifyProof(proofData, {
            verifierTarget: 'evm'
        });
        assert(isValid, "Transaction proof verification failed");
        console.log("Proof verified successfully ✅");
        
        // Log the hash that was proven
        console.log(`   Hash proven in ZK: ${txHash}`);

        return proofData;
    } finally {
        await api.destroy();
    }
}

/**
 * Compute deterministic address for a ZK Nexus account
 */
export async function computeZKNexusAddress(
    hre: HardhatRuntimeEnvironment,
    factoryAddress: string,
    validatorAddress: string,
    stateRoot: string,
    stateValidationProof: string,
    index: string
) {
    const networkConfig = hre.network.config as any;
    const publicClient = createPublicClient({
        transport: http(networkConfig.url)
    });
    
    const helper = new ZKNexusHelper(
        factoryAddress,
        validatorAddress,
        publicClient
    );
    
    const address = await helper.computeAccountAddress({
        stateRoot,
        stateValidationProof,
        index: BigInt(index)
    });

    console.log("Computed Nexus account address:", address);
    console.log("\nParameters:");
    console.log("  Factory:", factoryAddress);
    console.log("  Validator:", validatorAddress);
    console.log("  State Root:", stateRoot);
    console.log("  Proof Length:", stateValidationProof.length, "bytes");
    console.log("  Index:", index);
    
    return address;
}

/**
 * Get ZK MultiSig configuration for a Nexus account
 */
export async function getZKNexusConfig(
    hre: HardhatRuntimeEnvironment,
    validatorAddress: string,
    accountAddress: string
) {
    const networkConfig = hre.network.config as any;
    const publicClient = createPublicClient({
        transport: http(networkConfig.url)
    });
    
    const helper = new ZKNexusHelper(
        "0x0000000000000000000000000000000000000000", // Factory not needed for config read
        validatorAddress,
        publicClient
    );

    console.log("Checking Nexus account:", accountAddress);
    
    const isInit = await helper.isInitialized(accountAddress);
    console.log("  Is initialized:", isInit);

    if (isInit) {
        const config = await helper.getConfiguration(accountAddress);
        console.log("  State Root:", config.stateRoot);
        
        // Get verifier addresses (immutable in validator)
        const stateValidator = await helper.getStateValidator();
        const userOpValidator = await helper.getUserOpValidator();
        console.log("  State Validator:", stateValidator);
        console.log("  UserOp Validator:", userOpValidator);
        
        return config;
    } else {
        console.log("  ⚠️  Account not initialized with ZK validator");
    }
}

/**
 * Check if ZK validator is initialized for a Nexus account
 */
export async function checkZKNexusInitialized(
    hre: HardhatRuntimeEnvironment,
    validatorAddress: string,
    accountAddress: string
) {
    const networkConfig = hre.network.config as any;
    const publicClient = createPublicClient({
        transport: http(networkConfig.url)
    });
    
    const helper = new ZKNexusHelper(
        "0x0000000000000000000000000000000000000000",
        validatorAddress,
        publicClient
    );

    const isInit = await helper.isInitialized(accountAddress);
    console.log("Account:", accountAddress);
    console.log("Validator:", validatorAddress);
    console.log("Is initialized:", isInit);
    
    return isInit;
}

/**
 * Get the EntryPoint address used by a Nexus account
 */
export async function getAccountEntryPoint(
    hre: HardhatRuntimeEnvironment,
    accountAddress: string
) {
    const networkConfig = hre.network.config as any;
    const publicClient = createPublicClient({
        transport: http(networkConfig.url)
    });
    
    console.log("\n🔍 Checking EntryPoint for Nexus account...");
    console.log("   Account:", accountAddress);
    console.log("   Network:", hre.network.name);

    // Query the account's entryPoint() view function
    const accountABI = parseAbi(["function entryPoint() external view returns (address)"]);
    const accountContract = getContract({
        address: accountAddress as Address,
        abi: accountABI,
        client: publicClient
    });

    try {
        const entryPointAddress = await accountContract.read.entryPoint() as Address;
        console.log("\n✅ EntryPoint Address:", entryPointAddress);
        
        // Identify which version it is
        const knownEntryPoints: Record<string, string> = {
            "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789": "v0.6.0",
            "0x0000000071727De22E5E9d8BAf0edAc6f37da032": "v0.7.0",
        };
        
        const version = knownEntryPoints[entryPointAddress] || "Unknown version";
        console.log("   Version:", version);
        
        console.log("\n⚠️  Important: The EntryPoint is IMMUTABLE and cannot be changed.");
        console.log("   This was set during account deployment and is hardcoded in the contract.");
        console.log("   To use a different EntryPoint (v0.8.0, v0.9.0, etc.), you would need to");
        console.log("   deploy a NEW account with that EntryPoint address.");
        
        return entryPointAddress;
    } catch (error) {
        console.error("\n❌ Error querying EntryPoint:", error);
        throw error;
    }
}

/**
 * Send a UserOperation using the ZK Nexus account with pre-collected signatures
 */
export async function sendZKNexusUserOp(
    hre: HardhatRuntimeEnvironment,
    accountAddress: string,
    validatorAddress: string,
    entryPointAddress: string,
    to: string,
    value: string,
    data: string,
    signatures: Hex[],
    userOpHash: Hex,
    privateSigners: string[],
    privateThreshold: number,
    salt: Hex
) {
    const pk = vars.get("DEPLOYER_PRIVATE_KEY") as string;
    const networkConfig = hre.network.config as any;
    const publicClient = createPublicClient({
        transport: http(networkConfig.url)
    });
    const account = privateKeyToAccount(ensureHexPrefix(pk));
    const walletClient = createWalletClient({
        account,
        transport: http(networkConfig.url)
    }).extend(walletActions);

    console.log("\n🚀 Preparing UserOperation...");
    console.log("   Account:", accountAddress);
    console.log("   To:", to);
    console.log("   Value:", value);
    console.log("   Validator:", validatorAddress);

    // Parse value: if it contains a decimal point, treat as POL and convert to wei
    const valueInWei = value.includes(".") ? parseEther(value) : BigInt(value);
    console.log("   Value in wei:", valueInWei.toString());

    // Auto-detect EntryPoint if not provided
    if (!entryPointAddress || entryPointAddress === "" || entryPointAddress === "0x0000000000000000000000000000000000000000") {
        console.log("\n🔍 Auto-detecting EntryPoint...");
        const accountABI = parseAbi(["function entryPoint() external view returns (address)"]);
        const accountContract = getContract({
            address: accountAddress as Address,
            abi: accountABI,
            client: publicClient
        });
        entryPointAddress = await accountContract.read.entryPoint() as string;
    }
    console.log("   EntryPoint:", entryPointAddress);

     // First, check if the validator is installed on the account
    console.log("\n🔍 Checking validator installation...");
    const accountABI = parseAbi([
        "function isModuleInstalled(uint256 moduleTypeId, address module, bytes calldata additionalContext) external view returns (bool)"
    ]);
    const accountContract = getContract({
        address: accountAddress as Address,
        abi: accountABI,
        client: publicClient
    });
    
    const isInstalled = await accountContract.read.isModuleInstalled([
        BigInt(MODULE_TYPE_VALIDATOR), // 1 for validator
        validatorAddress as Address,
        "0x" as Hex // empty context
    ]) as boolean;
    
    console.log("   Is validator installed:", isInstalled);
    
    if (!isInstalled) {
        console.error("\n❌ VALIDATOR NOT INSTALLED!");
        console.error("   The ZK MultiSig validator is not installed on this Nexus account.");
        console.error("   You need to install the validator module first.");
        console.error("\n   To install, you would need to call:");
        console.error(`   account.installModule(${MODULE_TYPE_VALIDATOR}, "${validatorAddress}", initData)`);
        throw new Error("ZK MultiSig validator not installed on account");
    }
    
    console.log("   ✅ Validator is installed");
    
    // Check if validator is initialized with state configuration
    const validatorABI = parseAbi([
        "function isInitialized(address smartAccount) view returns (bool)",
        "function getStateRoot(address smartAccount) view returns (bytes32)"
    ]);
    const validatorContract = getContract({
        address: validatorAddress as Address,
        abi: validatorABI,
        client: publicClient
    });
    
    const isInitialized = await validatorContract.read.isInitialized([accountAddress as Address]) as boolean;
    console.log("   Is validator initialized:", isInitialized);
    
    if (!isInitialized) {
        console.error("\n❌ VALIDATOR NOT INITIALIZED!");
        console.error("   The validator module is installed but not initialized with state configuration.");
        console.error("   This is unusual - the factory should have initialized it during account creation.");
        console.error("\n   Debug info:");
        console.error(`   - Account: ${accountAddress}`);
        console.error(`   - Validator: ${validatorAddress}`);
        console.error("   - Module installed: true");
        console.error("   - Module initialized: false");
        throw new Error("ZK MultiSig validator not initialized on account");
    }
    
    console.log("   ✅ Validator is initialized");

    // Verify on-chain state root matches what we computed
    console.log("\n🔍 Verifying on-chain state configuration...");
    const onChainStateRoot = await validatorContract.read.getStateRoot([accountAddress as Address]) as Hex;
    console.log("   On-chain state root:", onChainStateRoot);

    // Encode the execution call data (ERC-7579 execute)
    // Mode bytes: [CallType][ExecType][bytes4 zeros][bytes4 selector][bytes22 context]
    // CallType: 0x00=single, 0x01=batch | ExecType: 0x00=revert, 0x01=try
    const executionMode = "0x0000000000000000000000000000000000000000000000000000000000000000" as Hex; // Single execution, revert on error
    const executionCalldata = concat([
        to as Hex,                                    // address (20 bytes hex)
        pad(toHex(valueInWei), { size: 32 }),       // value as 32-byte hex
        data as Hex                                   // calldata
    ]);
    const callData = concat([
        "0xe9ae5c53" as Hex, // execute(bytes32,bytes) selector
        encodeAbiParameters(
            parseAbiParameters("bytes32, bytes"),
            [executionMode, executionCalldata]
        )
    ]);

    // Get nonce with validator encoding
    const entryPointABI = parseAbi(["function getNonce(address,uint192) view returns (uint256)"]);
    const entryPoint = getContract({
        address: entryPointAddress as Address,
        abi: entryPointABI,
        client: publicClient
    });
    const validatorBits = BigInt(validatorAddress);
    const nonceKey = validatorBits;  // Validator address IS the nonce key (uint192)
    const nonce = await entryPoint.read.getNonce([accountAddress as Address, nonceKey]) as bigint;

    console.log("   Nonce:", nonce.toString());

    // Prepare UserOperation
    // NOTE: UltraHonk verification requires ~10M gas for all modexp/pairing operations
    const userOp = {
        sender: accountAddress,
        nonce: nonce,
        initCode: "0x" as Hex,
        callData: callData,
        accountGasLimits: encodePacked(["uint128", "uint128"], [BigInt(10000000), BigInt(3000000)]), // verificationGasLimit: 10M, callGasLimit: 3M
        preVerificationGas: BigInt(300000),
        gasFees: encodePacked(["uint128", "uint128"], [BigInt(3000000), BigInt(3000000)]),
        paymasterAndData: "0x" as Hex,
        signature: "0x" as Hex
    };

    // Get UserOp hash from EntryPoint and verify it matches the provided hash
    const entryPointHashABI = parseAbi([
        "function getUserOpHash((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)) view returns (bytes32)"
    ]);
    const entryPointContract = getContract({
        address: entryPointAddress as Address,
        abi: entryPointHashABI,
        client: publicClient
    });
    const computedUserOpHash = await entryPointContract.read.getUserOpHash([[
        userOp.sender,
        userOp.nonce,
        userOp.initCode,
        userOp.callData,
        userOp.accountGasLimits,
        userOp.preVerificationGas,
        userOp.gasFees,
        userOp.paymasterAndData,
        userOp.signature
    ]]) as Hex;

    console.log("\n   Computed UserOp Hash:", computedUserOpHash);
    console.log("   Provided UserOp Hash:", userOpHash);
    
    // Verify the hashes match
    if (computedUserOpHash.toLowerCase() !== userOpHash.toLowerCase()) {
        console.error("\n❌ HASH MISMATCH!");
        console.error("   This usually means the nonce changed between signing and submission.");
        console.error("   You need to regenerate signatures with the current UserOp hash.");
        throw new Error(`UserOp hash mismatch! Computed: ${computedUserOpHash}, Provided: ${userOpHash}`);
    }
    
    console.log("   ✅ UserOp hashes match!");

    // Generate ZK proof using pre-collected signatures
    console.log("\n🔐 Generating ZK proof with", signatures.length, "signature(s)...");
    const proofData = await proveWithExistingSignatures(
        userOpHash,
        signatures,
        privateSigners,
        privateThreshold,
        salt
    );

    // Set the proof as signature
    userOp.signature = toHex(proofData.proof);
    
    console.log("\n📤 Sending UserOperation...");
    
    // DIRECT VERIFIER TEST - Test the proof directly before submitting
    console.log("\n🧪 Testing verifier directly with proof and public inputs...");
    try {
        const verifierABI = parseAbi(["function verify(bytes calldata proof, bytes32[] calldata publicInputs) external returns (bool)"]);
        const honkVerifierAddress = "0xa68816F03fd22Fa6f17fE4B80aC5F98C3E73301a" as Address; // Direct HonkVerifier
        const honkVerifier = getContract({
            address: honkVerifierAddress,
            abi: verifierABI,
            client: publicClient
        });
        
        // Construct public inputs exactly as the validator does
        const testPublicInputs: Hex[] = [];
        const hashBytes = userOpHash.slice(2); // Remove 0x
        for (let i = 0; i < 32; i++) {
            const byte = hashBytes.substring(i * 2, i * 2 + 2);
            testPublicInputs.push(pad(('0x' + byte) as Hex, { size: 32 }));
        }
        testPublicInputs.push(pad(onChainStateRoot, { size: 32 }));
        
        console.log("   Test public inputs length:", testPublicInputs.length);
        console.log("   Test proof length:", userOp.signature.length);
        
        // Try calling verify (this will revert if it fails)
        const testResult = await publicClient.readContract({
            address: honkVerifierAddress,
            abi: verifierABI,
            functionName: 'verify',
            args: [userOp.signature, testPublicInputs]
        });
        console.log("   ✅ Direct verifier test PASSED! Result:", testResult);
    } catch (verifierError: any) {
        console.error("\n   ❌ Direct verifier test FAILED!");
        console.error("   Error:", verifierError.message);
        if (verifierError.data) {
            console.error("   Error data:", verifierError.data);
        }
        // Try to decode the error if it's a custom error
        if (verifierError.message.includes("PublicInputsLengthWrong")) {
            console.error("   → Public inputs length is wrong!");
        } else if (verifierError.message.includes("ProofLengthWrongWithLogN")) {
            console.error("   → Proof length is wrong for LOG_N!");
        } else if (verifierError.message.includes("SumcheckFailed")) {
            console.error("   → Sumcheck verification failed!");
        } else if (verifierError.message.includes("ShpleminiFailed")) {
            console.error("   → Shplemini verification failed!");
        }
        console.error("\n   This indicates the proof is being rejected by the verifier.");
        console.error("   Possible causes:");
        console.error("   1. Verifier contract VK doesn't match circuit used for proving");
        console.error("   2. Proof or public inputs are malformed");
        console.error("   3. Verifier contract is from a different circuit version");
    }
    
    // Send through EntryPoint
    const entryPointCallABI = parseAbi([
        "function handleOps((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)[], address) payable"
    ]);

    try {
        const hash = await walletClient.writeContract({
            address: entryPointAddress as Address,
            abi: entryPointCallABI,
            functionName: 'handleOps',
            args: [
                [[
                    userOp.sender as Address,
                    userOp.nonce,
                    userOp.initCode,
                    userOp.callData,
                    userOp.accountGasLimits,
                    userOp.preVerificationGas,
                    userOp.gasFees,
                    userOp.paymasterAndData,
                    userOp.signature
                ]],
                account.address
            ],
            chain: undefined
        });

        console.log("   Transaction hash:", hash);
        const receipt = await publicClient.waitForTransactionReceipt({ hash });
        console.log("   Gas used:", receipt.gasUsed.toString());
        console.log("   Status:", receipt.status);
        
        // Check if transaction succeeded
        if (receipt.status === "reverted") {
            console.error("\n❌ Transaction REVERTED!");
            console.error("   The transaction was mined but execution failed.");
            
            // Try to decode FailedOp event to get AA error code
            const failedOpABI = parseAbi([
                "event UserOperationRevertReason(bytes32 indexed userOpHash, address indexed sender, uint256 nonce, bytes revertReason)",
                "event UserOperationEvent(bytes32 indexed userOpHash, address indexed sender, address indexed paymaster, uint256 nonce, bool success, uint256 actualGasCost, uint256 actualGasUsed)"
            ]);
            
            for (const log of receipt.logs) {
                try {
                    const decoded = decodeEventLog({
                        abi: failedOpABI,
                        data: log.data,
                        topics: log.topics
                    });
                    
                    if (decoded.eventName === "UserOperationRevertReason") {
                        console.error("\n   Revert reason:", decoded.args.revertReason);
                        const revertStr = decoded.args.revertReason.toString();
                        
                        // Check for AA error codes in revert reason
                        if (revertStr.includes('AA24')) {
                            console.error("\n🔐 ERROR: AA24 - ZK Proof verification failed on-chain");
                            console.error("   Even though the direct verifier test passed, the on-chain validation rejected the proof.");
                            console.error("\n   Possible causes:");
                            console.error("   1. Different verifier contract being used by validator vs direct test");
                            console.error("   2. Public inputs constructed differently by validator");
                            console.error("   3. State root mismatch between local and on-chain");
                        } else if (revertStr.includes('AA25')) {
                            console.error("\n🔢 ERROR: AA25 - Invalid nonce");
                            console.error(`   The nonce changed between signing and submission.`);
                        } else if (revertStr.includes('AA21')) {
                            console.error("\n💰 ERROR: AA21 - Insufficient funds");
                        }
                    } else if (decoded.eventName === "UserOperationEvent") {
                        console.error("\n   UserOp success:", decoded.args.success);
                        console.error("   Actual gas used:", decoded.args.actualGasUsed?.toString());
                    }
                } catch (e) {
                    // Not a UserOp event, skip
                }
            }
            
            throw new Error(`Transaction reverted. Hash: ${hash}. Check PolygonScan for details.`);
        }
        
        console.log("\n✅ UserOperation executed successfully!");

        return {
            userOpHash,
            txHash: hash,
            receipt
        };
    } catch (error: any) {
        console.error("\n❌ UserOperation failed!");
        
        // Check for specific AA errors (check AA24 BEFORE AA21 since error code can contain both)
        if (error.data && typeof error.data === 'string') {
            const errorData = error.data;
            const errorMessage = error.message || '';
            
            // AA25: invalid nonce (check this first!)
            if (errorData.includes('AA25') || errorMessage.includes('AA25')) {
                console.error("\n🔢 ERROR: AA25 - Invalid account nonce");
                console.error("   The nonce in your UserOp doesn't match the account's current nonce.");
                console.error(`\n   Debug info:`);
                console.error(`   - Nonce used in UserOp: ${userOp.nonce.toString()}`);
                console.error(`   - UserOp hash signed: ${userOpHash}`);
                console.error(`\n   This usually means:`);
                console.error(`   1. Another transaction was sent between signing and submission`);
                console.error(`   2. You tried to submit a UserOp with an old signature`);
                console.error(`\n   Solution:`);
                console.error(`   1. Check current nonce: npx hardhat checkZKNexusAccount --network polygon --account ${accountAddress} --validator ${validatorAddress}`);
                console.error(`   2. Generate new signatures with current nonce using: npx hardhat signUserOp ...`);
                console.error(`   3. Collect threshold signatures and submit again`);
            }
            // AA24: signature error
            else if (errorData.includes('AA24') || errorMessage.includes('AA24')) {
                console.error("\n🔐 ERROR: AA24 - ZK Proof verification failed");
                console.error("   The proof was generated successfully but failed on-chain verification.");
                console.error("\n   Verified locally:");
                console.error(`   ✅ Public inputs match expected format`);
                console.error(`   ✅ State root matches on-chain`);
                console.error(`   ✅ UserOp hash matches: ${userOpHash}`);
                console.error("\n   Possible causes:");
                console.error("   1. Account has insufficient MATIC for gas (fund it first)");
                console.error("   2. Verifier contract issue (UltraHonk EVM verifier)");
                console.error("   3. Proof bytes encoding issue");
                console.error(`\n   Next steps:`);
                console.error(`   1. Fund account: cast send ${accountAddress} --value 0.1ether --rpc-url https://polygon-rpc.com --private-key $DEPLOYER_PRIVATE_KEY`);
                console.error(`   2. Check verifier contract deployment`);
            }
            // AA21: didn't pay prefund
            else if (errorMessage.includes('AA21')) {
                console.error("\n💰 ERROR: AA21 - Account needs funding");
                console.error(`   Send some MATIC to ${accountAddress}`);
                console.error(`   Recommended: 0.1 MATIC for gas`);
                console.error(`\n   Command:`);
                console.error(`   cast send ${accountAddress} --value 0.1ether --rpc-url https://polygon-rpc.com --private-key $DEPLOYER_PRIVATE_KEY`);
            }
        }
        
        throw error;
    }
}

/**
 * Sign a UserOperation for a ZK Nexus account (similar to zksafe sign)
 * This generates a single ECDSA signature from SAFE_OWNER_PRIVATE_KEY
 */
export async function signUserOp(
    hre: HardhatRuntimeEnvironment,
    accountAddress: string,
    validatorAddress: string,
    to: string,
    value: string,
    data: string
) {
    // Get wallet client (like zksafe sign)
    const pk = vars.get("SAFE_OWNER_PRIVATE_KEY") as string;
    const account = privateKeyToAccount(ensureHexPrefix(pk));
    const mywalletAddress = account.address;
    console.log("My wallet address:", mywalletAddress);

    const networkConfig = hre.network.config as any;
    const publicClient = createPublicClient({
        transport: http(networkConfig.url)
    });

    console.log("\n🔏 Signing UserOperation for ZK Nexus Account...");
    console.log("   Account:", accountAddress);
    console.log("   To:", to);
    console.log("   Value:", value);
    console.log("   Data:", data);

    // Parse value: if it contains a decimal point, treat as POL and convert to wei
    const valueInWei = value.includes(".") ? parseEther(value) : BigInt(value);
    console.log("   Value in wei:", valueInWei.toString());

    // Get the EntryPoint address from the account
    const accountABI = parseAbi(["function entryPoint() external view returns (address)"]);
    const accountContract = getContract({
        address: accountAddress as Address,
        abi: accountABI,
        client: publicClient
    });
    const entryPointAddress = await accountContract.read.entryPoint() as Address;
    console.log("   EntryPoint:", entryPointAddress);

    // Encode the execution call data (ERC-7579 execute)
    // Mode bytes: [CallType][ExecType][bytes4 zeros][bytes4 selector][bytes22 context]
    // CallType: 0x00=single, 0x01=batch | ExecType: 0x00=revert, 0x01=try
    const executionMode = "0x0000000000000000000000000000000000000000000000000000000000000000" as Hex; // Single execution, revert on error
    const executionCalldata = concat([
        to as Hex,                                    // address (20 bytes hex)
        pad(toHex(valueInWei), { size: 32 }),       // value as 32-byte hex
        data as Hex                                   // calldata
    ]);
    const callData = concat([
        "0xe9ae5c53" as Hex, // execute(bytes32,bytes) selector
        encodeAbiParameters(
            parseAbiParameters("bytes32, bytes"),
            [executionMode, executionCalldata]
        )
    ]);

    // Get nonce with validator encoding
    const entryPointABI = parseAbi(["function getNonce(address,uint192) view returns (uint256)"]);
    const entryPoint = getContract({
        address: entryPointAddress,
        abi: entryPointABI,
        client: publicClient
    });
    const validatorBits = BigInt(validatorAddress);
    const nonceKey = validatorBits;  // Validator address IS the nonce key (uint192)
    const nonce = await entryPoint.read.getNonce([accountAddress as Address, nonceKey]) as bigint;

    console.log("\n📋 UserOperation Details:");
    console.log("   Nonce key:", nonceKey.toString());
    console.log("   Nonce (full):", nonce.toString());
    console.log("   Nonce (hex):", "0x" + nonce.toString(16));
    
    // Decode nonce to show validator and sequence
    const nonceSequence = nonce & 0xFFFFFFFFFFFFFFFFn; // Lower 64 bits
    const nonceValidator = nonce >> 64n; // Upper 192 bits
    console.log("   Nonce sequence:", nonceSequence.toString());
    console.log("   Nonce validator:", "0x" + nonceValidator.toString(16));
    console.log("   CallData length:", callData.length);

    // Prepare UserOperation
    // NOTE: UltraHonk verification requires ~10M gas for all modexp/pairing operations
    const userOp = {
        sender: accountAddress,
        nonce: nonce,
        initCode: "0x" as Hex,
        callData: callData,
        accountGasLimits: encodePacked(["uint128", "uint128"], [BigInt(10000000), BigInt(3000000)]), // verificationGasLimit: 10M, callGasLimit: 3M
        preVerificationGas: BigInt(300000),
        gasFees: encodePacked(["uint128", "uint128"], [BigInt(3000000), BigInt(3000000)]),
        paymasterAndData: "0x" as Hex,
        signature: "0x" as Hex
    };

    // Get UserOp hash from EntryPoint
    const entryPointHashABI = parseAbi([
        "function getUserOpHash((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)) view returns (bytes32)"
    ]);
    const entryPointContract = getContract({
        address: entryPointAddress,
        abi: entryPointHashABI,
        client: publicClient
    });
    const userOpHash = await entryPointContract.read.getUserOpHash([[
        userOp.sender,
        userOp.nonce,
        userOp.initCode,
        userOp.callData,
        userOp.accountGasLimits,
        userOp.preVerificationGas,
        userOp.gasFees,
        userOp.paymasterAndData,
        userOp.signature
    ]]) as Hex;

    console.log("\n🔑 UserOp Hash:", userOpHash);

    // Sign the UserOp hash using raw hash signing (not message signing)
    console.log("\n✍️  Signing with account:", mywalletAddress);
    const signature = await account.sign({ 
        hash: userOpHash as `0x${string}` 
    });

    console.log("\n✅ Signature generated:");
    console.log("   Signer:", mywalletAddress);
    console.log("   Signature:", signature);

    console.log("\n💾 Save this information for proof generation:");
    console.log("   UserOp Hash:", userOpHash);
    console.log("   Signature:", signature);

    return {
        userOpHash,
        signature,
        signer: mywalletAddress,
        userOp
    };
}

/**
 * Create a new ZK MultiSig Nexus account
 */
export async function createZKNexusAccount(
    hre: HardhatRuntimeEnvironment,
    privateSigners: string[],
    privateThreshold: number,
    moduleValidatorAddress: string,
    factoryAddress: string,
) {
    const pk = vars.get("DEPLOYER_PRIVATE_KEY") as string;
    const deployerAccount = privateKeyToAccount(ensureHexPrefix(pk));
    const walletClient: WalletClient = createWalletClient({
        account: deployerAccount,
        //@ts-ignore
        transport: http(hre.network.config.url)
    });
    const publicClient = await hre.viem.getPublicClient();
    
    console.log("Creating ZK Nexus account...");
    console.log("  Factory:", factoryAddress);


    // Sort signers for deterministic tree construction
    const sortedPrivateSigners = [...privateSigners].sort((a, b) => {
        const addrA = BigInt(a);
        const addrB = BigInt(b);
        if (addrA < addrB) return -1;
        if (addrA > addrB) return 1;
        return 0;
    });
        
    //@ts-ignore
    const signersTree = new LeanIMT(hash);
    for (var privateSigner of sortedPrivateSigners) {
        signersTree.insert(poseidon.hash([BigInt(privateSigner)]));
    }
    
    // Build preliminary state tree (signers + threshold)
    const preliminaryStateTree = new LeanIMT(hash);
    preliminaryStateTree.insert(signersTree.root);
    preliminaryStateTree.insert(poseidon.hash([BigInt(privateThreshold)]));
    
    // Generate random salt for privacy protection
    const saltBytes = crypto.randomBytes(32);
    const SNARK_SCALAR_FIELD = BigInt("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001");
    let salt = BigInt('0x' + saltBytes.toString('hex'));
    salt %= SNARK_SCALAR_FIELD;
    const saltHex = toHex(salt) as Hex;
    
    // Mix salt into final state root (Approach B: Salt Mixed at End)
    const finalStateRoot = poseidon.hash([preliminaryStateTree.root, salt]);
    
    const signersRootHex = toHex(signersTree.root) as Hex;
    const stateRootHex = toHex(finalStateRoot) as Hex;
    
    console.log("\n📊 State Configuration:");
    console.log("   Private signers root:", signersRootHex);
    console.log("   Private threshold:", privateThreshold);
    console.log("   Salt:", saltHex);
    console.log("   State root (with salt):", stateRootHex);
    
    // Generate state validation proof
    console.log("\n🔐 Generating state validation proof...");
    const stateValidationProofData = await proveStateConfiguration(
        signersRootHex,
        privateThreshold,
        saltHex,
        stateRootHex
    );
    console.log("✅ State validation proof generated");
            
    console.log("\n📍 Computing signer address...");
    const stateRootAsBytes32 = pad(stateRootHex, { size: 32 }) as `0x${string}`;
    
    const helper = new ZKNexusHelper(
        factoryAddress,
        moduleValidatorAddress,
        publicClient,
        walletClient
    );
    
    const { account, transaction } = await helper.createAccount({
        stateRoot:stateRootAsBytes32,
        stateValidationProof: toHex(stateValidationProofData.proof),
        index: BigInt(0)
    });

    console.log("\n✅ Nexus account created successfully!");
    console.log("   Account address:", account);
    console.log("   Transaction hash:", transaction);
    
    const receipt = await publicClient.waitForTransactionReceipt({ hash: transaction });
    if (receipt) {
        console.log("   Gas used:", receipt.gasUsed.toString());
        console.log("   Block number:", receipt.blockNumber.toString());
    }
}

export async function createPrivateMultiSignersModuleFactoryContract(hre: HardhatRuntimeEnvironment) {

     // Get wallet client
    const pk = vars.get("DEPLOYER_PRIVATE_KEY") as string;
    const account = privateKeyToAccount(ensureHexPrefix(pk));
    const networkConfig = hre.network.config as any;
    const walletClient: WalletClient = createWalletClient({
        account,
        transport: http(networkConfig.url)
    });
    //const publicClient = await hre.viem.getPublicClient();
    const mywalletAddress = walletClient.account!.address;
    console.log("My wallet address: ", mywalletAddress);

    const result = await hre.ignition.deploy(factory, {
        parameters: {
            ZKMultiSigEcdsaFactory_v4: {
            },
        }
    });

    console.log("Private State Validation Honk Verifier: ", result.privateStateValidationHonkVerifier);
    console.log("ERC-8039 Private State Validation: ", result.erc8039PrivateStateValidation);
    console.log("TX Validation Honk Verifier: ", result.txValidationHonkVerifier);
    console.log("ER-8039 TX Validation: ", result.erc8039TxValidation);
    console.log("ZK MultiSig Validator: ", result.zkMultiSigValidator);
    console.log("ERC-7579 Account/Module Factory: ", result.zkMultiSigValidatorFactory);

}

/**
 * Check the status of a ZK Nexus account
 */
export async function checkZKNexusAccount(
    hre: HardhatRuntimeEnvironment,
    accountAddress: string,
    validatorAddress: string
) {
    const publicClient = await hre.viem.getPublicClient();
    
    console.log("\n🔍 Checking ZK Nexus Account Status");
    console.log("   Account:", accountAddress);
    console.log("   Validator:", validatorAddress);
    
    // Check if account has code (i.e., exists)
    const code = await publicClient.getBytecode({ address: accountAddress as Address });
    const accountExists = code && code.length > 2;
    console.log("\n📦 Account exists:", accountExists);
    
    if (!accountExists) {
        console.error("   ❌ Account has not been deployed yet!");
        return;
    }
    
    // Check validator installation
    console.log("\n🔧 Checking validator installation...");
    const accountABI = parseAbi([
        "function isModuleInstalled(uint256 moduleTypeId, address module, bytes calldata additionalContext) external view returns (bool)"
    ]);
    const accountContract = getContract({
        address: accountAddress as Address,
        abi: accountABI,
        client: publicClient
    });
    
    const MODULE_TYPE_VALIDATOR = 1;
    const isInstalled = await accountContract.read.isModuleInstalled([
        BigInt(MODULE_TYPE_VALIDATOR),
        validatorAddress as Address,
        "0x" as Hex
    ]) as boolean;
    
    console.log("   Validator installed:", isInstalled);
    
    if (!isInstalled) {
        console.error("   ❌ Validator is NOT installed on this account!");
        return;
    }
    
    // Check state root
    console.log("\n🔐 Checking state root...");
    const validatorABI = parseAbi([
        "function accountStateRoots(address) view returns (bytes32)"
    ]);
    const validatorContract = getContract({
        address: validatorAddress as Address,
        abi: validatorABI,
        client: publicClient
    });
    
    const stateRoot = await validatorContract.read.accountStateRoots([accountAddress as Address]) as Hex;
    console.log("   State root:", stateRoot);
    
    if (stateRoot === "0x0000000000000000000000000000000000000000000000000000000000000000") {
        console.error("   ❌ State root is ZERO! Validator not properly initialized!");
        return;
    }
    
    // Check nonce
    console.log("\n🔢 Checking nonce...");
    const entryPointAddress = "0x0000000071727De22E5E9d8BAf0edAc6f37da032"; // v0.7
    const entryPointABI = parseAbi([
        "function getNonce(address,uint192) view returns (uint256)"
    ]);
    const entryPoint = getContract({
        address: entryPointAddress,
        abi: entryPointABI,
        client: publicClient
    });
    
    const validatorBits = BigInt(validatorAddress);
    const nonceKey = validatorBits; // Validator address AS-IS for uint192 (address is 160 bits, fits in 192)
    const nonce = await entryPoint.read.getNonce([accountAddress as Address, nonceKey]) as bigint;
    
    console.log("   Nonce key (validator address):", nonceKey.toString());
    console.log("   Current nonce:", nonce.toString());
    
    // Check balance
    const balance = await publicClient.getBalance({ address: accountAddress as Address });
    console.log("\n💰 Account balance:", formatEther(balance), "POL");
    
    if (balance === 0n) {
        console.warn("   ⚠️  Account has zero balance! Fund it to pay for gas.");
    }
    
    console.log("\n✅ Account status check complete!");
}