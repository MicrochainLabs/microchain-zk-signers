import { zeroAddress, parseEther, toHex, Account, toBytes, recoverAddress, recoverPublicKey, Hex, createWalletClient, http, WalletClient, pad, bytesToHex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { formatEther } from 'viem';
import Safe, { EthSafeSignature } from '@safe-global/protocol-kit';
import { SafeTransactionData } from '@safe-global/types-kit';
import assert from 'assert';
import { HardhatRuntimeEnvironment } from "hardhat/types";
import { vars } from "hardhat/config";
import crypto from 'crypto';

import factory from "../ignition/modules/zkMultiSigEcdsaFactory";


import { poseidon } from "@iden3/js-crypto";
import { LeanIMT } from "@zk-kit/lean-imt";
// Native Noir packages (bypassing outdated hardhat-noir)
// Install with: pnpm add @noir-lang/noir_js @aztec/bb.js
import { Noir } from "@noir-lang/noir_js";
import { UltraHonkBackend } from "@aztec/bb.js";
import { readFileSync } from "fs";
import { join } from "path";

/// Extract x and y coordinates from a serialized ECDSA public key.
export function extractCoordinates(serializedPubKey: string): { x: number[], y: number[] } {
    // Ensure the key starts with '0x04' which is typical for an uncompressed key.
    if (!serializedPubKey.startsWith('0x04')) {
        throw new Error('The public key does not appear to be in uncompressed format.');
    }

    // The next 64 characters after the '0x04' are the x-coordinate.
    let xHex = serializedPubKey.slice(4, 68);

    // The following 64 characters are the y-coordinate.
    let yHex = serializedPubKey.slice(68, 132);

    // Convert the hex string to a byte array.
    let xBytes = Array.from(Buffer.from(xHex, 'hex'));
    let yBytes = Array.from(Buffer.from(yHex, 'hex'));
    return { x: xBytes, y: yBytes };
}

export function extractRSFromSignature(signatureHex: string): number[] {
    if (signatureHex.length !== 132 || !signatureHex.startsWith('0x')) {
        throw new Error('Signature should be a 132-character hex string starting with 0x.');
    }
    return Array.from(Buffer.from(signatureHex.slice(2, 130), 'hex'));
}

export function addressToArray(address: string): number[] {
    if (address.length !== 42 || !address.startsWith('0x')) {
        throw new Error('Address should be a 40-character hex string starting with 0x.');
    }
    return Array.from(toBytes(address));
}

export function padArray(arr: any[], length: number, fill: any = 0) {
    return arr.concat(Array(length - arr.length).fill(fill));
}

function ensureHexPrefix(value: string): `0x${string}` {
    return value.startsWith("0x") ? value as `0x${string}` : `0x${value}`;
}

// Hash function used to compute the tree nodes.
const hash = (a: bigint, b: bigint) => poseidon.hash([a, b])

export async function send(hre: any, safeAddr: string, to: string, value: string, data: string, proof: string) {
    // Get wallet client
    const pk = ensureHexPrefix(vars.get("DEPLOYER_PRIVATE_KEY") as string);
    const account = privateKeyToAccount(pk);
    const mywalletAddress = account.address;
    console.log("My wallet address: ", mywalletAddress);
    const publicClient = await hre.viem.getPublicClient();

    // Initialize Safe
    const safe = await Safe.init({
        provider: hre.network.config.url,
        signer: pk,
        safeAddress: safeAddr
    });

    const version = await safe.getContractVersion();
    const threshold = await safe.getThreshold();
    const owners = await safe.getOwners();
    const safeAddress = await safe.getAddress();
    console.log("connected to safe ", safeAddress);
    console.log("  version: ", version);
    console.log("  owners: ", owners);
    console.log("  threshold: ", threshold);
    console.log("  nonce: ", await safe.getNonce());
    console.log("  chainId: ", await safe.getChainId());
    console.log("  balance: ", formatEther(await safe.getBalance()));

   const safeTransactionData = {
        to: to,
        value: value,//parseEther(value).toString(),
        data: data
    }

    const safeTx = await safe.createTransaction({
    transactions: [safeTransactionData]
    })

    const safeTxHash = await safe.getTransactionHash(safeTx)
    console.log("Transaction hash: ", safeTxHash);

    const ethSafeSignature = new EthSafeSignature(owners[0], proof, true);
    safeTx.addSignature(ethSafeSignature);

    //console.log(await safe.getEncodedTransaction(safeTx)); // for simulation and debugging in Tenderly

    const executeTxResponse = await safe.executeTransaction(safeTx)
    const receipt = await executeTxResponse.transactionResponse?.wait()

    console.log("Transaction hash: ", executeTxResponse.hash);
    console.log("Transaction receipt: ", receipt);
    console.log("Transaction executed successfully")

}

export async function prove(hre: HardhatRuntimeEnvironment, safeAddr: string, txHash: string, signatures_: string, privateThreshold: number, privateSigners: string[], signersAddressesFormat: number, salt: string) {
    // Initialize Safe - we need it to prepare the witness (owners/threeshold) from onchain data.
    const safe = await Safe.init({
        provider: hre.network.config.url,
        safeAddress: safeAddr
    });

    const version = await safe.getContractVersion();
    const threshold = await safe.getThreshold();
    const owners = await safe.getOwners();
    const address = await safe.getAddress();
    console.log("connected to safe ", address);
    console.log("  version: ", version);
    console.log("  owners: ", owners);
    console.log("  threshold: ", threshold);
    console.log("  nonce: ", await safe.getNonce());
    console.log("  chainId: ", await safe.getChainId());
    console.log("  balance: ", formatEther(await safe.getBalance()));

    const signatures = signatures_.split(",").map(sig => sig.trim()).filter(sig => {
        if (!sig.startsWith("0x")) {
            throw new Error("Invalid signature format (must start with 0x)");
        }
        return true;
    });
    
    // Get the proxy contract (first owner should be the ZK MultiSig proxy, only for the current configuration reading)
    let proxyContract = null;
    try {
        proxyContract = await hre.viem.getContractAt("ZKMultiSigEcdsaSingleton", owners[0] as `0x${string}`);
    } catch (e) {
        console.log("Contract owner not found!", e);
        throw new Error(`Contract signer not found for Safe Ownership on ${address}`);
    }
    
    if (!proxyContract) {
        throw new Error(`Contract signer not found for Safe Ownership on ${address}`);
    }
    
    // Read configuration from the proxy (stateRoot, verifier)
    // When calling through the proxy, it will append the config to calldata
    const [onChainStateRoot, verifierAddress] = await proxyContract.read.getConfiguration();

    console.log("On-chain state root:", onChainStateRoot);
    console.log("Verifier address:", verifierAddress);
    console.log("Private threshold:", privateThreshold);
        
    const proofData = await proveTransactionSignatures(hre, signatures as Hex[], txHash as Hex, privateSigners, signersAddressesFormat, toHex(BigInt(privateThreshold)), salt as `0x${string}`, onChainStateRoot as Hex);
    console.log("Proof: ", toHex(proofData.proof));
    console.log("Public inputs:", proofData.publicInputs);
}

export async function proveTransactionSignatures(hre: HardhatRuntimeEnvironment, signatures: Hex[], txHash: Hex, privateSigners: string[], signersAddressesFormat: number, privateThreshold: Hex, salt: Hex, onChainStateRoot: Hex) {
        // Load compiled circuit directly from filesystem (bypassing hardhat-noir)
        const circuitPath = join(process.cwd(), "noir", "target", "zk_multi_sig_ecdsa.json");
        const compiledCircuit = JSON.parse(readFileSync(circuitPath, "utf-8"));
        
        // Initialize UltraHonk backend with bytecode and Noir for witness generation
        const backend = new UltraHonkBackend(compiledCircuit.bytecode, { threads: 8 });
        const noir = new Noir(compiledCircuit);
        console.log("UltraHonk backend initialized (bypassing hardhat-noir)");

        const MAX_DEPTH = 4; //to be passed as paramter
        const nil_pubkey = {
            x: Array.from(toBytes("0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")),
            y: Array.from(toBytes("0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"))
        };
        // Our Nil signature is a signature with r and s set to the generator point.
        const nil_signature = Array.from(
            toBytes("0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"));

        // Sort signatures by address - this is how the Safe contract does it.
        const sortedSignatures = await Promise.all(signatures.map(async (sig) => {
            const addr = await recoverAddress({hash: txHash, signature: sig});
            return { sig, addr };
        }));
        sortedSignatures.sort((a, b) => a.addr.localeCompare(b.addr));
        const sortedSigs = sortedSignatures.map(s => s.sig);

        // Sort signers for deterministic tree construction
        const sortedPrivateSigners = [...privateSigners].sort((a, b) => {
            const addrA = BigInt(a);
            const addrB = BigInt(b);
            if (addrA < addrB) return -1;
            if (addrA > addrB) return 1;
            return 0;
        });
        
        const signersTree = new LeanIMT(hash)
        for (var privateSigner of sortedPrivateSigners) {
            /*0: Normal address
            1: Poseidon Hash address*/
            if(signersAddressesFormat == 0)
                signersTree.insert(poseidon.hash([BigInt(privateSigner)]))
            else if (signersAddressesFormat == 1) 
                signersTree.insert(BigInt(privateSigner))
            else
                throw new Error("Invalid owner addresses format variable value (0: Normal address) or (1: Poseidon Hash address)");
        }
        
        // Compute preliminary state root (signers + threshold)
        const preliminaryStateTree = new LeanIMT(hash);
        preliminaryStateTree.insert(signersTree.root);
        preliminaryStateTree.insert(poseidon.hash([BigInt(privateThreshold)]));
        
        // Mix salt into final state root (same as deployment)
        const finalStateRoot = poseidon.hash([preliminaryStateTree.root, BigInt(salt)]);
        console.log("Computed state root (with salt):", toHex(finalStateRoot));

        if(onChainStateRoot != toHex(finalStateRoot)){
            throw new Error("Invalid state tree root");
        }

        const signersPathsProof: any[][] = [] //siblings
        const signersIndicesProof: any[][] = [] //indices
        const merkleProofLength : any[] = []
        for (var signature of sortedSigs) {
            const recoveredAddress = await recoverAddress({hash: txHash, signature: signature});
            const index= await signersTree.indexOf(poseidon.hash([BigInt(recoveredAddress)]));
            const addressProof= await signersTree.generateProof(index);

            await signersPathsProof.push(padArray(addressProof.siblings.map(v => toHex(v)), MAX_DEPTH, "0x0"))
            merkleProofLength.push(addressProof.siblings.length)

            const merkleProofIndices = []
            for (let i = 0; i < MAX_DEPTH; i += 1) {
                merkleProofIndices.push((addressProof.index >> i) & 1)
            }
             
            await signersIndicesProof.push(merkleProofIndices)
        }
        
        const defaultTxSigSiblingsOrIndices = Array(MAX_DEPTH).fill("0x0");
        const input = {
            signers: padArray(await Promise.all(sortedSigs.map(async (sig) => {
                const pubKey = await recoverPublicKey({
                    hash: txHash as `0x${string}`,
                    signature: sig
                });
                return extractCoordinates(pubKey);
            })), 5, nil_pubkey),
            threshold: privateThreshold,
            signers_root:  toHex(signersTree.root),
            merkle_proof_length: padArray(merkleProofLength, 5, 0),
            indices: padArray(signersIndicesProof, 5, defaultTxSigSiblingsOrIndices),
            siblings: padArray(signersPathsProof, 5, defaultTxSigSiblingsOrIndices),
            signatures: padArray(sortedSigs.map(sig => extractRSFromSignature(sig)), 5, nil_signature),
            txn_hash: Array.from(toBytes(txHash as `0x${string}`)),
            on_chain_state_root: toHex(finalStateRoot),
            salt: salt
        };

        // Generate witness using native Noir
        console.log("Generating witness...");
        const { witness } = await noir.execute(input);
        console.log("Witness generated successfully");

        // Generate proof using UltraHonk backend for EVM verification
        console.log("Generating proof...");
        const startTime = Date.now();
        const proofData = await backend.generateProof(witness, {
            keccak: true
        });
        const provingTime = Date.now() - startTime;
        console.log(`Proof generated successfully in ${provingTime}ms`);
        console.log(`Proof size: ${proofData.proof.length} bytes`);
        console.log(`Public inputs: ${proofData.publicInputs.length}`);

        // Verify proof
        console.log("Verifying proof...");
        const isValid = await backend.verifyProof(proofData, { 
            keccak: true
        });
        assert(isValid, "Verification failed");
        console.log("Proof verification succeeded");
        
        // Clean up backend resources
        await backend.destroy();
        
        return proofData;
}

/**
 * Generates a ZK proof that validates the initial state configuration for a new signer proxy.
 * This proves that signers_root + threshold correctly hash to the provided state_root.
 * 
 * @param signersRoot - The Merkle root of the signers tree
 * @param threshold - The minimum number of signatures required
 * @param stateRoot - The expected microchain ownership state root
 * @returns ProofData containing the proof and public inputs
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
    const backend = new UltraHonkBackend(compiledCircuit.bytecode, { threads: 8 });
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
            keccak: true, // Use keccak hash for EVM verification
        });
        const provingTime = Date.now() - startTime;
        console.log(`State validation proof generated in ${provingTime}ms`);
        console.log(`Proof size: ${proofData.proof.length} bytes`);
        console.log(`Public inputs: ${proofData.publicInputs.length}`);

        // Verify proof locally
        console.log("Verifying state validation proof...");
        const isValid = await backend.verifyProof(proofData, {
            keccak: true // Use keccak hash for EVM verification
        });
        assert(isValid, "State validation proof verification failed");
        console.log("State validation proof verified successfully");

        return proofData;
    } finally {
        await backend.destroy();
    }
}


export async function sign(hre: HardhatRuntimeEnvironment, safeAddr: string, to: string, value: string, data: string) {
    // Get wallet client
    const pk = vars.get("SAFE_OWNER_PRIVATE_KEY") as string;
    //const publicClient = await hre.viem.getPublicClient();
    const account = privateKeyToAccount(ensureHexPrefix(pk));
    const mywalletAddress = account.address;
    console.log("My wallet address: ", mywalletAddress);

    // Initialize Safe
    const safe = await Safe.init({
        provider: hre.network.config.url,
        signer: pk,
        safeAddress: safeAddr
    });

    const version = await safe.getContractVersion();
    const threshold = await safe.getThreshold();
    const owners = await safe.getOwners();
    const address = await safe.getAddress();
    console.log("connected to safe ", address);
    console.log("  version: ", version);
    console.log("  owners: ", owners);
    console.log("  threshold: ", threshold);
    console.log("  nonce: ", await safe.getNonce());
    console.log("  chainId: ", await safe.getChainId());
    console.log("  balance: ", formatEther(await safe.getBalance()));

    const safeTransactionData: SafeTransactionData = {
        to,
        value,
        data,
        operation: 0,
        // default fields below
        safeTxGas: "0x0",
        baseGas: "0x0",
        gasPrice: "0x0",
        gasToken: zeroAddress,
        refundReceiver: zeroAddress,
        nonce: await safe.getNonce(),
    };

    console.log("transaction", safeTransactionData);
    const transaction = await safe.createTransaction({ transactions: [safeTransactionData] });
    const txHash = await safe.getTransactionHash(transaction);
    console.log("txHash", txHash);

    const safeSig = await safe.signTypedData(transaction);
    console.log("Signature: ", safeSig.data);
}


export async function createSafeWithinMicorchainProtocol(hre: HardhatRuntimeEnvironment, owners: string[], threshold: number) {
    // Get wallet client
    const pk = vars.get("DEPLOYER_PRIVATE_KEY") as string;
    const account = privateKeyToAccount(ensureHexPrefix(pk));
    const walletClient: WalletClient = createWalletClient({
        account,
        transport: http(hre.network.config.url)
    });
    const publicClient = await hre.viem.getPublicClient();
    const mywalletAddress = walletClient.account!.address;
    console.log("My wallet address: ", mywalletAddress);


    const safe = await Safe.init({
        provider: walletClient.transport,
        predictedSafe: {
            safeAccountConfig: {
                owners,
                threshold: threshold,
            }
        },
    });

    const safeAddress = await safe.getAddress() as `0x${string}`;
    const deploymentTransaction = await safe.createSafeDeploymentTransaction();

    const transactionHash = await walletClient.sendTransaction({
        account: walletClient.account as Account,
        chain: walletClient.chain,
        to: deploymentTransaction.to,
        value: parseEther(deploymentTransaction.value),
        data: deploymentTransaction.data as `0x${string}`,
    });

    const transactionReceipt = await publicClient.waitForTransactionReceipt({
        hash: transactionHash
    });

    if (transactionReceipt.status != "success") {
        throw new Error("Safe failed to deploy.")
    }

    console.log("Created zkSafe at address: ", safeAddress);
}

export async function createPrivateMultiSignersProxyContract(
    hre: HardhatRuntimeEnvironment,
    privateSigners: string[],
    privateThreshold: number,
    txValidationVerifierAddress: string,
    factoryAddress: string
) {
     // Get wallet client
    const pk = vars.get("DEPLOYER_PRIVATE_KEY") as string;
    const account = privateKeyToAccount(ensureHexPrefix(pk));
    const walletClient: WalletClient = createWalletClient({
        account,
        transport: http(hre.network.config.url)
    });
    //const publicClient = await hre.viem.getPublicClient();
    const mywalletAddress = walletClient.account!.address;
    console.log("My wallet address: ", mywalletAddress);

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

    // Get the factory contract
    const factoryContract = await hre.viem.getContractAt("ZKMultiSigEcdsaFactory", factoryAddress as `0x${string}`);
    
    // Get the predicted signer address (deterministic via CREATE2)
    console.log("\n📍 Computing signer address...");
    const stateRootAsBytes32 = pad(stateRootHex, { size: 32 }) as `0x${string}`;
    const predictedSignerAddress = await factoryContract.read.getSigner([
        stateRootAsBytes32,
        txValidationVerifierAddress as `0x${string}`
    ]);
    console.log("   Predicted signer address:", predictedSignerAddress);

    // Create the signer proxy with state validation
    console.log("\n🚀 Creating signer proxy with state validation...");
    const txHash = await factoryContract.write.createSigner([
        stateRootAsBytes32,
        txValidationVerifierAddress as `0x${string}`,
        toHex(stateValidationProofData.proof)
    ], {
        account: walletClient.account!,
    });
    
    console.log("   Transaction hash:", txHash);
    
    // Wait for transaction confirmation
    const publicClient = await hre.viem.getPublicClient();
    const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash });
    
    console.log("\n✅ Signer proxy created successfully!");
    console.log("   Signer address: ", predictedSignerAddress);
    console.log("   State root:", stateRootHex);
    console.log("   Salt: ", salt);
    console.log("   SaltHex: ", saltHex);
    console.log("   Gas used:", receipt.gasUsed.toString());
    console.log("   Block number:", receipt.blockNumber.toString());
    console.log("\n💡 Important: Save the salt value above! It's needed for signature verification.");

    /*return {
        signerAddress: predictedSignerAddress,
        stateRoot: stateRootHex,
        salt: saltHex,
        verifier: verifier,
        transactionHash: txHash,
        receipt: receipt
    };*/

}

export async function createPrivateMultiSignersFactoryContract(hre: HardhatRuntimeEnvironment) {

     // Get wallet client
    const pk = vars.get("DEPLOYER_PRIVATE_KEY") as string;
    const account = privateKeyToAccount(ensureHexPrefix(pk));
    const walletClient: WalletClient = createWalletClient({
        account,
        transport: http(hre.network.config.url)
    });
    //const publicClient = await hre.viem.getPublicClient();
    const mywalletAddress = walletClient.account!.address;
    console.log("My wallet address: ", mywalletAddress);

    const result = await hre.ignition.deploy(factory, {
        parameters: {
            ZKMultiSigEcdsaFactory_v1: {
            },
        }
    });

    console.log("Private State Validation Honk Verifier: ", result.privateStateValidationHonkVerifier);
    console.log("ERC-8039 Private State Validation: ", result.erc8039PrivateStateValidation);
    console.log("TX Validation Honk Verifier: ", result.txValidationHonkVerifier);
    console.log("ER-8039 TX Validation: ", result.erc8039TxValidation);
    console.log("ERC-1271 Contract Signature Factory: ", result.contractSignaturefactory);

}
