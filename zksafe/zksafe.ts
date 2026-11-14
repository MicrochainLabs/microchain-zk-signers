import { zeroAddress, parseEther, toHex, Account, Hex, createWalletClient, http, WalletClient } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { formatEther } from 'viem';
import Safe, { EthSafeSignature } from '@safe-global/protocol-kit';
import { SafeTransactionData, SafeVersion } from '@safe-global/types-kit';
import { HardhatRuntimeEnvironment } from "hardhat/types";
import { vars } from "hardhat/config";
import { fieldToBytes32, parseSalt, type ProveOptions } from "zk-smart-account-kit-sdk/zk-multisig";

import factory from "../ignition/modules/zkMultiSigEcdsaFactory";
import { deriveState, printSaltBackupNotice, proveStateValidation, proveTransaction, signersFormatFromFlag } from "../zkcommon/zkMultiSig";

const SAFE_VERSION: SafeVersion = "1.5.0";

function ensureHexPrefix(value: string): `0x${string}` {
    return value.startsWith("0x") ? value as `0x${string}` : `0x${value}`;
}

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
    const receipt = await publicClient.waitForTransactionReceipt({ hash: executeTxResponse.hash as Hex })

    console.log("Transaction hash: ", executeTxResponse.hash);
    console.log("Transaction receipt: ", receipt);
    console.log("Transaction executed successfully")

}

export async function prove(hre: HardhatRuntimeEnvironment, safeAddr: string, txHash: string, signatures_: string, privateThreshold: number | string, privateSigners: string[], signersAddressesFormat: number | string, privateSalt: string) {
    const salt = parseSalt(privateSalt);
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
        
    const proofData = await proveTransactionSignatures(hre, signatures as Hex[], txHash as Hex, privateSigners, signersAddressesFormat, toHex(BigInt(privateThreshold)), salt, onChainStateRoot as Hex);
    console.log("Proof: ", proofData.proof);
    console.log("Public inputs:", proofData.publicInputs);
}

export async function proveTransactionSignatures(hre: HardhatRuntimeEnvironment, signatures: Hex[], txHash: Hex, privateSigners: string[], signersAddressesFormat: number | string, privateThreshold: Hex, salt: bigint, onChainStateRoot: Hex, options?: ProveOptions) {
    const config = {
        signers: privateSigners,
        threshold: Number(BigInt(privateThreshold)),
        salt,
        signersFormat: signersFormatFromFlag(signersAddressesFormat),
    };
    return proveTransaction(config, txHash, signatures, onChainStateRoot, options);
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
            },
            safeDeploymentConfig: {
                safeVersion: SAFE_VERSION,
            }
        },
    });

    const safeAddress = await safe.getAddress() as `0x${string}`;
    const deploymentTransaction = await safe.createSafeDeploymentTransaction();

    const transactionHash = await walletClient.sendTransaction({
        account: walletClient.account as Account,
        chain: walletClient.chain,
        to: deploymentTransaction.to as `0x${string}`,
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
    privateThreshold: number | string,
    txValidationVerifierAddress: string,
    factoryAddress: string,
    privateSalt?: string
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

    const factoryContract = await hre.viem.getContractAt("ZKMultiSigEcdsaFactory", factoryAddress as `0x${string}`);

    const { state, saltHex, saltProvided } = deriveState(privateSigners, privateThreshold, privateSalt);

    const signersRootHex = toHex(state.signersRoot) as Hex;
    const stateRootHex = toHex(state.stateRoot) as Hex;

    console.log("\n📊 State Configuration:");
    console.log("   Private signers root:", signersRootHex);
    console.log("   Private threshold:", privateThreshold);
    console.log("   State root:", stateRootHex);

    // Generate state validation proof
    console.log("\n🔐 Generating state validation proof...");
    const stateValidationProofData = await proveStateValidation(state);
    console.log("✅ State validation proof generated");

    // Get the predicted signer address (deterministic via CREATE2)
    console.log("\n📍 Computing signer address...");
    const stateRootAsBytes32 = fieldToBytes32(state.stateRoot);
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
        stateValidationProofData.proof
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
    console.log("   Gas used:", receipt.gasUsed.toString());
    console.log("   Block number:", receipt.blockNumber.toString());
    printSaltBackupNotice(saltHex, saltProvided);

    return {
        signerAddress: predictedSignerAddress,
        stateRoot: stateRootHex,
        salt: saltHex,
        verifier: txValidationVerifierAddress,
        transactionHash: txHash,
        receipt: receipt
    };

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
