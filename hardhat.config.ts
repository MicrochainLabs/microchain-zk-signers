import { HardhatUserConfig } from "hardhat/types";
//import { task, vars } from "hardhat/config";
import "hardhat-deploy";
import "@nomicfoundation/hardhat-toolbox-viem";
import "@nomicfoundation/hardhat-ignition";
import "@nomicfoundation/hardhat-ignition-viem";
import "@nomicfoundation/hardhat-foundry";

import { DeterministicDeploymentInfo } from "hardhat-deploy/dist/types";
import { getSingletonFactoryInfo } from "@safe-global/safe-singleton-factory";

import { createSafeWithinMicorchainProtocol, sign, prove, send, createPrivateMultiSignersFactoryContract, createPrivateMultiSignersProxyContract } from "./zksafe/zksafe";
import { computeZKNexusAddress, getZKNexusConfig, checkZKNexusInitialized, createPrivateMultiSignersModuleFactoryContract, createZKNexusAccount, sendZKNexusUserOp, getAccountEntryPoint, signUserOp } from "./zknexus/zknexus";

const deterministicDeployment = (network: string): DeterministicDeploymentInfo => {
    const info = getSingletonFactoryInfo(parseInt(network));
    if (!info) {
        throw new Error(`
        Safe factory not found for network ${network}. You can request a new deployment at https://github.com/safe-global/safe-singleton-factory.
        For more information, see https://github.com/safe-global/safe-contracts#replay-protection-eip-155
      `);
    }
    return {
        factory: info.address,
        deployer: info.signerAddress,
        funding: (BigInt(info.gasLimit) * BigInt(info.gasPrice)).toString(),
        signedTx: info.transaction,
    };
};

//ZK Safe tasks
task("send", "Send a zksafe transaction with a proof")
    .addParam("safe", "Address of the Safe")
    .addParam("to", "Address of the recipient")
    .addParam("value", "Value to send")
    .addParam("data", "Calldata to send")
    .addParam("proof", "The proof")
    .setAction(async (taskArgs, hre) => send(hre, taskArgs.safe, taskArgs.to, taskArgs.value, taskArgs.data, taskArgs.proof));


task("prove", "Prove a zksafe transaction") 
    .addParam("safe", "Address of the Safe")
    .addParam("txhash", "Transaction hash")
    .addParam("signatures", "Signatures (comma separated)")
    .addParam("privatesigners", "Comma separated list of private signers")
    .addParam("privatethreshold", "Private threshold")
    .addParam("signersaddressesformat", "Owner address format: normal or hash")
    .addParam("salt", "Salt")
    .setAction(async (taskArgs, hre) => prove(hre, taskArgs.safe, taskArgs.txhash, taskArgs.signatures, taskArgs.privatethreshold, taskArgs.privatesigners.split(","), taskArgs.signersaddressesformat, taskArgs.salt));
    
task("sign", "Sign Safe transaction")
    .addParam("safe", "Address of the Safe")
    .addParam("to", "Address of the recipient")
    .addParam("value", "Value to Send")
    .addParam("data", "Calldata to send")
    .setAction(async (taskArgs, hre) => sign(hre, taskArgs.safe, taskArgs.to, taskArgs.value, taskArgs.data));

task("createSafeWithinMicorchainProtocol", "Create a ZkSafe")
    .addParam("owners", "Comma separated list of owners")
    .addParam("threshold", "Threshold")
    .setAction(async (taskArgs, hre) => createSafeWithinMicorchainProtocol(hre, taskArgs.owners.split(","), taskArgs.threshold));

task("createPrivateMultiSignersProxyContract", "Create a private multi signers contract")
    .addParam("privatesigners", "Comma separated list of private signers")
    .addParam("privatethreshold", "Private threshold")
    .addParam("txvalidationverifieraddress", " TX Validation Verifier address")
    .addParam("factoryaddress", "Factory contract signature address")
    .setAction(async (taskArgs, hre) => createPrivateMultiSignersProxyContract(hre, taskArgs.privatesigners.split(","), taskArgs.privatethreshold, taskArgs.txvalidationverifieraddress, taskArgs.factoryaddress));

task("createFactory", "Create Factor")
    .setAction(async (taskArgs, hre) => createPrivateMultiSignersFactoryContract(hre));





// ZK Nexus tasks
task("sendZKNexusUserOp", "Send a UserOperation using ZK Nexus account with pre-collected signatures")
    .addParam("account", "The Nexus account address")
    .addParam("validator", "Validator contract address")
    .addOptionalParam("entrypoint", "EntryPoint contract address (auto-detected if not provided)", "")
    .addParam("to", "Target address")
    .addParam("value", "Value in wei")
    .addParam("data", "Call data (hex)")
    .addParam("signatures", "Comma separated list of signatures from signUserOp")
    .addParam("userophash", "UserOp hash from signUserOp")
    .addParam("privatesigners", "Comma separated list of private signer addresses")
    .addParam("privatethreshold", "Private threshold")
    .addParam("salt", "Salt used during account creation")
    .setAction(async (taskArgs, hre) => sendZKNexusUserOp(
        hre,
        taskArgs.account,
        taskArgs.validator,
        taskArgs.entrypoint,
        taskArgs.to,
        taskArgs.value,
        taskArgs.data,
        taskArgs.signatures.split(",") as `0x${string}`[],
        taskArgs.userophash as `0x${string}`,
        taskArgs.privatesigners.split(","),
        parseInt(taskArgs.privatethreshold),
        taskArgs.salt as `0x${string}`
    ));

task("signUserOp", "Sign a UserOperation for a Nexus account (like zksafe sign)")
    .addParam("account", "The Nexus account address")
    .addParam("validator", "Validator contract address")
    .addParam("to", "Target address")
    .addParam("value", "Value in wei")
    .addParam("data", "Call data (hex)")
    .setAction(async (taskArgs, hre) => signUserOp(
        hre,
        taskArgs.account,
        taskArgs.validator,
        taskArgs.to,
        taskArgs.value,
        taskArgs.data
    ));

task("createZKNexusAccount", "Create a new ZK MultiSig Nexus account")
    .addParam("privatesigners", "Comma separated list of private signers")
    .addParam("privatethreshold", "Private threshold")
    .addParam("modulevalidatoraddress", "Validator contract address")
    .addParam("factoryaddress", "Factory contract address")
    .setAction(async (taskArgs, hre) => createZKNexusAccount(
        hre,
        taskArgs.privatesigners.split(","),
        taskArgs.privatethreshold,
        taskArgs.modulevalidatoraddress,
        taskArgs.factoryaddress
    ));

task("createModuleFactory", "Create Factor")
    .setAction(async (taskArgs, hre) => createPrivateMultiSignersModuleFactoryContract(hre));


//Utility tasks
task("getAccountEntryPoint", "Get the EntryPoint address used by a Nexus account")
    .addParam("account", "The Nexus account address")
    .setAction(async (taskArgs, hre) => getAccountEntryPoint(hre, taskArgs.account));

task("computeZKNexusAddress", "Compute deterministic address for a ZK Nexus account")
    .addParam("factory", "Factory contract address")
    .addParam("validator", "Validator contract address")
    .addParam("stateroot", "State root commitment")
    .addParam("proof", "State validation ZK proof (hex string)")
    .addOptionalParam("index", "Account index", "0")
    .setAction(async (taskArgs, hre) => computeZKNexusAddress(
        hre,
        taskArgs.factory,
        taskArgs.validator,
        taskArgs.stateroot,
        taskArgs.proof,
        taskArgs.index
    ));

task("getZKNexusConfig", "Get ZK MultiSig configuration for a Nexus account")
    .addParam("validator", "Validator contract address")
    .addParam("account", "Nexus account address")
    .setAction(async (taskArgs, hre) => getZKNexusConfig(
        hre,
        taskArgs.validator,
        taskArgs.account
    ));

task("checkZKNexusInitialized", "Check if ZK validator is initialized for account")
    .addParam("validator", "Validator contract address")
    .addParam("account", "Nexus account address")
    .setAction(async (taskArgs, hre) => checkZKNexusInitialized(
        hre,
        taskArgs.validator,
        taskArgs.account
    ));

const getAccounts = function(): string[] {
    let accounts = [];
    accounts.push(vars.get("DEPLOYER_PRIVATE_KEY"));
    accounts.push(vars.get("SAFE_OWNER_PRIVATE_KEY"));
    return accounts;
}

const config: HardhatUserConfig = {
    paths: {
        sources: "./contracts",
        cache: "./cache",
        artifacts: "./artifacts"
    },
    solidity: {
        compilers: [
            {
                version: "0.8.29",
                settings: {
                    //viaIR: true,
                    optimizer: {
                        enabled: true,
                        runs: 20
                    },
                    evmVersion: "cancun"
                }
            },
            {
                version: "0.8.27",
                settings: {
                    optimizer: {
                        enabled: true,
                        runs: 200
                    },
                    evmVersion: "cancun"
                }
            },
            {
                version: "0.8.20",
                settings: {
                    optimizer: {
                        enabled: true,
                        runs: 200
                    },
                    evmVersion: "paris"
                }
            }
        ]
    },
    namedAccounts: {
        deployer: {
            default: 0,
        },
        users: {
            default: 1,
        },
    },
    networks: {
        mainnet: {
            url: "http://192.168.1.4:8545",
            accounts: getAccounts(),
        },
        localhost: {
            url: "http://127.0.0.1:8545",
        },
        gnosis: {
            url: "https://gnosis.drpc.org",
            accounts: getAccounts(),
        },
        bsc: {
            url: "https://bsc-dataseed.binance.org/",
            accounts: getAccounts(),
        },
        polygon: {
            url: "",  
            accounts: getAccounts(),
        },
        polygonAmoy: {
            url: "https://rpc-amoy.polygon.technology",
            accounts: getAccounts(),
            chainId: 80002,
        },
        sepolia: {
            url: "https://ethereum-sepolia-rpc.publicnode.com",
            accounts: getAccounts(),
        },
        telos: {
             url: "https://mainnet-asia.telos.net/evm",
             accounts: getAccounts(),
        },
        arbitrum: {
            url: "https://1rpc.io/arb",
            accounts: getAccounts(),
        },
        optimism: {
            url: "https://1rpc.io/op",
            accounts: getAccounts(),
        },
        buildbear: {
            url:  "https://rpc.buildbear.io/1kx",
            accounts: getAccounts(),
        },
        base: {
            url: "https://base.rpc.subquery.network/public",
            accounts: getAccounts(),
            initialBaseFeePerGas: 5000000000, // 5 gwei
            gasPrice: 25000000000, // 25 gwei (base fee + priority fee)
        },
        scroll: {
            url: "https://scroll.drpc.org",
            accounts: getAccounts(),
        }
    },
    etherscan: {
        customChains: [
         {
            network: "gnosis",
            chainId: 100,
            urls: {
              // 3) Select to what explorer verify the contracts
              // Gnosisscan
              apiURL: "https://api.gnosisscan.io/api",
              browserURL: "https://gnosisscan.io/",
            },
          },
          {
            network: "bsc",
            chainId: 56,
            urls: {
              apiURL: "https://api.bscscan.com/api",
              browserURL: "https://bscscan.com/",
            },
          },
          {
            network: "polygon",
            chainId: 137,
            urls: {
              apiURL: "https://api.polygonscan.com/api",
              browserURL: "https://polygonscan.com/",
            },
          },
          {
            network: "scroll",
            chainId: 534352,
            urls: {
              apiURL: "https://api.scrollscan.com/api",
              browserURL: "https://scrollscan.com/",
            },
          }
        ],
        apiKey: {
            gnosis: vars.get("GNOSISSCAN_API_KEY", ""),
            sepolia: vars.get("ETHERSCAN_API_KEY", ""),
            mainnet: vars.get("ETHERSCAN_API_KEY", ""),
            bsc: vars.get("BSCSCAN_API_KEY", ""),
            polygon: vars.get("POLYGONSCAN_API_KEY", ""),
            arbitrumOne: vars.get("ARBISCAN_API_KEY", ""),
            optimisticEthereum: vars.get("OPTIMISTIC_API_KEY", ""),
            scroll: vars.get("SCROLLSCAN_API_KEY", ""),
            base: vars.get("BASESCAN_API_KEY", ""),
        },
    },
    ignition: {
        strategyConfig: {
            create2: {
                // salt: "0x0Ccb2b6675A60EC6a5c20Fb0631Be8EAF3Ba2dCD" + "00" + "69eb570cb274b0ebea0271",
                salt: "0x00000000000000000000000000000000000000000069eb570cb274b0ebea0275",
            }
        }
    },
    mocha: {
        timeout: 100000000
    },
    deterministicDeployment,
};

export default config;
