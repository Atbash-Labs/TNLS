import axios from "axios";
import { Wallet, SecretNetworkClient, fromUtf8 } from "secretjs";
import fs from "fs";
import assert from "assert";
import { PreExecutionMsg, PostExecutionMsg, Payload, Contract, Sender, Binary } from "./GatewayContract";
import { ecdh, ecdsaSign, privateKeyVerify } from "secp256k1";
import { Wallet as EthWallet } from "ethers";
import { arrayify, SigningKey } from "ethers/lib/utils";
import { createHash } from 'crypto';
import { encrypt_payload } from './encrypt-payload/pkg'
// import { uuid } from 'uuid';


// Returns a client with which we can interact with secret network
const initializeClient = async (endpoint: string, chainId: string) => {
  const wallet = new Wallet(); // Use default constructor of wallet to generate random mnemonic.
  const accAddress = wallet.address;
  const client = await SecretNetworkClient.create({
    // Create a client to interact with the network
    grpcWebUrl: endpoint,
    chainId: chainId,
    wallet: wallet,
    walletAddress: accAddress,
  });

  console.log(`\nInitialized client with wallet address: ${accAddress}`);
  return client;
};

// Stores and instantiaties a new contract in our network
const initializeContract = async (
  client: SecretNetworkClient,
  contractPath: string
) => {
  const wasmCode = fs.readFileSync(contractPath);
  console.log("Uploading contract");

  const uploadReceipt = await client.tx.compute.storeCode(
    {
      wasmByteCode: wasmCode,
      sender: client.address,
      source: "",
      builder: "",
    },
    {
      gasLimit: 5000000,
    }
  );

  if (uploadReceipt.code !== 0) {
    console.log(
      `Failed to get code id: ${JSON.stringify(uploadReceipt.rawLog)}`
    );
    throw new Error(`Failed to upload contract`);
  }

  const codeIdKv = uploadReceipt.jsonLog![0].events[0].attributes.find(
    (a: any) => {
      return a.key === "code_id";
    }
  );

  console.log(`Upload used \x1b[33m${uploadReceipt.gasUsed}\x1b[0m gas\n`);

  const codeId = Number(codeIdKv!.value);
  console.log("Contract codeId: ", codeId);

  const contractCodeHash = await client.query.compute.codeHash(codeId);
  console.log(`Contract hash: ${contractCodeHash}`);

  const contract = await client.tx.compute.instantiateContract(
    {
      sender: client.address,
      codeId,
      initMsg: { entropy: "secret"},
      codeHash: contractCodeHash,
      label: "My contract" + Math.ceil(Math.random() * 10000), // The label should be unique for every contract, add random string in order to maintain uniqueness
    },
    {
      gasLimit: 5000000,
    }
  );

  if (contract.code !== 0) {
    throw new Error(
      `Failed to instantiate the contract with the following error ${contract.rawLog}`
    );
  }

  const contractAddress = contract.arrayLog!.find(
    (log) => log.type === "message" && log.key === "contract_address"
  )!.value;

  const encryption_pubkey = contract.arrayLog!.find(
    (log) => log.type === "wasm" && log.key === "encryption_pubkey"
  )!.value;

  const signing_pubkey = contract.arrayLog!.find(
    (log) => log.type === "wasm" && log.key === "signing_pubkey"
  )!.value;

  console.log(`Contract address: ${contractAddress}\n`);

  console.log(`\x1b[32mEncryption key: ${encryption_pubkey}\x1b[0m`);
  console.log(`\x1b[32mVerification key: ${signing_pubkey}\x1b[0m\n`);

  console.log(`Init used \x1b[33m${contract.gasUsed}\x1b[0m gas`);

  var contractInfo: [string, string, string] = [contractCodeHash, contractAddress, encryption_pubkey];
  return contractInfo;
};

const getFromFaucet = async (address: string) => {
  await axios.get(`http://localhost:5000/faucet?address=${address}`);
};

async function getScrtBalance(userCli: SecretNetworkClient): Promise<string> {
  let balanceResponse = await userCli.query.bank.balance({
    address: userCli.address,
    denom: "uscrt",
  });
  return balanceResponse.balance!.amount;
}

async function fillUpFromFaucet(
  client: SecretNetworkClient,
  targetBalance: Number
) {
  let balance = await getScrtBalance(client);
  while (Number(balance) < targetBalance) {
    try {
      await getFromFaucet(client.address);
    } catch (e) {
      console.error(`\x1b[2mfailed to get tokens from faucet: ${e}\x1b[0m`);
    }
    balance = await getScrtBalance(client);
  }
  console.error(`got tokens from faucet: ${balance}`);
}

// Initialization procedure
async function initializeAndUploadContract() {
  let endpoint = "http://localhost:9091";
  let chainId = "secretdev-1";

  const client = await initializeClient(endpoint, chainId);

  await fillUpFromFaucet(client, 100_000_000);

  const [contractHash, contractAddress, gatewayPublicKey] = await initializeContract(
    client,
    "contract.wasm"
  );

  var clientInfo: [SecretNetworkClient, string, string, string] = [
    client,
    contractHash,
    contractAddress,
    gatewayPublicKey
  ];
  return clientInfo;
}

async function inputTx(
  client: SecretNetworkClient,
  contractHash: string,
  contractAddress: string,
  gatewayPublicKey: string, // base64
) {
  const wallet = EthWallet.createRandom(); 
  const user_public_address: string = wallet.address;
  const user_public_key: string = new SigningKey(wallet.privateKey).compressedPublicKey;
  console.log('\x1b[34m%s\x1b[0m', `\nEthereum Address: ${wallet.address}\nPublic Key: ${user_public_key}\nPrivate Key: ${wallet.privateKey}\n`);

  const userPrivateKeyBytes = arrayify(wallet.privateKey)
  const gatewayPublicKeyBuffer = Buffer.from(gatewayPublicKey, 'base64')
  const gatewayPublicKeyBytes = arrayify(gatewayPublicKeyBuffer)
  const sharedKey = ecdh(gatewayPublicKeyBytes, userPrivateKeyBytes)

  const userPublicKeyBytes = arrayify(user_public_key)

  const routing_info: Contract = {
    address: "secret19zpyd046u4swqpksr3n44cej4j8pg6ahw95y85",
    hash: "2a2fbe493ef25b536bbe0baa3917b51e5ba092e14bd76abf50a59526e2789be3"
  };
  const sender: Sender = {
    address: user_public_address,
    public_key: Buffer.from(userPublicKeyBytes).toString('base64'),
  };
  const inputs = JSON.stringify({"input1": "some string", "input2": 1, "input3": true});
  const payload: Payload = {
    data: inputs,
    routing_info: routing_info,
    sender: sender,
  };
  console.log("Unencrypted Payload:");
  console.log(payload);

  const plaintext = Buffer
    .from(JSON.stringify(payload));
  const ciphertext = Buffer
    .from(encrypt_payload(gatewayPublicKeyBytes, userPrivateKeyBytes, plaintext))
    .toString('base64');

  const payload_hash = createHash('sha256').update(plaintext).digest();
  const payload_hash_64 = payload_hash.toString('base64');
  console.log(`Payload Hash is ${payload_hash.byteLength} bytes`);

  const payload_signature = ecdsaSign(payload_hash,arrayify(wallet.privateKey)).signature;
  const payload_signature_64 = Buffer.from(payload_signature).toString('base64');
  console.log(`payload Signature is ${payload_signature.byteLength} bytes`);

  const handle_msg: PreExecutionMsg = {
    handle: "test",
    payload: ciphertext,
    payload_hash: payload_hash_64,
    payload_signature: payload_signature_64,
    routing_info: routing_info,
    sender: sender,
    task_id: 1,
  };
  console.log("handle_msg:");
  console.log(handle_msg);

  const tx = await client.tx.compute.executeContract(
    {
      sender: client.address,
      contractAddress: contractAddress,
      codeHash: contractHash,
      msg: {
        input: { inputs: handle_msg },
      },
      sentFunds: [],
    },
    {
      gasLimit: 200000,
    }
  );

  console.log(`inputTx used \x1b[33m${tx.gasUsed}\x1b[0m gas`);

  if (tx.code !== 0) {
    throw new Error(
      `Failed with the following error:\n ${tx.rawLog}`
    );
  };
  assert(tx.code === 0, `\x1b[31;1m[FAIL]\x1b[0m`)

  const status = tx.arrayLog!.find(
    (log) => log.type === "wasm" && log.key === "status"
  )!.value;
  assert(status == "sent to secret contract");
}

async function queryPubKey(
  client: SecretNetworkClient,
  contractHash: string,
  contractAddress: string,
): Promise<string> {
  type PublicKeyResponse = { key: Binary };

  const response = (await client.query.compute.queryContract({
    contractAddress: contractAddress,
    codeHash: contractHash,
    query: { get_public_key: {} },
  })) as PublicKeyResponse;

  console.log(`Gateway Public Key: ${response.key}`)
  return response.key
}

async function test_input_tx(
  client: SecretNetworkClient,
  contractHash: string,
  contractAddress: string,
) {
  console.log(`Sending query: {"get_public_key": {} }`)
  const gatewayPublicKey = await queryPubKey(client, contractHash, contractAddress);
  inputTx(client, contractHash, contractAddress, gatewayPublicKey)
}

async function runTestFunction(
  tester: (
    client: SecretNetworkClient,
    contractHash: string,
    contractAddress: string
  ) => void,
  client: SecretNetworkClient,
  contractHash: string,
  contractAddress: string
) {
  console.log(`\n\x1b[1m[TESTING] ${tester.name}\x1b[0m\n`);
  await tester(client, contractHash, contractAddress);
  console.log(`\x1b[92;1m[SUCCESS] ${tester.name}\x1b[0m\n`);
}

(async () => {
  const [client, contractHash, contractAddress, gatewayPublicKey] =
    await initializeAndUploadContract();
    await runTestFunction(test_input_tx, client, contractHash, contractAddress);
})();
