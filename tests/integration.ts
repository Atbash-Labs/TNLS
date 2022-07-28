import axios from "axios";
import { Wallet, SecretNetworkClient, fromUtf8 } from "secretjs";
import fs from "fs";
import assert from "assert";
import { PreExecutionMsg, PostExecutionMsg, Payload, Contract, Sender, Binary, BroadcastMsg } from "./GatewayContract";
import { ecdsaSign } from "secp256k1";
import { Wallet as EthWallet } from "ethers";
import { arrayify, SigningKey } from "ethers/lib/utils";
import { createHash, randomBytes } from 'crypto';
import { encrypt_payload } from './encrypt-payload/pkg'
import 'dotenv/config'

var mnemonic: string;
var endpoint: string = "http://localhost:9091";
var chainId: string = "secretdev-1";

// uncomment if using .env file
// mnemonic = process.env.MNEMONIC!;
// endpoint = process.env.GRPC_WEB_URL!;
// chainId = process.env.CHAIN_ID!;

// Returns a client with which we can interact with secret network
const initializeClient = async (endpoint: string, chainId: string) => {
  let wallet: Wallet;
  if (mnemonic) {
    wallet = new Wallet(mnemonic);
  } else {
    wallet = new Wallet();
  }
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

  var contractInfo: [string, string] = [contractCodeHash, contractAddress];
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

  const client = await initializeClient(endpoint, chainId);

  if (chainId == "secretdev-1") {await fillUpFromFaucet(client, 100_000_000)};

  const [contractHash, contractAddress] = await initializeContract(
    client,
    "contract.wasm.gz"
  );

  var clientInfo: [SecretNetworkClient, string, string] = [
    client,
    contractHash,
    contractAddress
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
  const userPublicAddress: string = wallet.address;
  const userPublicKey: string = new SigningKey(wallet.privateKey).compressedPublicKey;
  console.log(`\n\x1b[34mEthereum Address: ${wallet.address}\n\x1b[34mPublic Key: ${userPublicKey}\n\x1b[34mPrivate Key: ${wallet.privateKey}\x1b[0m\n`);

  const userPrivateKeyBytes = arrayify(wallet.privateKey)
  const userPublicKeyBytes = arrayify(userPublicKey)
  const gatewayPublicKeyBuffer = Buffer.from(gatewayPublicKey, 'base64')
  const gatewayPublicKeyBytes = arrayify(gatewayPublicKeyBuffer)

  const routing_info: Contract = {
    address: "secret19zpyd046u4swqpksr3n44cej4j8pg6ahw95y85",
    hash: "2a2fbe493ef25b536bbe0baa3917b51e5ba092e14bd76abf50a59526e2789be3"
  };
  const sender: Sender = {
    address: userPublicAddress,
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
  const nonce = arrayify(randomBytes(12));
  let ciphertext = Buffer
    .from(encrypt_payload(gatewayPublicKeyBytes, userPrivateKeyBytes, plaintext, nonce))
    .toString('base64');

  const payloadHash = createHash('sha256').update(ciphertext,'base64').digest();
  const payloadHash64 = payloadHash.toString('base64');
  console.log(`Payload Hash is ${payloadHash.byteLength} bytes`);

  const payloadSignature = ecdsaSign(payloadHash, userPrivateKeyBytes).signature;
  const payloadSignature64 = Buffer.from(payloadSignature).toString('base64');
  console.log(`payload Signature is ${payloadSignature.byteLength} bytes`);

  const handle_msg: PreExecutionMsg = {
    task_id: 1,
    handle: "test",
    routing_info: routing_info,
    sender_info: sender,
    payload: ciphertext,
    nonce: Buffer.from(nonce).toString('base64'),
    payload_hash: payloadHash64,
    payload_signature: payloadSignature64,
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
  // assert(tx.code === 0, `\x1b[31;1m[FAIL]\x1b[0m`);

  const status = tx.arrayLog!.find(
    (log) => log.type === "wasm" && log.key === "status"
  )!.value;
  assert(status == "sent to private contract");
}

async function outputTx(
  client: SecretNetworkClient,
  contractHash: string,
  contractAddress: string,
) {
  const inputs = JSON.stringify({"input1": "some string", "input2": 1, "input3": true});
  const input_hash = createHash('sha256').update(inputs).digest(); // hash needs to match the one inside the contract
  const handle_msg: PostExecutionMsg = {
    result: "{\"answer\": 42}",
    task_id: 1,
    input_hash: Buffer.from(input_hash).toString('base64'),
  };
  console.log("handle_msg:");
  console.log(handle_msg);

  const tx = await client.tx.compute.executeContract(
    {
      sender: client.address,
      contractAddress: contractAddress,
      codeHash: contractHash,
      msg: {
        output: { outputs: handle_msg },
      },
      sentFunds: [],
    },
    {
      gasLimit: 200000,
    }
  );
  
  if (tx.code !== 0) {
    throw new Error(
      `Failed with the following error:\n ${tx.rawLog}`
      );
    };
  assert(tx.code === 0, `\x1b[31;1m[FAIL]\x1b[0m`);
  
  const status = tx.arrayLog!.find(
    (log) => log.type === "wasm" && log.key === "status"
    )!.value;
  assert(status == "sent to relayer");

  const jsonString = Buffer.from(tx.data[0]).toString('utf8');
  const broadcastMsg = JSON.parse(jsonString) as BroadcastMsg;

  console.log(broadcastMsg)
  console.log(`outputTx used \x1b[33m${tx.gasUsed}\x1b[0m gas`);
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

  console.log(`Gateway Public Key: ${response.key}`);
  return response.key
}

async function test_input_tx(
  client: SecretNetworkClient,
  contractHash: string,
  contractAddress: string,
) {
  console.log(`Sending query: {"get_public_key": {} }`);
  const gatewayPublicKey = await queryPubKey(client, contractHash, contractAddress);
  await inputTx(client, contractHash, contractAddress, gatewayPublicKey);
}

async function test_output_tx(
  client: SecretNetworkClient,
  contractHash: string,
  contractAddress: string,
) {
  await outputTx(client, contractHash, contractAddress);
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
  const [client, contractHash, contractAddress] =
    await initializeAndUploadContract();
  await runTestFunction(test_input_tx, client, contractHash, contractAddress);
  await runTestFunction(test_output_tx, client, contractHash, contractAddress);
})();
