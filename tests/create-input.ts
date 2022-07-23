import { PreExecutionMsg, PostExecutionMsg, Payload, Contract, Sender, Binary } from "./GatewayContract";
import { publicKeyCreate, privateKeyVerify, ecdh } from "secp256k1";
import { Wallet as EthWallet, utils } from "ethers";
import { randomBytes, createCipheriv, createDecipheriv }from 'crypto'
import { sha256, SigningKey } from "ethers/lib/utils";

async function inputTx() {
  
  let gatewayPrivKey
  do {
    gatewayPrivKey = randomBytes(32)
  } while (!privateKeyVerify(gatewayPrivKey));

  const gatewayPubKey = publicKeyCreate(gatewayPrivKey);
  console.log('\x1b[35m%s\x1b[0m', `\nGateway Private Key: ${Uint8Array.from(gatewayPrivKey)}\nGateway Public Key: ${gatewayPubKey}`);

  var wallet = EthWallet.createRandom(); 
  var signing_key = new SigningKey(wallet.privateKey);

  const public_address: string = wallet.address;
  const public_key: string = signing_key.compressedPublicKey;
  const private_key: string = signing_key.privateKey;
  console.log('\x1b[34m%s\x1b[0m', `\nEthereum Address: ${public_address}\nPublic Key: ${public_key}\nPrivate Key: ${private_key}`);

  const privateKey = utils.arrayify(wallet.privateKey)
  const publicKey = utils.arrayify(wallet.publicKey)

  var sharedKey = ecdh(gatewayPubKey, privateKey)

  const routing_info: Contract = {
    // these are fake
    address: "secret19zpyd046u4swqpksr3n44cej4j8pg6ahw95y85",
    hash: "2a2fbe493ef25b536bbe0baa3917b51e5ba092e14bd76abf50a59526e2789be3"
  };

  const sender: Sender = {
    address: public_address,
    public_key: Buffer.from(public_key).toString('base64'),
  };

  const inputs: string = JSON.stringify({"input1": "some string", "input2": 1, "input3": true});

  const payload: Payload = {
    data: inputs,
    routing_info: routing_info,
    sender: sender,
  };
  console.log(payload)

  // const nonce = randomBytes(12);
  const nonce = Uint8Array.from([117, 110, 105, 113, 117, 101, 32, 110, 111, 110, 99, 101]);
  // const nonce = Buffer.from(uint8array);
  console.log(Buffer.from(nonce).toString('utf8'))
  // const aad = Buffer.from('0123456789', 'hex');
  const cipher = createCipheriv('chacha20-poly1305', sharedKey, nonce, {
      authTagLength: 16
  });
  const plaintext = Buffer.from(JSON.stringify(payload));
  console.log(JSON.stringify(payload))
  // cipher.setAAD(aad, {
  //   plaintextLength: plaintext.byteLength
  // });
  const ciphertext = cipher.update(plaintext, undefined, 'base64');
  cipher.final();
  const tag = cipher.getAuthTag();

  const payload_hash = sha256(plaintext);
  const payload_hash_64 = Buffer.from(payload_hash).toString('base64')

  const payload_signature = await wallet.signMessage(payload_hash);
  const payload_signature_64 = Buffer.from(payload_signature).toString('base64');

  const handle_msg: PreExecutionMsg = {
    handle: "test",
    payload: ciphertext,
    payload_hash: payload_hash_64,
    payload_signature: payload_signature_64,
    routing_info: routing_info,
    sender: sender,
    task_id: 1,
  };
  console.log('\x1b[31m%s\x1b[0m', handle_msg)

  const sharedKey2 = ecdh(publicKey, gatewayPrivKey)
  const decipher = createDecipheriv('chacha20-poly1305', sharedKey2, nonce, {
    authTagLength: 16
  });
  // decipher.setAAD(aad, {
  //   plaintextLength: plaintext.byteLength
  // });
  const decrypted_payload = decipher.update(ciphertext, 'base64', 'utf-8');
  decipher.final();

  console.log(decrypted_payload)
}

inputTx()