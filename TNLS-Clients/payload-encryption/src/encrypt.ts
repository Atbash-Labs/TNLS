import { encrypt_payload } from "./wasm";
import { ethers } from "ethers";
import { arrayify, SigningKey } from "ethers/lib/utils";
import { Buffer } from "buffer/";
import secureRandom from "secure-random";

export async function setupEncrypt(element: HTMLButtonElement) {
  element.innerHTML = `Encrypt`

  // @ts-ignore
  const provider = new ethers.providers.Web3Provider(window.ethereum);
  const [myAddress] = await provider.send("eth_requestAccounts", []);

  const offchain_assets = document.querySelector<HTMLFormElement>('#input1')?.value;
  const onchain_assets = document.querySelector<HTMLFormElement>('#input2')?.value;
  const liabilities = document.querySelector<HTMLFormElement>('#input3')?.value;
  const missed_payments = document.querySelector<HTMLFormElement>('#input4')?.value;
  const income = document.querySelector<HTMLFormElement>('#input5')?.value;

  const data = JSON.stringify({
    address: myAddress,
    offchain_assets: Number(offchain_assets),
    onchain_assets: Number(onchain_assets),
    liabilities: Number(liabilities),
    missed_payments: Number(missed_payments),
    income: Number(income)
  })

  const routing_info = "secret10pyejy66429refv3g35g2t7am0was7ya6hvrzf"
  const routing_code_hash = "5daf336102c875f790dfeabb23a4d985bf71a9856b6cb52be00fd7e9de41ce32"
  const user_address = myAddress
  // generating ephemeral keys
  const wallet = ethers.Wallet.createRandom();
  const userPrivateKeyBytes = arrayify(wallet.privateKey);
  const userPublicKey: string = new SigningKey(wallet.privateKey).compressedPublicKey;
  const userPublicKeyBytes = arrayify(userPublicKey)
  //
  const user_key = Buffer.from(userPublicKeyBytes).toString('base64');

  const thePayload = JSON.stringify({
    data: data,
    routing_info: routing_info,
    routing_code_hash: routing_code_hash,
    user_address: user_address,
    user_key: user_key,
  })
  console.log(thePayload)

  const gatewayPublicKey = "AnPh4zgH57ijrnAEaTxQMtBJSYIe9fJruWRRD8JLt+Cf"; // TODO get this key
  const gatewayPublicKeyBuffer = Buffer.from(gatewayPublicKey, "base64");
  const gatewayPublicKeyBytes = arrayify(gatewayPublicKeyBuffer);

  const plaintext = Buffer.from(JSON.stringify(thePayload));
  const nonce = secureRandom(12, { type: "Uint8Array" });

  const ciphertext = Buffer.from(
    encrypt_payload(
      gatewayPublicKeyBytes,
      userPrivateKeyBytes,
      plaintext,
      nonce
    )
    ).toString("base64");

  const encrypt = async () => {
    document.querySelector<HTMLDivElement>('#preview')!.innerHTML = `
      <p>${ciphertext}</p>
    `
  }
  element.addEventListener('click', () => encrypt())
}