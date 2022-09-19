import { ethers } from 'ethers'

export async function setupSignMessage(element: HTMLButtonElement) {
    element.innerHTML = `Sign`
    // @ts-ignore
    const provider = new ethers.providers.Web3Provider(window.ethereum);
    const [myAddress] = await provider.send("eth_requestAccounts", []);
    // const signer = provider.getSigner();
    // const publicKey = provider.send('eth_requestPublicKey', []);
  
    const msgParams = JSON.stringify({
      domain: {
        // Defining the chain aka Rinkeby testnet or Ethereum Main Net
        chainId: 5,
        // Give a user friendly name to the specific contract you are signing for.
        name: 'TNLS Gateway',
        // If name isn't enough add verifying contract to make sure you are establishing contracts with the proper entity
        verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
        // Just let's you know the latest version. Definitely make sure the field name is correct.
        version: '1',
      },
  
      // Defining the message signing data content.
      message: {
        /*
         - Anything you want. Just a JSON Blob that encodes the data you want to send
         - No required fields
         - This is DApp Specific
         - Be as explicit as possible when building out the message schema.
        */
  
        // placeholder values
        data: '{"address": 0x1234,"name": "Alice","offchain_assets": 0,"onchain_assets": 2000,"liabilities": 4000,"missed_payments": 0,"income": 5000,}',
        routing_info: {
          hash: "5daf336102c875f790dfeabb23a4d985bf71a9856b6cb52be00fd7e9de41ce32",
          address: "secret10pyejy66429refv3g35g2t7am0was7ya6hvrzf",
        },
        sender: {
          address: "0x7e84203513CD6DECDB28bdDc733456f10aD0397E",
          public_key: "AqA4dmLYgDncbCTi5n7GQTJT6gbylwmzjYPx3ocmNT+L",
        },
      },
      // Refers to the keys of the *types* object below.
      primaryType: 'Payload',
      types: {
        // TODO: Clarify if EIP712Domain refers to the domain the contract is hosted on
        EIP712Domain: [
          { name: 'name', type: 'string' },
          { name: 'version', type: 'string' },
          { name: 'chainId', type: 'uint256' },
          { name: 'verifyingContract', type: 'address' },
        ],  
        // Refer to PrimaryType
        Payload: [
          { name: 'data', type: 'string' },
          { name: 'routing_info', type: 'RoutingInfo' },
          { name: 'sender', type: 'Sender' },
        ],
        RoutingInfo: [
          { name: 'hash', type: 'string' },
          { name: 'address', type: 'string' },
        ],
        Sender: [
          { name: 'address', type: 'string' },
          { name: 'public_key', type: 'string' },
        ]
      },
    });
  
    const from = myAddress;
    const params = [from, msgParams];
    const method = 'eth_signTypedData_v4';
    const signMessage =async () => {
        provider.send(method, params);
    }

    element.addEventListener('click', () => signMessage())
  }