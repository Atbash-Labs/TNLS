import { ethers } from 'ethers'

export async function setupSignMessage(element: HTMLButtonElement) {
    element.innerHTML = `Sign`
    // @ts-ignore
    const provider = new ethers.providers.Web3Provider(window.ethereum);
    const [myAddress] = await provider.send("eth_requestAccounts", []);
    // const signer = provider.getSigner();
    // const publicKey = provider.send('eth_requestPublicKey', []);

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

    const msgParams = JSON.stringify({
      domain: {
        // Defining the chain aka Rinkeby testnet or Ethereum Main Net
        chainId: 5,
        // Give a user friendly name to the specific contract you are signing for.
        name: 'TNLS Demo',
        // If name isn't enough add verifying contract to make sure you are establishing contracts with the proper entity
        verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
        // Just let's you know the latest version. Definitely make sure the field name is correct.
        version: '1',
      },
  
      // Defining the message signing data content.
      message: {
        data: data,
        routing_info: "secret10pyejy66429refv3g35g2t7am0was7ya6hvrzf",
        routing_code_hash: "5daf336102c875f790dfeabb23a4d985bf71a9856b6cb52be00fd7e9de41ce32",
        user_address: "0x7e84203513CD6DECDB28bdDc733456f10aD0397E",
        user_key: "AqA4dmLYgDncbCTi5n7GQTJT6gbylwmzjYPx3ocmNT+L",
      },
      // Refers to the keys of the *types* object below.
      primaryType: 'Payload',
      types: {
        EIP712Domain: [
          { name: 'name', type: 'string' },
          { name: 'version', type: 'string' },
          { name: 'chainId', type: 'uint256' },
          { name: 'verifyingContract', type: 'address' },
        ],  
        // Refer to PrimaryType
        Payload: [
          { name: 'data', type: 'string' },
          { name: 'routing_info', type: 'string' },
          { name: 'routing_code_hash', type: 'string' },
          { name: 'user_address', type: 'string' },
          { name: 'user_key', type: 'string' },
        ],
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