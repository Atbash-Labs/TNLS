import { encrypt_payload } from "./wasm";
import { ethers } from "ethers";
import { arrayify, SigningKey } from "ethers/lib/utils";
import { Buffer } from "buffer/";
import secureRandom from "secure-random";

export async function setupSubmit(element: HTMLButtonElement) {
    // @ts-ignore
    const provider = new ethers.providers.Web3Provider(window.ethereum);
    const [myAddress] = await provider.send("eth_requestAccounts", []);

    // generating ephemeral keys
    const wallet = ethers.Wallet.createRandom();
    const userPrivateKeyBytes = arrayify(wallet.privateKey);
    const userPublicKey: string = new SigningKey(wallet.privateKey).compressedPublicKey;
    const userPublicKeyBytes = arrayify(userPublicKey)
    //

    const gatewayPublicKey = "AnPh4zgH57ijrnAEaTxQMtBJSYIe9fJruWRRD8JLt+Cf"; // TODO get this key
    const gatewayPublicKeyBuffer = Buffer.from(gatewayPublicKey, "base64");
    const gatewayPublicKeyBytes = arrayify(gatewayPublicKeyBuffer);

    element.addEventListener("click", async function(event: Event){
        event.preventDefault()

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
        console.log(data)

        const routing_info = "secret10pyejy66429refv3g35g2t7am0was7ya6hvrzf"
        const routing_code_hash = "5daf336102c875f790dfeabb23a4d985bf71a9856b6cb52be00fd7e9de41ce32"
        const user_address = myAddress
        const user_key = Buffer.from(userPublicKeyBytes)

        const handle = "request_score"
    
        const thePayload = JSON.stringify({
          data: data,
          routing_info: routing_info,
          routing_code_hash: routing_code_hash,
          user_address: user_address,
          user_key: user_key.toString('base64'),
        })
        console.log(thePayload)
        
        const plaintext = Buffer.from(JSON.stringify(thePayload));
        const nonce = secureRandom(12, { type: "Uint8Array" });

        const ciphertext = Buffer.from(
        encrypt_payload(
            gatewayPublicKeyBytes,
            userPrivateKeyBytes,
            plaintext,
            nonce
        ));
        console.log(`Encrypted Payload: ${ciphertext.toString('base64')}`)
    
        // get Metamask to sign the payloadHash
        const payloadHash = ethers.utils.keccak256(arrayify(ciphertext))
        console.log(`Message hash: ${payloadHash}`)

        const msgParams = JSON.stringify({
            domain: {
                chainId: 5,
                name: 'TNLS Client Demo',
                verifyingContract: '0x32B3Ae25D548140094259eF164a52da7929CbbB9',
                version: '1',
            },
        
            // Defining the message signing data content.
            message: {
                payloadHash: payloadHash
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
                { name: 'payloadHash', type: 'string' },
              ],
            },
          })
        
        const from = myAddress;
        const params = [from, msgParams];
        const method = 'eth_signTypedData_v4';

        const payload_signature = await provider.send(method, params)
        console.log(`Signature: ${payload_signature}`)
        //

        const _userAddress = myAddress
        const _sourceNetwork = "ethereum"
        const _routingInfo = routing_info
        const _payloadHash = payloadHash
        const _info = {
            user_key: ethers.utils.hexlify(user_key),
            routing_code_hash: routing_code_hash,
            handle: handle,
            nonce: ethers.utils.hexlify(nonce),
            payload: ethers.utils.hexlify(ciphertext),
            payload_signature: payload_signature
        }
                
        const abiEncodedMsg = ethers.utils.defaultAbiCoder.encode(
            [ "address _userAddress", "string _sourceNetwork", "string _routingInfo", "bytes32 _payloadHash", 
              "tuple(bytes user_key, string routing_code_hash, string handle, bytes12 nonce, bytes payload, bytes payload_signature) _info" ],
            [
                _userAddress,
                _sourceNetwork,
                _routingInfo,
                _payloadHash,
                _info
            ]
        )

        // gives a nasty warning in metamask... I think this step is supposed to be done client-side instead
        // const eth_sign_params = [myAddress, payloadHash]
        // const [signedTx] = await provider.send("eth_sign", eth_sign_params);

        const tx_params = [
            {
              from: myAddress,
              to: '0x32B3Ae25D548140094259eF164a52da7929CbbB9',
              gas: '0x0493E0', // 300000
              gasPrice: '0x03E8', // 1000
              value: '0x03E8', // 1000
              data: "0x000000000000000000", // TODO figure out what this data is meant to be
            },
          ];

        // const [tx] = await provider.send("eth_sendTransaction", tx_params);

        document.querySelector<HTMLDivElement>('#preview')!.innerHTML = `
        <h2>Raw Payload</h2>
        <p>${thePayload}</p>
        <h2>Encrypted Payload</h2>
        <p>${ciphertext.toString('base64')}</p>
        <h2>Other Info</h2>
        <p>
        Encryption method: ChaCha20Poly1305 <br>
        Public key used during encryption: ${userPublicKey} <br>
        Nonce used during encryption: ${nonce} <br>
        Payload Hash: ${payloadHash} <br>
        Payload Signature: ${payload_signature} <br>

        _userAddress: ${_userAddress} <br>
        _sourceNetwork: ${_sourceNetwork} <br>
        _routingInfo: ${_routingInfo} <br>
        _payloadHash: ${_payloadHash} <br>
        _info: ${JSON.stringify(_info)} <br>

        abiEncodedMsg: ${abiEncodedMsg} <br>
        </p>
        `
    })
}