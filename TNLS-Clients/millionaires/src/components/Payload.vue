<template>
  <div>
    <form @submit.prevent="encryptPayload">
      <label>Input Values: </label>
      <input type="text" placeholder="JSON string" v-model="payload.data" />
      <label>Contract Hash: </label>
      <input
        type="text"
        placeholder="code hash"
        v-model="payload.routing_info.hash"
      />
      <label>Contract Address: </label>
      <input
        type="text"
        placeholder="secret..."
        v-model="payload.routing_info.address"
      />
      <label>Sender Address: </label>
      <input type="text" placeholder="0x..." v-model="payload.sender.address" />
      <label>Sender Public Key: </label>
      <input
        type="text"
        placeholder="my public key"
        v-model="payload.sender.public_key"
      />
      <button>Create Payload</button>
    </form>
  </div>
  <div id="preview">
    <div class="box">
      <h3>Raw Payload:</h3>
      {{ payload }}
    </div>
    <div class="box">
      <h3>Encrypted Payload:</h3>
      {{ ciphertext }}
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from "vue";
import { encrypt_payload } from '@/wasm';
import { Wallet as EthWallet } from "ethers";
import { arrayify, SigningKey } from "ethers/lib/utils";
import {Buffer} from 'buffer/'
import type {
  PreExecutionMsg,
  Contract,
  Binary,
  Sender,
  Payload,
} from "@/contracts/private-gateway";
// const {randomBytes} = await import('node:crypto');

// const form = ref<PreExecutionMsg>({
//     task_id: 0,
//     handle: '',
//     routing_info: {
//         hash:'',
//         address:'',
//     },
//     sender_info: {
//         address: '',
//         public_key: '',
//     },
//     payload: '',
//     nonce: '',
//     payload_hash: '',
//     payload_signature: '',
//     source_network: '',
// });

const payload = ref<Payload>({
  // placeholder values
  data: '{"my_value": 1}',
  routing_info: {
    hash: "5daf336102c875f790dfeabb23a4d985bf71a9856b6cb52be00fd7e9de41ce32",
    address: "secret10pyejy66429refv3g35g2t7am0was7ya6hvrzf",
  },
  sender: {
    address: "0x7e84203513CD6DECDB28bdDc733456f10aD0397E",
    public_key: "AqA4dmLYgDncbCTi5n7GQTJT6gbylwmzjYPx3ocmNT+L",
  },
});

const ciphertext = ref<string>("hello");

// async function encryptPayload() {}

async function encryptPayload() {
    const thePayload = payload.value;
    const wallet = EthWallet.createRandom();
    const userPublicAddress: string = wallet.address;
    const userPublicKey: string = new SigningKey(wallet.privateKey).compressedPublicKey;

    const userPrivateKeyBytes = arrayify(wallet.privateKey)
    const userPublicKeyBytes = arrayify(userPublicKey)

    const gatewayPublicKey = "AnPh4zgH57ijrnAEaTxQMtBJSYIe9fJruWRRD8JLt+Cf"
    const gatewayPublicKeyBuffer = Buffer.from(gatewayPublicKey, 'base64')
    const gatewayPublicKeyBytes = arrayify(gatewayPublicKeyBuffer)

    const plaintext = Buffer
        .from(JSON.stringify(thePayload));
    // // const nonce = arrayify(randomBytes(12));
    const nonce = arrayify([0,1,2,3,4,5,6,7,8,9,10,11])

    ciphertext.value = Buffer
    .from(encrypt_payload(gatewayPublicKeyBytes, userPrivateKeyBytes, plaintext, nonce))
    .toString('base64');
}

</script>

<style scoped>
form {
  display: grid;
  max-width: 250px;
  row-gap: 0.4rem;
}
button {
  margin-top: 1rem;
}

#preview {
  display: grid;
  grid-template-rows: 1fr 1fr;
  margin: 0 2rem;
}

.box {
  outline: thick double hsla(160, 100%, 37%, 1);
  transition: 0.4s;
  padding: 0.5rem 1rem;
  margin-top: 1rem;
  word-break: break-all;
}
.box h3 {
  color: var(--color-heading);
}

@media (hover: hover) {
  .box:hover {
    background-color: hsla(160, 100%, 37%, 0.2);
  }
}
</style>
