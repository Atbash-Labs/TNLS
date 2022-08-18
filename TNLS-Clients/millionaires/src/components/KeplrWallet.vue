<template>
  <div>
    <button v-if="!isConnected" @click="bootstrap">Connect</button>
    <span v-else-if="isConnected"
      ><button>Connected</button> {{ myAddress }}</span
    >
    <br />
    <button @click="getBalance">Get SCRT Balance</button>
    {{ balance }}
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from "vue";
import { SecretNetworkClient } from "secretjs";
import type { Window as KeplrWindow, Keplr } from "@keplr-wallet/types";

declare global {
  // eslint-disable-next-line @typescript-eslint/no-empty-interface
  interface Window extends KeplrWindow {}
}
declare let window: KeplrWindow;

const isConnected = ref<boolean>(false);

const balance = ref<string>();
const myAddress = ref<string>();
const secretjs = ref<SecretNetworkClient>();

const CHAIN_ID = "pulsar-2";
const grpcWebUrl = "https://grpc.pulsar.scrttestnet.com";

async function bootstrap() {
  await window.keplr!.enable(CHAIN_ID);

  const keplrOfflineSigner = window.getOfflineSignerOnlyAmino!(CHAIN_ID);
  [{ address: myAddress.value }] = await keplrOfflineSigner.getAccounts();

  secretjs.value = await SecretNetworkClient.create({
    grpcWebUrl,
    chainId: CHAIN_ID,
    wallet: keplrOfflineSigner,
    walletAddress: myAddress.value,
    encryptionUtils: window.getEnigmaUtils!(CHAIN_ID),
  });
  isConnected.value = true;
}

async function getBalance() {
  const { balance: myBalance } = await secretjs.value!.query.bank.balance({
    address: myAddress.value,
    denom: "uscrt",
  });
  balance.value = (parseInt(myBalance!.amount) / 1000000).toLocaleString(
    "en-US"
  );
}
</script>
