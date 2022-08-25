<script setup lang="ts">
import MetaMask from "@/components/MetaMask.vue";
import ThePayload from "../components/ThePayload.vue";
</script>

<template>
    <MetaMask />
  <main>
    <!-- <ThePayload /> -->
  </main>
</template>

<style scoped>
main {
  display: grid;
  grid-template-columns: 250px 1fr;
}
</style>
