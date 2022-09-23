=======
# TNLS
This repository is an alpha implementation of the Snakepath Network and its underlying TNLS protocol, currently connecting the Eth Goerli testnet to the Secret Network pulsar-2 testnet.

Docs (whih are relatively barebones atm but will be being improved over time) can be found at [our gitbook](https://fortress-labs.gitbook.io/snakepath/)

## TNLS Architecture
![TNLS Architecture](assets/tnls_architecture.png)

## Ethereum Contracts

You will need a copy of [Foundry](https://github.com/foundry-rs/foundry) installed before proceeding. See the [installation guide](https://github.com/foundry-rs/foundry#installation) for details.

To build the contracts:

```sh
git clone https://github.com/Atbash-Labs/TNLS.git
cd public-gateway
forge install 
```

### Run Tests

In order to run unit tests, run: 

```sh
forge test
```
