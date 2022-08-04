from pprint import pprint

from web3 import Web3
from base_interface import BaseChainInterface, BaseContractInterface, Task
from typing import List, Mapping, Sequence
from requests import HTTPError
from logging import getLogger, basicConfig, INFO, StreamHandler
import os

with open(f"{os.getcwd()}/infura_api_endpoint.txt") as file:
    infura_endpoint = file.read()

API_MODE = "dev"

ADDRESS = "0xce1dfc3F67B028Ed19a97974F8cD2bAF6fba1672" if API_MODE != "dev" else "0xae050f76654B1Cf264A203545371F1575119530C"

API_URL = infura_endpoint.replace("{ENDPOINT}", "mainnet") if API_MODE != "dev" else infura_endpoint.replace(
    "{ENDPOINT}", "ropsten")

web3provider = Web3(Web3.HTTPProvider(API_URL))


class EthInterface(BaseChainInterface):
    def __init__(self, private_key="", address=ADDRESS, provider=Web3(Web3.HTTPProvider(API_URL))):
        self.private_key = private_key
        self.provider = provider
        self.address = address
        basicConfig(
            level=INFO,
            format="%(asctime)s [Eth Interface: %(levelname)8.8s] %(message)s",
            handlers=[StreamHandler()],
        )
        self.logger = getLogger()
        pass

    def create_transaction(self, contract_function, data):
        # create task
        nonce = self.provider.eth.get_transaction_count(self.address)
        try:
            tx = contract_function(data).buildTransaction({
            'from': self.address,
            'gas': 200000,
            'nonce': nonce,
            'gasPrice': self.provider.eth.gasPrice,
            })
        except HTTPError:
            tx = contract_function(data).buildTransaction({
                'from': self.address,
                'gas': 200000,
                'nonce': nonce,
                'gasPrice': 20000,
            })

        return tx

    def sign_and_send_transaction(self, tx):
        # sign task
        signed_tx = self.provider.eth.account.sign_transaction(tx, self.private_key)
        # send task
        tx_hash = self.provider.eth.send_raw_transaction(signed_tx.rawTransaction)
        return tx_hash

    def get_transactions(self):
        return self.get_last_txs(self.address)

    def get_last_block(self):
        return self.provider.eth.blockNumber

    def get_last_txs(self, address=ADDRESS):
        # get last txs for address
        transactions: Sequence[Mapping] = self.provider.eth.get_block(self.get_last_block(), full_transactions=True)[
            'transactions']
        correct_transactions = [transaction for transaction in transactions if transaction['from'] == address]
        correct_transactions = list(
            map(lambda tx: self.provider.eth.get_transaction_receipt(tx['hash']), correct_transactions))

        return correct_transactions


class EthContract(BaseContractInterface):
    def __init__(self, interface, address, abi):
        self.address = address
        self.abi = abi
        self.interface = interface
        self.contract = interface.provider.eth.contract(address=self.address, abi=self.abi)
        basicConfig(
            level=INFO,
            format="%(asctime)s [Eth Contract: %(levelname)8.8s] %(message)s",
            handlers=[StreamHandler()],
        )
        self.logger = getLogger()
        pass

    def get_function(self, function_name):
        return self.contract.functions[function_name]

    def call_function(self, function_name, *args):
        function = self.get_function(function_name)
        txn = self.interface.create_transaction(function, args)
        return self.interface.sign_and_send_transaction(txn)

    def parse_event_from_txn(self, event_name, txn) -> List[Task]:
        event = self.contract.events[event_name]
        try:
            tasks = event.processReceipt(txn)
        except Exception as e:
            self.logger.info(e)
            return []
        task_list = []
        for task in tasks:
            args = task['args']
            task_list.append(Task(args))
        return task_list


if __name__ == "__main__":
    interface = EthInterface(address='0xEB7D94Cefa561E83901aD87cB91eFcA73a1Fc812')
    txs = interface.get_last_txs()
    pprint(txs)
