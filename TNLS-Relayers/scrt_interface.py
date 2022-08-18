import json

from secret_sdk.client.lcd import LCDClient
from secret_sdk.key.raw import RawKey

from base_interface import BaseChainInterface, BaseContractInterface


class SCRTInterface(BaseChainInterface):
    def __init__(self, private_key=None, address=None, api_url=None, chain_id=None, **kwargs):
        self.private_key = RawKey(private_key)
        self.provider = LCDClient(url=api_url, chain_id=chain_id, **kwargs)
        self.address = address
        self.wallet = self.provider.wallet(self.private_key)

    def sign_and_send_transaction(self, tx):
        signed_tx = self.wallet.key.sign_tx(tx)
        return self.provider.tx.broadcast(signed_tx)

    def get_transactions(self):
        # gets the transactions from the most recent block for a particular address.
        pass


class SCRTContract(BaseContractInterface):
    def __init__(self, interface, address, abi, code_hash):
        self.address = address
        self.abi = json.loads(abi)
        self.interface = interface
        self.code_hash = code_hash
        pass

    def get_function(self, function_name):
        # IS THIS CORRECT?  HOW DO WE REPRESENT AN ABI?
        return self.abi[function_name]
        pass

    def construct_txn(self, function_schema, *args):
        # IS THIS CORRECT?
        function_schema['args'] = args
        txn = self.interface.wasm.contract_execute_msg(
            sender_address=self.interface.address,
            contract_address=self.address,
            handle_msg=function_schema,

        )
        return txn

    def call_function(self, function_name, *args):
        function_schema = self.get_function(function_name)
        txn = self.construct_txn(function_schema, *args)
        return self.interface.sign_and_send_transaction(txn)

    def parse_event_from_txn(self, event_name, txn):
        # FIGURE THIS OUT!

        pass
