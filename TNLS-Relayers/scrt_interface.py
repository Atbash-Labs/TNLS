import json
from logging import getLogger, basicConfig, DEBUG, StreamHandler

from secret_sdk.client.lcd import LCDClient
from secret_sdk.core.auth.data import TxLog
from secret_sdk.key.raw import RawKey

from base_interface import BaseChainInterface, BaseContractInterface, Task


class SCRTInterface(BaseChainInterface):
    def __init__(self, private_key="c2cdf0a8b0a83b35ace53f097b5e6e6a0a1f2d40535eff1cf434f52a43d59d8f",
                 address=None, api_url=None, chain_id=None, provider=None, **kwargs):
        self.private_key = RawKey.from_hex(private_key)
        if provider is None:
            self.provider = LCDClient(url=api_url, chain_id=chain_id, **kwargs)
        else:
            self.provider = provider
        self.address = address
        self.wallet = self.provider.wallet(self.private_key)

    def sign_and_send_transaction(self, tx):
        signed_tx = self.wallet.key.sign_tx(tx)
        return self.provider.tx.broadcast(signed_tx)

    def get_transactions(self, address):
        block_info = self.provider.tendermint.block_info()
        height = block_info['block']['header']['height']
        txns = self.provider.tx.search(options={'message.sender': address, 'tx.minheight': height}).txs
        logs_list = [txn.logs for txn in txns]
        return logs_list


class SCRTContract(BaseContractInterface):
    def __init__(self, interface, address, abi):
        self.address = address
        self.abi = json.loads(abi)
        self.interface = interface
        basicConfig(
            level=DEBUG,
            format="%(asctime)s [SCRT interface: %(levelname)8.8s] %(message)s",
            handlers=[StreamHandler()],
        )
        self.logger = getLogger()
        pass

    def get_function(self, function_name):
        # IS THIS CORRECT?  HOW DO WE REPRESENT AN ABI?
        return self.abi[function_name]
        pass

    def construct_txn(self, function_schema, function_name, *args):
        # IS THIS CORRECT?
        arg_keys = function_schema['args']
        arg_values = [arg for arg in args]
        if len(arg_keys) != len(arg_values):
            self.logger.warning(f"Arguments do not match schema."
                                f"  Expected {len(arg_keys)} arguments but got {len(arg_values)}")
            if len(arg_keys) > len(arg_values):
                arg_values += [""] * (len(arg_keys) - len(arg_values))
            else:
                arg_values = arg_values[:len(arg_keys)]
        arg_dict = dict(zip(arg_keys, arg_values))
        function_schema = {function_name: arg_dict}
        txn = self.interface.wasm.contract_execute_msg(
            sender_address=self.interface.address,
            contract_address=self.address,
            handle_msg=function_schema,

        )
        return txn

    def call_function(self, function_name, *args):
        function_schema = self.get_function(function_name)
        txn = self.construct_txn(function_schema, function_name, *args)
        return self.interface.sign_and_send_transaction(txn)

    def parse_event_from_txn(self, event_name: str, log: TxLog):
        task_list = [Task(event) for event in log.events if event['type'] == event_name]
        return task_list
