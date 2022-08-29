import json
from logging import getLogger, basicConfig, DEBUG, StreamHandler
from typing import List

from secret_sdk.client.lcd import LCDClient
from secret_sdk.core.auth.data import TxLog
from secret_sdk.key.raw import RawKey

from base_interface import BaseChainInterface, BaseContractInterface, Task


class SCRTInterface(BaseChainInterface):
    def __init__(self, private_key="c2cdf0a8b0a83b35ace53f097b5e6e6a0a1f2d40535eff1cf434f52a43d59d8f",
                 address=None, api_url=None, chain_id=None, provider=None, **kwargs):
        if isinstance(private_key, str):
            self.private_key = RawKey.from_hex(private_key)
        else:
            self.private_key = RawKey(private_key)
        if provider is None:
            self.provider = LCDClient(url=api_url, chain_id=chain_id, **kwargs)
        else:
            self.provider = provider
        self.address = address
        assert self.address == str(self.private_key.acc_address), f"Address {self.address} and private key " \
                                                                  f"{self.private_key.acc_address} mismatch"
        self.wallet = self.provider.wallet(self.private_key)

    def sign_and_send_transaction(self, tx):
        signed_tx = self.wallet.key.sign_tx(tx)
        return self.provider.tx.broadcast(signed_tx)

    def get_transactions(self, address, height=None):
        block_info = self.provider.tendermint.block_info()
        if height is None:
            height = block_info['block']['header']['height']
        txns = self.provider.tx.search(options={'message.sender': address, 'tx.minheight': height}).txs
        logs_list = [txn.logs for txn in txns]
        flattened_log_list = [item for sublist in logs_list for item in sublist]
        return flattened_log_list


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

    def construct_txn(self, function_schema, function_name, args):
        # IS THIS CORRECT?
        arg_keys = function_schema['args']
        arg_dict = dict()
        if isinstance(args, list):
            arg_values = [arg for arg in args]
            if len(arg_keys) != len(arg_values):
                self.logger.warning(f"Arguments do not match schema."
                                    f"  Expected {len(arg_keys)} arguments but got {len(arg_values)}")
                if len(arg_keys) > len(arg_values):
                    arg_values += [""] * (len(arg_keys) - len(arg_values))
                else:
                    arg_values = arg_values[:len(arg_keys)]
            arg_dict = dict(zip(arg_keys, arg_values))
        elif isinstance(args, dict):
            arg_dict = args
            if set(arg_keys) != set(args.keys()):
                self.logger.warning(f"Arguments do not match schema."
                                    f"  Expected {sorted(list(arg_keys))} arguments but got {sorted(list(args.keys()))}")
                if set(arg_keys) > set(args.keys()):
                    for key in arg_keys:
                        if key not in args.keys():
                            arg_dict[key] = ""
                arg_dict = {key: arg_dict[key] for key in arg_keys}
        function_schema = {function_name: arg_dict}
        txn = self.interface.wasm.contract_execute_msg(
            sender_address=self.interface.address,
            contract_address=self.address,
            handle_msg=function_schema,

        )
        return txn

    def call_function(self, function_name, *args):
        # TODO:  FIGURE OUT ARGS PROCESSING HERE
        function_schema = self.get_function(function_name)
        if len(args) == 1:
            args = args[0]
        args = json.loads(json.dumps(args))
        txn = self.construct_txn(function_schema, function_name, args)
        return self.interface.sign_and_send_transaction(txn)

    def parse_event_from_txn(self, event_name: str, logs: List[TxLog]):
        task_list = []
        for log in logs:
            events = [event for event in log.events if event['type'] == event_name]
            for event in events:
                attr_dict = {attribute['key']: attribute['value'] for attribute in event['attributes']}
                task_list.append(Task(attr_dict))
        return task_list
