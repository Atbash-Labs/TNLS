from json import loads
from typing import List

import pytest

from ..base_interface import BaseChainInterface, BaseContractInterface, Task

"""
Figure out something where the fake chain returns a fixed set of transactions,
and the contract interface handling them just returns the incoming results plus n, where n is the
specific destination network the contract gets routed to?
"""


class FakeChainInterface(BaseChainInterface):

    def __init__(self, tx_list):
        self.tx_list = tx_list
        pass

    def get_transactions(self):
        return self.tx_list
        pass

    def create_transaction(self, _contract_function, _data):
        pass

    def sign_and_send_transaction(self, _tx):
        pass


class FakeContractInterface(BaseContractInterface):

    def __init__(self, num_to_add):
        self.num_to_add = num_to_add
        self.results = {}
        pass

    def call_function(self, _function_name, *args):
        task_dict = loads(str(args))
        task_result = task_dict['task_data'] + self.num_to_add
        task_id = task_dict['task_id']
        self.results[task_id] = task_result
        pass

    def parse_event_from_txn(self, event_name, txn) -> List[Task]:
        return [Task(txn)]


@pytest.fixture
def fake_interface_factory():
    def _factory_fn(task_dict_list, num_to_add):
        return FakeChainInterface(task_dict_list), FakeContractInterface(num_to_add)

    return _factory_fn
