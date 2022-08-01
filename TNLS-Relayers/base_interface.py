import abc
import json
from typing import List

class Task:
    def __init__(self, task_dict):
        self.task_destination_network = task_dict['task_destination_network']
        self.task_data = task_dict
        self.__dict__.update(task_dict)

    def __str__(self):
        return json.dumps(self.__dict__)

    def __repr__(self):
        return self.__str__()
class BaseChainInterface(abc.ABC):
    @abc.abstractmethod
    def create_transaction(self, contract_function, data):
        #create task
        pass

    @abc.abstractmethod
    def sign_and_send_transaction(self, tx):
        pass

    @abc.abstractmethod
    def get_transactions(self):
        pass

class BaseContractInterface(abc.ABC):

    @abc.abstractmethod
    def get_function(self, function_name):
        pass

    @abc.abstractmethod
    def call_function(self, function_name, *args):
        pass


    @abc.abstractmethod
    def parse_event_from_txn(self, event_name, txn) -> List[Task]:
        pass


