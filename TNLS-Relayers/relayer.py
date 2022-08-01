'''
Overall execution:

poller:

every N seconds:
poll both sides for gateway transactions
parse transactions into list of objects
save each object somewhere? (sqlite?)
spin up thread to handle routing each object to the right location

Individual thread:
for each object:
get destination network
verify signature?
stringify object as json
send json string to destination network
update sqlite db (keyed by task ID) with state of object

'''

from eth_interface import EthInterface, EthContract
from scrt_interface import SCRTInterface, SCRTContract
from base_interface import Task


class Relayer:
    def __init__(self, eth_interface: EthInterface, eth_contract_interface: EthContract, scrt_interface: SCRTInterface,
                 scrt_contract_interface: SCRTContract):
        self.task_list = []
        self.eth_interface = eth_interface
        self.eth_contract_interface = eth_contract_interface
        self.scrt_contract_interface = scrt_contract_interface
        self.scrt_interface = scrt_interface
        self.chain_interfaces = {'Ethereum': self.eth_interface, 'SCRT': self.scrt_interface}
        self.contract_interfaces = {'Ethereum': self.eth_contract_interface, 'SCRT': self.scrt_contract_interface}

        pass

    def poll_for_transactions(self):
        for name, interface in self.chain_interfaces.items():
            transactions = interface.get_transactions()
            for transaction in transactions:
                task = self.contract_interfaces[name].parse_event_from_txn(transaction)
                self.task_list.append(task)

    def route_transaction(self, task: Task):
        contract_for_txn = self.contract_interfaces[task.task_destination_network]
        function = contract_for_txn.get_function(task.task_data['function_name'])
        contract_for_txn.call_function(function, str(task))
        pass

    def update_db(self):
        pass

    def run(self):
        pass
