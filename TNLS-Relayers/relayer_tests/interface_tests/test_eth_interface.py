import pytest
from web3 import Web3
from eth_interface import EthInterface, EthContract


@pytest.fixture
def non_send_provider(monkeypatch):
    with open("../../infura_api_endpoint.txt") as file:
        infura_endpoint = file.read()

    API_MODE = "dev"
    API_URL = infura_endpoint.replace("{ENDPOINT}", "mainnet") if API_MODE != "dev" else infura_endpoint.replace(
        "{ENDPOINT}", "ropsten")

    web3provider = Web3(Web3.HTTPProvider(API_URL))
    web3provider.transaction_info = []

    def mock_send_raw_transaction(tx):
        web3provider.transaction_info.append(tx)
        return tx

    monkeypatch.setattr(web3provider.eth, 'send_raw_transaction', mock_send_raw_transaction)
    monkeypatch.setattr(web3provider.eth, 'get_transaction_count', lambda _address: 1)
    yield web3provider


@pytest.fixture
def no_transaction_check_provider(non_send_provider, monkeypatch):
    non_send_provider.transaction_retrieved = []
    def mock_get_block(_block_number, _full_transactions=False):
        return {
            'transactions': non_send_provider.transaction_retrieved
        }

    def mock_get_transaction_receipt(tx_hash):
        if tx_hash == '1':
            return {
                'status': 1,
                'transactionHash': '1',
                'blockHash': '1',
                'blockNumber': 1,
                'transactionIndex': 1,
                'from': '0x0',
                'to': '0x0',
                'cumulativeGasUsed': 1,
                'gasUsed': 1,
                'contractAddress': '0x0',
                'logs': [
                    # fill later
                ],
            }
        else:
            return {
                {
                    'status': 0,
                    'transactionHash': '1',
                    'blockHash': '1',
                    'blockNumber': 1,
                    'transactionIndex': 1,
                    'from': '0x0',
                    'to': '0x0',
                    'cumulativeGasUsed': 1,
                    'gasUsed': 1,
                    'contractAddress': '0x0',
                    'logs': [
                        # fill later
                    ],
                }

            }

    monkeypatch.setattr(non_send_provider.eth, 'get_block', mock_get_block)
    monkeypatch.setattr(non_send_provider.eth, 'get_transaction_receipt', mock_get_transaction_receipt)
    return non_send_provider


def test_transaction_builder_good(non_send_provider):
    sample_private_key = '8da4ef21b864d2cc526dbdb2a120bd2874c36c9d0a1fb7f8c63d7f7a8b41de8f'
    sample_address = '0x63FaC9201494f0bd17B9892B9fae4d52fe3BD377'

    def sample_contract_function(data):
        class ContractFunction:
            def buildTransaction(self, params):
                transact_dict = {
                    'data': data,
                    'to': sample_address,
                }
                transact_dict.update(params)
                return transact_dict

        return ContractFunction()

    # Note:  the below privkeys/addrs are published online

    interface = EthInterface(address=sample_address, provider=non_send_provider,
                             private_key=sample_private_key)
    transaction = interface.create_transaction(sample_contract_function, '0x123')
    transaction.pop('gasPrice')
    assert transaction == {
        'data': '0x123',
        'from': sample_address,
        'nonce': 1,
        'gas': 200000,
        'to': sample_address,
    }
    transaction['gasPrice'] = 1
    assert str(Web3.toInt(interface.sign_and_send_transaction(
        transaction))) == '646961047256234134936427207708597400990062481352738925532\
44382979189820165162760809784845372096459771505600454239891815718170891799\
6311654666704958317118883520202866260746151473787908917221684661552359733009\
6619889394626268873948136817484127'


def test_transaction_builder_bad_address_from(non_send_provider):
    pass

def test_transaction_builder_bad_address_to(non_send_provider):
    pass

def test_transaction_builder_bad_private_key(non_send_provider):
    pass

def test_transaction_builder_mismatched_private_key(non_send_provider):
    pass

def test_correct_txn_filtering(no_transaction_check_provider):
    no_transaction_check_provider.transaction_retrieved = []
    pass
# NEED TO CREATE A STANDARD ABI AND STUFF TO PULL FROM/SAMPLE EVENTS
