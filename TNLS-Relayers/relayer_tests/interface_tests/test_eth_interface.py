import pytest
from web3 import Web3


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
    yield web3provider

@pytest.fixture
def fixed_block_and_receipts(non_send_provider, monkeypatch):
    def mock_get_block(_block_number, _full_transactions=False):
        return {
            'transactions': [
                #fill later
                '1',
            ]}
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
                    #fill later
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
                        #fill later
                    ],
                }

            }
    monkeypatch.setattr(non_send_provider.eth, 'get_block', mock_get_block)
    monkeypatch.setattr(non_send_provider.eth, 'get_transaction_receipt', mock_get_transaction_receipt)


#NEED TO CREATE A STANDARD ABI AND STUFF TO PULL FROM/SAMPLE EVENTS