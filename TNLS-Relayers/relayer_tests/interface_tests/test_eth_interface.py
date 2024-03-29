import sys

import pytest
from eth_tester import EthereumTester, PyEVMBackend
from web3 import Web3
from web3.exceptions import InvalidAddress

from eth_interface import EthInterface, EthContract


@pytest.fixture
def filter_out_hashes():
    """
    Fixture used for filtering out hashes from a list of transactions.
    """

    def _filter_out_hashes(txns):
        return [txn['transactionHash'] for txn in txns]

    return _filter_out_hashes


@pytest.fixture
def provider_privkey_address(monkeypatch):
    """
    Fixture that provides a mock eth backend as well as a private key and address
    for an account on that backend

    """
    base_provider = Web3.EthereumTesterProvider(EthereumTester(backend=PyEVMBackend()))
    base_priv_key = base_provider.ethereum_tester.backend.account_keys[0]
    base_addr = base_provider.ethereum_tester.get_accounts()[0]
    web3provider = Web3(base_provider)
    yield web3provider, base_priv_key, base_addr


@pytest.fixture
def fake_provider(monkeypatch):
    """
    Fixture that provides a mock eth backend that doesn't process transactions
    """
    web3provider = Web3(Web3.EthereumTesterProvider())
    yield web3provider


@pytest.fixture
def no_transaction_check_provider(fake_provider, monkeypatch):
    """
    Fixture that augments the previous one to also provide sample blocks and transactions
    with a user-settable transaction store
    """
    fake_provider.transaction_retrieved = []

    def _mock_get_block(_block_number, **_kwargs):
        return {
            'transactions': fake_provider.transaction_retrieved
        }

    def _mock_get_transaction_receipt(tx_hash):
        return {
            'status': 1,
            'transactionHash': tx_hash,
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

    monkeypatch.setattr(fake_provider.eth, 'get_block', _mock_get_block)
    monkeypatch.setattr(fake_provider.eth, 'get_transaction_receipt', _mock_get_transaction_receipt)
    return fake_provider


@pytest.fixture
def sample_contract_function_factory():
    """
    Fixture that provides a factory for basic contract functions that
    return their parameters as a dict.
    """

    def _sample_contract_function(address):
        def helper(data):
            class ContractFunction:
                def buildTransaction(self, params):
                    transact_dict = {
                        'data': data,
                        'to': address,
                    }
                    transact_dict.update(params)
                    return transact_dict

            return ContractFunction()

        return helper

    return _sample_contract_function


def test_transaction_builder_good(provider_privkey_address, sample_contract_function_factory):
    # Tests that transaction creation, signing and sending works as expected
    provider, sample_private_key, sample_address = provider_privkey_address

    interface = EthInterface(address=sample_address, provider=provider,
                             private_key=sample_private_key)
    transaction = interface.create_transaction(sample_contract_function_factory(sample_address), '0x123')
    transaction.pop('gasPrice')
    assert transaction == {
        'data': '0x123',
        'from': sample_address,
        'nonce': 0,
        'gas': 200000,
        'to': sample_address,
    }
    transaction['gasPrice'] = 1000000000000
    # string is saved tx_hash
    assert str(Web3.toInt(interface.sign_and_send_transaction(
        transaction))) == '65179427771983584748417465488745607597763943977140432452056461044412680211905'


def test_transaction_builder_bad_address_from(fake_provider, sample_contract_function_factory):
    # Confirms that when the interface is created with a bad address, it raises an error
    sample_private_key = '8da4ef21b864d2cc526dbdb2a120bd2874c36c9d0a1fb7f8c63d7f7a8b41de8f'
    sample_address = '0x0'

    # Note:  the below privkeys/addrs are published online

    interface = EthInterface(address=sample_address, provider=fake_provider,
                             private_key=sample_private_key)
    with pytest.raises(InvalidAddress):
        _ = interface.create_transaction(sample_contract_function_factory(sample_address), '0x123')


def test_transaction_builder_bad_address_to(fake_provider, sample_contract_function_factory):
    # Confirms that when a transaction is created with a bad destination address, it raises an error
    sample_private_key = '8da4ef21b864d2cc526dbdb2a120bd2874c36c9d0a1fb7f8c63d7f7a8b41de8f'
    sample_address = '0x63FaC9201494f0bd17B9892B9fae4d52fe3BD377'

    interface = EthInterface(address=sample_address, provider=fake_provider,
                             private_key=sample_private_key)
    transaction = interface.create_transaction(sample_contract_function_factory(sample_address), '0x123')
    transaction.pop('gasPrice')
    assert transaction == {
        'data': '0x123',
        'from': sample_address,
        'nonce': 0,
        'gas': 200000,
        'to': sample_address,
    }
    transaction['gasPrice'] = 1
    transaction['to'] = '0x0'
    with pytest.raises(TypeError) as excinfo:
        interface.sign_and_send_transaction(transaction)
    assert "invalid fields" in str(excinfo.value)
    assert "{'to'" in str(excinfo.value)


def test_transaction_builder_bad_private_key(fake_provider, sample_contract_function_factory):
    # Confirms that when an interface is created with a bad private key, it raises an error on transaction creation
    sample_private_key = ''
    sample_address = '0x63FaC9201494f0bd17B9892B9fae4d52fe3BD377'

    interface = EthInterface(address=sample_address, provider=fake_provider,
                             private_key=sample_private_key)
    transaction = interface.create_transaction(sample_contract_function_factory(sample_address), '0x123')
    transaction.pop('gasPrice')
    assert transaction == {
        'data': '0x123',
        'from': sample_address,
        'nonce': 0,
        'gas': 200000,
        'to': sample_address,
    }
    transaction['gasPrice'] = 1
    transaction['to'] = '0x0'
    with pytest.raises(ValueError) as excinfo:
        interface.sign_and_send_transaction(transaction)
    assert "instead of 0 bytes" in str(excinfo.value)
    pass


def test_transaction_builder_mismatched_private_key(fake_provider, sample_contract_function_factory):
    # Confirms that when an interface is created with the wrong bad private key,
    # it raises an error on transaction creation
    sample_private_key = '8da4ef21b864d2cc526dbdb2a120bd2874c36c9d0a1fb7f8c63d7f7a8b41de8e'
    sample_address = '0x63FaC9201494f0bd17B9892B9fae4d52fe3BD377'

    # Note:  the below privkeys/addrs are published online

    interface = EthInterface(address=sample_address, provider=fake_provider,
                             private_key=sample_private_key)
    transaction = interface.create_transaction(sample_contract_function_factory(sample_address), '0x123')
    transaction.pop('gasPrice')
    assert transaction == {
        'data': '0x123',
        'from': sample_address,
        'nonce': 0,
        'gas': 200000,
        'to': sample_address,
    }
    transaction['gasPrice'] = 1
    with pytest.raises(TypeError) as excinfo:
        interface.sign_and_send_transaction(transaction)
    assert 'from field must match key' in str(excinfo.value)


def test_correct_txn_filtering_one_in(no_transaction_check_provider, filter_out_hashes):
    # Tests that get_last_txs correctly finds a single matching transaction
    no_transaction_check_provider.transaction_retrieved = [
        {'from': '0x0', 'to': '0x1', 'hash': '0x2'},
    ]
    interface = EthInterface(address='0x0', provider=no_transaction_check_provider)
    assert filter_out_hashes(interface.get_last_txs(block_number=1, address='0x0')) == ['0x2']

@pytest.mark.skip(reason="This test is broken")
def test_correct_txn_filtering_one_out(no_transaction_check_provider, filter_out_hashes):
    # Tests that get_last_txs correctly ignores a single mismatching transaction
    no_transaction_check_provider.transaction_retrieved = [
        {'from': '0x1', 'to': '0x1', 'hash': '0x2'},
    ]
    interface = EthInterface(address='0x0', provider=no_transaction_check_provider)
    assert filter_out_hashes(interface.get_last_txs(block_number=1, address='0x0')) == []


@pytest.mark.skip(reason="This test is broken")
def test_correct_txn_filtering_many(no_transaction_check_provider, filter_out_hashes):
    # Tests that get_last_txs correctly finds multiple matching transactions among mismatched ones
    no_transaction_check_provider.transaction_retrieved = [
        {'from': '0x1', 'to': '0x1', 'hash': '0x2'},
        {'from': '0x1', 'to': '0x1', 'hash': '0x3'},
        {'from': '0x1', 'to': '0x1', 'hash': '0x4'},
        {'from': '0x0', 'to': '0x1', 'hash': '0x5'},
        {'from': '0x0', 'to': '0x1', 'hash': '0x6'},
        {'from': '0x0', 'to': '0x1', 'hash': '0x7'},
    ]
    interface = EthInterface(address='0x0', provider=no_transaction_check_provider)
    assert filter_out_hashes(interface.get_last_txs(block_number=1, address='0x0')) == ['0x5', '0x6', '0x7']


@pytest.fixture
def address_and_abi_of_contract(provider_privkey_address):
    """
    Creates a contract with the below code, deploys it, and returns it, it's address, and ABI.
    """

    #
    # pragma solidity^0.5.3;
    #
    # contract Foo {
    #
    #     string public bar;
    #     event barred(string _bar);
    #
    #     constructor() public {
    #         bar = "hello world";
    #     }
    #
    #     function setBar(string memory _bar) public {
    #         bar = _bar;
    #         emit barred(_bar);
    #     }
    #
    # }

    deploy_address = Web3.EthereumTesterProvider().ethereum_tester.get_accounts()[0]

    abi = """[{"anonymous":false,"inputs":[{"indexed":false,"name":"_bar","type":"string"}],"name":"barred","type":"event"},{"constant":false,"inputs":[{"name":"_bar","type":"string"}],"name":"setBar","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"inputs":[],"payable":false,"stateMutability":"nonpayable","type":"constructor"},{"constant":true,"inputs":[],"name":"bar","outputs":[{"name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"}]"""  # noqa: E501
    # This bytecode is the output of compiling with
    # solc version:0.5.3+commit.10d17f24.Emscripten.clang
    bytecode = """608060405234801561001057600080fd5b506040805190810160405280600b81526020017f68656c6c6f20776f726c640000000000000000000000000000000000000000008152506000908051906020019061005c929190610062565b50610107565b828054600181600116156101000203166002900490600052602060002090601f016020900481019282601f106100a357805160ff19168380011785556100d1565b828001600101855582156100d1579182015b828111156100d05782518255916020019190600101906100b5565b5b5090506100de91906100e2565b5090565b61010491905b808211156101005760008160009055506001016100e8565b5090565b90565b6103bb806101166000396000f3fe608060405234801561001057600080fd5b5060043610610053576000357c01000000000000000000000000000000000000000000000000000000009004806397bc14aa14610058578063febb0f7e14610113575b600080fd5b6101116004803603602081101561006e57600080fd5b810190808035906020019064010000000081111561008b57600080fd5b82018360208201111561009d57600080fd5b803590602001918460018302840111640100000000831117156100bf57600080fd5b91908080601f016020809104026020016040519081016040528093929190818152602001838380828437600081840152601f19601f820116905080830192505050505050509192919290505050610196565b005b61011b61024c565b6040518080602001828103825283818151815260200191508051906020019080838360005b8381101561015b578082015181840152602081019050610140565b50505050905090810190601f1680156101885780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b80600090805190602001906101ac9291906102ea565b507f5f71ad82e16f082de5ff496b140e2fbc8621eeb37b36d59b185c3f1364bbd529816040518080602001828103825283818151815260200191508051906020019080838360005b8381101561020f5780820151818401526020810190506101f4565b50505050905090810190601f16801561023c5780820380516001836020036101000a031916815260200191505b509250505060405180910390a150565b60008054600181600116156101000203166002900480601f0160208091040260200160405190810160405280929190818152602001828054600181600116156101000203166002900480156102e25780601f106102b7576101008083540402835291602001916102e2565b820191906000526020600020905b8154815290600101906020018083116102c557829003601f168201915b505050505081565b828054600181600116156101000203166002900490600052602060002090601f016020900481019282601f1061032b57805160ff1916838001178555610359565b82800160010185558215610359579182015b8281111561035857825182559160200191906001019061033d565b5b509050610366919061036a565b5090565b61038c91905b80821115610388576000816000905550600101610370565b5090565b9056fea165627a7a72305820ae6ca683d45ee8a71bba45caee29e4815147cd308f772c853a20dfe08214dbb50029"""  # noqa: E501

    # Create our contract class.
    foo_contract = provider_privkey_address[0].eth.contract(abi=abi, bytecode=bytecode)
    # issue a transaction to deploy the contract.
    tx_hash = foo_contract.constructor().transact(
        {
            "from": deploy_address,
            'gas': 1000000,
        }
    )
    # wait for the transaction to be mined
    tx_receipt = provider_privkey_address[0].eth.wait_for_transaction_receipt(tx_hash, 180)
    # instantiate and return an instance of our contract.
    return tx_receipt.contractAddress, abi, foo_contract(tx_receipt.contractAddress)


@pytest.fixture
def address_and_abi_of_contract_full_interface(provider_privkey_address):
    """
    Creates a contract with the below code, deploys it, and returns it, it's address, and ABI.
    """

    deploy_address = Web3.EthereumTesterProvider().ethereum_tester.get_accounts()[0]

    abi = """[
	{
		"anonymous": false,
		"inputs": [
			{
				"indexed": true,
				"internalType": "uint256",
				"name": "task_id",
				"type": "uint256"
			},
			{
				"indexed": false,
				"internalType": "string",
				"name": "source_network",
				"type": "string"
			},
			{
				"indexed": false,
				"internalType": "bytes",
				"name": "payload",
				"type": "bytes"
			},
			{
				"indexed": false,
				"internalType": "bytes32",
				"name": "payload_hash",
				"type": "bytes32"
			},
			{
				"indexed": false,
				"internalType": "bytes",
				"name": "payload_signature",
				"type": "bytes"
			},
			{
				"indexed": false,
				"internalType": "bytes",
				"name": "result",
				"type": "bytes"
			},
			{
				"indexed": false,
				"internalType": "bytes32",
				"name": "result_hash",
				"type": "bytes32"
			},
			{
				"indexed": false,
				"internalType": "bytes",
				"name": "result_signature",
				"type": "bytes"
			},
			{
				"indexed": false,
				"internalType": "bytes32",
				"name": "packet_hash",
				"type": "bytes32"
			},
			{
				"indexed": false,
				"internalType": "bytes",
				"name": "packet_signature",
				"type": "bytes"
			}
		],
		"name": "logCompletedTask",
		"type": "event"
	},
	{
		"inputs": [
			{
				"internalType": "uint256",
				"name": "_taskId",
				"type": "uint256"
			},
			{
				"internalType": "string",
				"name": "_sourceNetwork",
				"type": "string"
			},
			{
				"components": [
					{
						"internalType": "bytes",
						"name": "payload",
						"type": "bytes"
					},
					{
						"internalType": "bytes32",
						"name": "payload_hash",
						"type": "bytes32"
					},
					{
						"internalType": "bytes",
						"name": "payload_signature",
						"type": "bytes"
					},
					{
						"internalType": "bytes",
						"name": "result",
						"type": "bytes"
					},
					{
						"internalType": "bytes32",
						"name": "result_hash",
						"type": "bytes32"
					},
					{
						"internalType": "bytes",
						"name": "result_signature",
						"type": "bytes"
					},
					{
						"internalType": "bytes32",
						"name": "packet_hash",
						"type": "bytes32"
					},
					{
						"internalType": "bytes",
						"name": "packet_signature",
						"type": "bytes"
					}
				],
				"internalType": "struct Util.PostExecutionInfo",
				"name": "_info",
				"type": "tuple"
			}
		],
		"name": "postExecution",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	}
]"""
    bytecode = "608060405234801561001057600080fd5b506106e4806100206000396000f3fe608060405234801561001057600080fd5b506004361061002b5760003560e01c806338157d9a14610030575b600080fd5b61004a60048036038101906100459190610480565b61004c565b005b827fa6959e124e12197da17aa251aed434d16737f5c0a70a86e4ccc26f957d49241483836000015184602001518560400151866060015187608001518860a001518960c001518a60e001516040516100ac999897969594939291906105f7565b60405180910390a2505050565b6000604051905090565b600080fd5b600080fd5b6000819050919050565b6100e0816100cd565b81146100eb57600080fd5b50565b6000813590506100fd816100d7565b92915050565b600080fd5b600080fd5b6000601f19601f8301169050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b6101568261010d565b810181811067ffffffffffffffff821117156101755761017461011e565b5b80604052505050565b60006101886100b9565b9050610194828261014d565b919050565b600067ffffffffffffffff8211156101b4576101b361011e565b5b6101bd8261010d565b9050602081019050919050565b82818337600083830152505050565b60006101ec6101e784610199565b61017e565b90508281526020810184848401111561020857610207610108565b5b6102138482856101ca565b509392505050565b600082601f8301126102305761022f610103565b5b81356102408482602086016101d9565b91505092915050565b600080fd5b600080fd5b600067ffffffffffffffff82111561026e5761026d61011e565b5b6102778261010d565b9050602081019050919050565b600061029761029284610253565b61017e565b9050828152602081018484840111156102b3576102b2610108565b5b6102be8482856101ca565b509392505050565b600082601f8301126102db576102da610103565b5b81356102eb848260208601610284565b91505092915050565b6000819050919050565b610307816102f4565b811461031257600080fd5b50565b600081359050610324816102fe565b92915050565b6000610100828403121561034157610340610249565b5b61034c61010061017e565b9050600082013567ffffffffffffffff81111561036c5761036b61024e565b5b610378848285016102c6565b600083015250602061038c84828501610315565b602083015250604082013567ffffffffffffffff8111156103b0576103af61024e565b5b6103bc848285016102c6565b604083015250606082013567ffffffffffffffff8111156103e0576103df61024e565b5b6103ec848285016102c6565b606083015250608061040084828501610315565b60808301525060a082013567ffffffffffffffff8111156104245761042361024e565b5b610430848285016102c6565b60a08301525060c061044484828501610315565b60c08301525060e082013567ffffffffffffffff8111156104685761046761024e565b5b610474848285016102c6565b60e08301525092915050565b600080600060608486031215610499576104986100c3565b5b60006104a7868287016100ee565b935050602084013567ffffffffffffffff8111156104c8576104c76100c8565b5b6104d48682870161021b565b925050604084013567ffffffffffffffff8111156104f5576104f46100c8565b5b6105018682870161032a565b9150509250925092565b600081519050919050565b600082825260208201905092915050565b60005b8381101561054557808201518184015260208101905061052a565b83811115610554576000848401525b50505050565b60006105658261050b565b61056f8185610516565b935061057f818560208601610527565b6105888161010d565b840191505092915050565b600081519050919050565b600082825260208201905092915050565b60006105ba82610593565b6105c4818561059e565b93506105d4818560208601610527565b6105dd8161010d565b840191505092915050565b6105f1816102f4565b82525050565b6000610120820190508181036000830152610612818c61055a565b90508181036020830152610626818b6105af565b9050610635604083018a6105e8565b818103606083015261064781896105af565b9050818103608083015261065b81886105af565b905061066a60a08301876105e8565b81810360c083015261067c81866105af565b905061068b60e08301856105e8565b81810361010083015261069e81846105af565b90509a995050505050505050505056fea264697066735822122094f38c0a022e22b5e1399f789645902c30a4fe69496fc563dbac325f471cc3dd64736f6c634300080a0033"
    # Create our contract class.
    foo_contract = provider_privkey_address[0].eth.contract(abi=abi, bytecode=bytecode)
    # issue a transaction to deploy the contract.
    tx_hash = foo_contract.constructor().transact(
        {
            "from": deploy_address,
            'gas': 1000000,
        }
    )
    # wait for the transaction to be mined
    tx_receipt = provider_privkey_address[0].eth.wait_for_transaction_receipt(tx_hash, 180)
    # instantiate and return an instance of our contract.
    return tx_receipt.contractAddress, abi, foo_contract(tx_receipt.contractAddress)


@pytest.mark.skipif(sys.platform.startswith('win'), reason="does not run on windows")
def test_basic_contract_init(provider_privkey_address, address_and_abi_of_contract):
    # Confirms that the ethContract interface initializes correctly
    provider, private_key, address = provider_privkey_address
    interface = EthInterface(address=address,
                             provider=provider,
                             private_key=private_key)
    _ = EthContract(interface=interface, address=address_and_abi_of_contract[0],
                    abi=address_and_abi_of_contract[1])


@pytest.mark.skipif(sys.platform.startswith('win'), reason="does not run on windows")
def test_event_getter(provider_privkey_address, address_and_abi_of_contract):
    # Confirms that the ethContract interface correctly retrieves events
    provider, private_key, address = provider_privkey_address
    interface = EthInterface(address=address,
                             private_key=private_key,
                             provider=provider)
    contract = EthContract(interface=interface, address=address_and_abi_of_contract[0],
                           abi=address_and_abi_of_contract[1])
    foo_contract = address_and_abi_of_contract[2]
    tx_hash = foo_contract.functions.setBar("testing contracts is easy", ).transact(
        {
            "from": address,
            'gas': 1000000,
        }
    )
    receipt = provider.eth.wait_for_transaction_receipt(tx_hash, 180)
    evt_logs = contract.parse_event_from_txn('barred', receipt)
    assert evt_logs != []
    assert evt_logs[0].task_data['_bar'] == "testing contracts is easy"
    tx_hash = foo_contract.constructor().transact(
        {
            "from": address,
            'gas': 1000000,
        }
    )
    # wait for the transaction to be mined
    tx_receipt = provider_privkey_address[0].eth.wait_for_transaction_receipt(tx_hash, 180)
    evt_logs = contract.parse_event_from_txn('barred', tx_receipt)
    assert evt_logs == []


@pytest.mark.skipif(sys.platform.startswith('win'), reason="does not run on windows")
def test_function_call(provider_privkey_address, address_and_abi_of_contract):
    # Confirms that the ethContract interface correctly calls functions
    provider, private_key, address = provider_privkey_address
    interface = EthInterface(address=address,
                             private_key=private_key,
                             provider=provider)
    contract = EthContract(interface=interface, address=address_and_abi_of_contract[0],
                           abi=address_and_abi_of_contract[1])
    foo_contract = address_and_abi_of_contract[2]
    tx = contract.call_function('setBar', '{"_bar":"testing contracts is easy"}')
    # verify that the log's data matches the expected value
    receipt = provider.eth.wait_for_transaction_receipt(tx, 180)
    logs = list(foo_contract.events.barred.getLogs())
    assert len(logs) == 1
    event = logs[0]
    assert event.blockHash == receipt.blockHash
    assert event.__dict__['args']['_bar'] == 'testing contracts is easy'


@pytest.mark.skipif(sys.platform.startswith('win'), reason="does not run on windows")
def test_function_call_with_real_interface(provider_privkey_address, address_and_abi_of_contract_full_interface):
    # Confirms that the ethContract interface correctly calls functions
    provider, private_key, address = provider_privkey_address
    interface = EthInterface(address=address,
                             private_key=private_key,
                             provider=provider)
    contract = EthContract(interface=interface, address=address_and_abi_of_contract_full_interface[0],
                           abi=address_and_abi_of_contract_full_interface[1])
    foo_contract = address_and_abi_of_contract_full_interface[2]
    input = '[ 1,' \
            ' "secret",' \
            ' ["0x3078363136343634323036313230363237353665363336383230366636363230373337343735363636363030303' \
            '03030303030303030303030303030303030303030","0x8a5efa54dcbe3378b7910b0bba0c461fbc' \
            '85a0928ac485730fedf4c3f4158248","0xd4651f38497602c5c287aff4aa79afa7f3b82abe862151b0bcc7' \
            'c539b2f9f5f24ca54a148aef19b9ed7e7fd2f84c72fc149eabb32c735d704fdbe6928dda8eef1c","0x3078373' \
            '3366636643635323037323635373337353663373430303030303030303030303030303030303030303030303030' \
            '3030303030303030303030303030303030","0xe764ca2c3aae5dc9c65410ab1bb6b48aaee607cbdf7a2308091a' \
            '71b2a9d16ee4","0x8f02e349b0cb8136cc534c46a1fb483fda66456750ac66442155d050154dc84b390212216c6' \
            '9bd3ec62e6ef4299395c1b2577bec7ce11aea85ac1c62f52b92f21c","0xe764ca2c3aae5dc9c65410ab1bb6b48aa' \
            'ee607cbdf7a2308091a71b2a9d16ee4","0x8f02e349b0cb8136cc534c46a1fb483fda66456750ac66442155d0501' \
            '54dc84b390212216c69bd3ec62e6ef4299395c1b2577bec7ce11aea85ac1c62f52b92f21c"]]'
    tx = contract.call_function('postExecution', input)
    # verify that the log's data matches the expected value
    receipt = provider.eth.wait_for_transaction_receipt(tx, 180)
    logs = list(foo_contract.events.logCompletedTask.getLogs())
    assert len(logs) == 1
    event = logs[0]
    assert event.blockHash == receipt.blockHash
    assert event.__dict__['args']['source_network'] == 'secret'
