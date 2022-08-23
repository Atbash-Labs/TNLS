import sys
from logging import WARNING

import pytest

from base_interface import BaseChainInterface
from scrt_interface import SCRTInterface, SCRTContract


@pytest.fixture
def filter_out_hashes():
    """
    Fixture used for filtering out hashes from a list of transactions.
    """

    def _filter_out_hashes(txns):
        return [txn['hash'] for txn in txns]

    return _filter_out_hashes


@pytest.fixture
def provider_privkey_address(monkeypatch):
    """
    Fixture that provides a mock scrt backend as well as a private key and address
    for an account on that backend

    """
    pass


@pytest.fixture
def fake_provider(monkeypatch):
    """
    Fixture that provides a mock scrt backend that doesn't process transactions
    """

    class FakeProvider:
        def wallet(self, _priv_key):
            return []

        pass

    return FakeProvider()
    pass


@pytest.fixture
def no_transaction_check_provider(fake_provider, monkeypatch):
    """
    Fixture that augments the previous one to also provide sample blocks and transactions
    with a user-settable transaction store
    """
    fake_provider.transaction_retrieved = []

    class FakeTendermint:
        def __init__(self):
            pass

        def block_info(self):
            return {'block': {'header': {'height': 0}}}

    class FakeTxn:
        def __init__(self, log):
            self.logs = log

    class FakeSearchResults:
        def __init__(self):
            self.txs = [FakeTxn(tx) for tx in fake_provider.transaction_retrieved]

    class FakeTx:
        def __init__(self):
            self.txs = []
            pass

        def search(self, **kwargs):
            self.txs = []
            txs = FakeSearchResults().txs
            for tx in txs:
                if tx.logs['from'] == kwargs['options']['message.sender']:
                    self.txs.append(tx)
            return self

    fake_provider.tendermint = FakeTendermint()
    fake_provider.tx = FakeTx()
    return fake_provider


def test_transaction_builder_good(provider_privkey_address):
    # Tests that transaction signing and sending works as expected
    pass


def test_transaction_builder_bad_address_from(fake_provider):
    # Confirms that when the interface is created with a bad address, it raises an error
    pass


def test_transaction_builder_bad_address_to(fake_provider):
    # Confirms that when a transaction is created with a bad destination address, it raises an error
    pass


def test_transaction_builder_bad_private_key(fake_provider):
    # Confirms that when an interface is created with a bad private key, it raises an error on transaction creation
    pass


def test_transaction_builder_mismatched_private_key(fake_provider):
    # Confirms that when an interface is created with the wrong private key for an address
    # it raises an error on transaction creation
    pass


def test_correct_txn_filtering_one_in(no_transaction_check_provider, filter_out_hashes):
    # Tests that get_transactions correctly finds a single matching transaction
    no_transaction_check_provider.transaction_retrieved = [
        {'from': '0x0', 'to': '0x1', 'hash': '0x2'},
    ]
    interface = SCRTInterface(address='0x0', provider=no_transaction_check_provider)
    assert filter_out_hashes(interface.get_transactions(address='0x0')) == ['0x2']


def test_correct_txn_filtering_one_out(no_transaction_check_provider, filter_out_hashes):
    # Tests that get_transactions correctly ignores a single mismatching transaction
    no_transaction_check_provider.transaction_retrieved = [
        {'from': '0x1', 'to': '0x1', 'hash': '0x2'},
    ]
    interface = SCRTInterface(address='0x0', provider=no_transaction_check_provider)
    assert filter_out_hashes(interface.get_transactions(address='0x0')) == []


def test_correct_txn_filtering_many(no_transaction_check_provider, filter_out_hashes):
    # Tests that get_transactions correctly finds multiple matching transactions among mismatched ones
    no_transaction_check_provider.transaction_retrieved = [
        {'from': '0x1', 'to': '0x1', 'hash': '0x2'},
        {'from': '0x1', 'to': '0x1', 'hash': '0x3'},
        {'from': '0x1', 'to': '0x1', 'hash': '0x4'},
        {'from': '0x0', 'to': '0x1', 'hash': '0x5'},
        {'from': '0x0', 'to': '0x1', 'hash': '0x6'},
        {'from': '0x0', 'to': '0x1', 'hash': '0x7'},
    ]
    interface = SCRTInterface(address='0x0', provider=no_transaction_check_provider)
    assert filter_out_hashes(interface.get_transactions(address='0x0')) == ['0x5', '0x6', '0x7']


@pytest.fixture
def address_and_abi_of_contract(provider_privkey_address):
    """
    Creates a contract with the below code (scrtified)
    , deploys it, and returns it, it's address, and ABI, and code_hash.
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

    pass


@pytest.mark.skipif(sys.platform.startswith('win'), reason="does not run on windows")
def test_basic_contract_init(provider_privkey_address, address_and_abi_of_contract):
    # Confirms that the scrtContract interface initializes correctly
    pass


@pytest.mark.skipif(sys.platform.startswith('win'), reason="does not run on windows")
def test_event_getter(provider_privkey_address, address_and_abi_of_contract):
    # Confirms that the scrtContract interface correctly retrieves events
    pass


@pytest.mark.skipif(sys.platform.startswith('win'), reason="does not run on windows")
def test_function_call(provider_privkey_address, address_and_abi_of_contract):
    # Confirms that the scrtContract interface correctly calls functions
    pass


@pytest.fixture
def contract_schema_for_construction(request):
    sample_abi_path = f'{request.path.parent}/sample_scrt_abi.json'
    with open(sample_abi_path) as f:
        return f.read()


@pytest.fixture
def fake_interface_provider():
    class FakeWasm:
        def __init__(self):
            self.contract_execute_msg = dict

    class FakeInterfaceProvider(BaseChainInterface):
        def __init__(self):
            self.address = "0x0"
            self.wasm = FakeWasm()
            self.wasm.contract_execute_msg = dict
            pass

        def get_transactions(self, _address):
            pass

        def sign_and_send_transaction(self, tx):
            return tx

    return FakeInterfaceProvider


def test_basic_txn_construction(fake_interface_provider, contract_schema_for_construction):
    fake_contract = SCRTContract(address="0x1", abi=contract_schema_for_construction,
                                 interface=fake_interface_provider())
    assert fake_contract.call_function("function_1", 1, 2) == {'contract_address': '0x1',
                                                               'handle_msg': {'function_1': {'a': 1, 'b': 2}},
                                                               'sender_address': '0x0'}


def test_too_many_args(fake_interface_provider, contract_schema_for_construction, caplog):
    fake_contract = SCRTContract(address="0x1", abi=contract_schema_for_construction,
                                 interface=fake_interface_provider())
    with caplog.at_level(WARNING):
        assert fake_contract.call_function("function_1", 1, 2, 3) == {'contract_address': '0x1',
                                                                      'handle_msg': {'function_1': {'a': 1, 'b': 2}},
                                                                      'sender_address': '0x0'}
    assert "Expected 2 arguments but got 3" in caplog.text


def test_too_few_args(fake_interface_provider, contract_schema_for_construction, caplog):
    fake_contract = SCRTContract(address="0x1", abi=contract_schema_for_construction,
                                 interface=fake_interface_provider())
    with caplog.at_level(WARNING):
        assert fake_contract.call_function("function_2", 1, 2) == {'contract_address': '0x1',
                                                                   'handle_msg': {
                                                                       'function_2': {'a': 1, 'b': 2, 'c': ''}},
                                                                   'sender_address': '0x0'}
    assert "Expected 3 arguments but got 2" in caplog.text