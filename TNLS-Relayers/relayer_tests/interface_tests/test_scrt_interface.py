import sys

import pytest

from scrt_interface import SCRTInterface


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
    return fake_provider


@pytest.fixture
def sample_contract_function_factory():
    """
    Fixture that provides a factory for basic contract functions that
    return their parameters as a dict.
    """

    pass


def test_transaction_builder_good(provider_privkey_address, sample_contract_function_factory):
    # Tests that transaction signing and sending works as expected
    pass


def test_transaction_builder_bad_address_from(fake_provider, sample_contract_function_factory):
    # Confirms that when the interface is created with a bad address, it raises an error
    pass


def test_transaction_builder_bad_address_to(fake_provider, sample_contract_function_factory):
    # Confirms that when a transaction is created with a bad destination address, it raises an error
    pass


def test_transaction_builder_bad_private_key(fake_provider, sample_contract_function_factory):
    # Confirms that when an interface is created with a bad private key, it raises an error on transaction creation
    pass


def test_transaction_builder_mismatched_private_key(fake_provider, sample_contract_function_factory):
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
