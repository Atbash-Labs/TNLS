// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Script.sol";
import {Gateway} from "../src/Gateway.sol";
import {Client} from "../src/Client.sol";

contract ContractScript is Script {
    function setUp() public {}

    Gateway gatewayAddress;

    function run() public {
        vm.startBroadcast();

        gatewayAddress = new Gateway();

        vm.stopBroadcast();
    }
}