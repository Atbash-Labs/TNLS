// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/console2.sol";
import "forge-std/Script.sol";
import {Gateway} from "../src/Gateway.sol";
import {Client} from "../src/Client.sol";

contract DeployScript is Script {
    function setUp() public {}

    Gateway gatewayAddress;
    Client clientAddress;

    function run() public {
        vm.startBroadcast();

        gatewayAddress = new Gateway();
        clientAddress = new Client(address(gatewayAddress));
        
        console2.logAddress(address(gatewayAddress));
        console2.logAddress(address(clientAddress));

        vm.stopBroadcast();
    }
}