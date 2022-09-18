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

        /// ----    DO IT THISSS WAY -------  //////
        
        // GatewayDub gatewayAddress;
        // ClientDub clientAddress;
        // uint256 privKey = vm.envUint("PRIVATE_KEY");
        // address deployer = vm.rememberKey(privKey);
        // uint256 verificationAddress = vm.envAddress("SECRET_DERIVED_ETHADDRESS");
        // string memory route = "secret";

        // // Update the route with with masterVerificationKey signature
        // bytes32 routeHash = getRouteHash(route, verificationAddress);
        // bytes32 ethSignedMessageHash = getEthSignedMessageHash(routeHash);

        // (uint8 v, bytes32 r, bytes32 s) = vm.sign(privKey, ethSignedMessageHash);
        // bytes memory sig = abi.encodePacked(r, s, v);

        // vm.startBroadcast();
        
        // gatewayAddress = new GatewayDub();
        // clientAddress = new ClientDub(address(gatewayAddress));
        
        // console2.logAddress(address(gatewayAddress));
        // console2.logAddress(address(clientAddress));
        // console2.logAddress(deployer);

        // gatewayAddress.initialize(deployer);

        // gatewayAddress.updateRoute(route, verificationAddress, sig);

        // vm.stopBroadcast();


    }
}
