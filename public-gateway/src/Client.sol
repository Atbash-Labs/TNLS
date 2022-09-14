// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import {Util} from "../src/Util.sol";
import {IGateway} from "../src/interfaces/IGateway.sol";
import "../src/interfaces/IClient.sol";

contract Client is IClient {
    using Util for Util.Task;
    using Util for Util.ExecutionInfo;

    /// @notice Emitted when we recieve callback for our result of the computation
    event ComputedResult(uint256 indexed taskId, bytes indexed result);

    /*//////////////////////////////////////////////////////////////
                             Constructor
    //////////////////////////////////////////////////////////////*/

    address public GatewayAddress;

    constructor(address _gatewayAddress) {
        GatewayAddress = _gatewayAddress;
    }

    /*//////////////////////////////////////////////////////////////
                        New Task and Send Call
    //////////////////////////////////////////////////////////////*/

    function newTask(
        address _callbackAddress,
        bytes4 _callbackSelector,
        address _userAddress,
        string memory _sourceNetwork,
        string memory _routingInfo,
        bytes32 _payloadHash
    )
        internal
        pure
        returns (Util.Task memory)
    {
        return Util.Task(_callbackAddress, _callbackSelector, _userAddress, _sourceNetwork, _routingInfo, _payloadHash, false);
    }

    /// @param _userAddress  Task Id of the computation
    /// @param _sourceNetwork computed result
    /// @param _routingInfo The second stored number input
    /// @param _payloadHash The second stored number input
    /// @param _info ExecutionInfo struct
    function send(
        address _userAddress,
        string memory _sourceNetwork,
        string memory _routingInfo,
        bytes32 _payloadHash,
        Util.ExecutionInfo memory _info
    )
        public
    {
        Util.Task memory newtask;

        newtask = newTask(address(this), this.callback.selector, _userAddress, _sourceNetwork, _routingInfo, _payloadHash);

        IGateway(GatewayAddress).preExecution(newtask, _info);
    }

    /*//////////////////////////////////////////////////////////////
                               Callback
    //////////////////////////////////////////////////////////////*/

    /// @param _taskId  Task Id of the computation
    /// @param _result computed result
    /// @param _result The second stored number input
    function callback(uint256 _taskId, bytes memory _result) external {
        emit ComputedResult(_taskId, _result);
    }
}