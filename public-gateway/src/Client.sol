// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;
import {Util} from "../src/Util.sol";
import {IGateway} from "../src/interfaces/IGateway.sol";

contract Client {

    using Util for Util.Task;
    using Util for Util.ExecutionInfo;


    /// @notice Emitted when we recieve callback for our result of the computation
    event FinalResultWithInputs(uint256 _taskId, bytes _result);

    /*//////////////////////////////////////////////////////////////
                              Task
    //////////////////////////////////////////////////////////////*/

    function newTask(
        address _callbackAddress,
        bytes4 _callbackSelector,
        address _userAddress,
        string memory _sourceNetwork,
        string memory _routingInfo,
        bytes32 _payloadHash
    )
        public
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
    function send(address _userAddress, string memory _sourceNetwork, string memory _routingInfo, bytes32 _payloadHash, Util.ExecutionInfo memory _info) internal {
      
      // address _callbackAddress;
      // bytes4 _callbackSelector;

      Util.Task memory newtask;

      newtask = newTask(address(this), this.callback.selector, _userAddress, _sourceNetwork, _routingInfo, _payloadHash);

      // need to find a way to fix the calling  
      // IGateway.preExecution(newtask, _info);


      // take in the task struct and executioninfo struct as arguments

      // call with address and callbackselector

    }


    /// @param _taskId  Task Id of the computation
    /// @param _result computed result
    /// @param _result The second stored number input
    function callback(uint256 _taskId, bytes memory _result) external {






    }
}