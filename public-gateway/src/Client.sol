// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;
import {Gateway, Util} from "../src/Contract.sol";


contract Client {

    using Util for Util.Task;
    using Util for Util.ExecutionInfo;


    /// @notice Emitted when we recieve callback for our result of the computation
    event FinalResultWithInputs(uint256 _taskId, bytes _result, bytes _resultSig);


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

    function send() internal {
      
      // address _callbackAddress;
      // bytes4 _callbackSelector;


      // take in the task struct and executioninfo struct as arguments

      // call with address and callbackselector

    }


    /// @param _taskId  Task Id of the computation
    /// @param _result computed result
    /// @param _result The second stored number input
    function callback(uint256 _taskId, bytes memory _result, bytes memory _resultSig) external {






    }
}