// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

contract Client {
    
    /// @notice Emitted when we recieve callback for our result of the computation
    event FinalResultWithInputs(uint256 _taskId, bytes _result, bytes _resultSig);


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