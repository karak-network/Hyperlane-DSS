// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity ^0.8.0;

import "../../../contracts/interfaces/DSS/IRemoteChallenger.sol";

contract TestChallenger is IRemoteChallenger {
    uint256 delayBlocks;

    constructor(uint256 _delayBlocks) {
        delayBlocks = _delayBlocks;
    }

    function challengeDelayBlocks() external view returns (uint256) {
        return delayBlocks;
    }

    function handleChallenge(address operator) external {}
}
