// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity ^0.8.0;

import "../../../contracts/interfaces/DSS/IRemoteChallenger.sol";
import "../helpers/TestChallenger.sol";

library HyperlaneDSSHelper {
    function deployChallengers(
        uint256 numOfChallengers,
        uint256 challengerDelay
    )
        public
        returns (
            IRemoteChallenger[] memory challengers,
            address[] memory challengerAddrArr
        )
    {
        challengers = new IRemoteChallenger[](numOfChallengers);
        challengerAddrArr = new address[](numOfChallengers);
        for (uint256 i = 0; i < numOfChallengers; i++) {
            challengers[i] = IRemoteChallenger(
                address(new TestChallenger(challengerDelay))
            );
            challengerAddrArr[i] = address(challengers[i]);
        }
    }
}
