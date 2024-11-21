// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TestVault {
    address public asset;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    function setAsset(address _asset) public {
        asset = _asset;
    }

    function convertToAssets(uint256 assets) public pure returns (uint256) {
        return assets;
    }

    function setTotalSupply(uint256 _totalSupply) external {
        totalSupply = _totalSupply;
    }

    function setBalance(address user, uint256 bal) external {
        balanceOf[user] = bal;
    }
}
