// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity ^0.8;

import "forge-std/Test.sol";
import {ProxyAdmin} from "../../contracts/upgrade/ProxyAdmin.sol";
import {TransparentUpgradeableProxy, ITransparentUpgradeableProxy} from "../../contracts/upgrade/TransparentUpgradeableProxy.sol";
import {HyperlaneDSS, HyperlaneDSSLib} from "../../contracts/DSS/HyperlaneDSS.sol";
import "../../contracts/interfaces/DSS/vendored/Errors.sol";
import "../../contracts/interfaces/DSS/vendored/ICore.sol";
import {HyperlaneDSSHelper} from "./utils/HyperlaneDSShelper.sol";
import {CommonUtils} from "./utils/CommonUtils.sol";

import "./Bytecodes.sol";
import "./helpers/TestChallenger.sol";
import "./helpers/TestVault.sol";

contract HyperlaneDSSTest is Test {
    using HyperlaneDSSLib for HyperlaneDSSLib.AssetParams;

    address hyperlaneDSSOwner = address(0x0df1);
    address coreAddress = 0xc4B3D494c166eBbFF9C716Da4cec39B579795A0d;
    uint256 minimumWeight = 8000;
    uint256 maxSlashablePercentageWad = 40 * 1e18;
    address PROXY_ADMIN_OWNER = address(0x0ff1);
    HyperlaneDSSLib.Quorum quorum;
    ProxyAdmin proxyAdmin;
    HyperlaneDSS hyperlaneDSS;
    address asset = 0x9b006CA060491991554f78e9961926fc3960718e;
    uint256 weight = 10000;
    address operator = address(0x0af1);
    address operatorSigningKey = address(0x0bf1);
    uint256 constant MAX_CHALLENGERS = 10;

    function setUp() public {
        vm.prank(PROXY_ADMIN_OWNER);
        proxyAdmin = new ProxyAdmin();
        address hyperlaneDSSImpl = address(new HyperlaneDSS());
        hyperlaneDSS = HyperlaneDSS(
            address(
                new TransparentUpgradeableProxy(
                    hyperlaneDSSImpl,
                    address(proxyAdmin),
                    ""
                )
            )
        );
        HyperlaneDSSLib.AssetParams memory asset = HyperlaneDSSLib.AssetParams({
            asset: asset,
            weight: uint96(10000)
        });
        quorum.assets.push(asset);
        vm.mockCall(
            coreAddress,
            abi.encodeCall(ICore.registerDSS, maxSlashablePercentageWad),
            ""
        );
        hyperlaneDSS.initialize(
            hyperlaneDSSOwner,
            coreAddress,
            minimumWeight,
            maxSlashablePercentageWad,
            quorum
        );
    }

    function test_initialization() public {
        assertEq(hyperlaneDSS.owner(), hyperlaneDSSOwner);
        assertEq(coreAddress, hyperlaneDSS.core());
        assertEq(
            keccak256(abi.encode(quorum)),
            keccak256(abi.encode(hyperlaneDSS.quorum()))
        );
        vm.expectRevert("Initializable: contract is already initialized");
        hyperlaneDSS.initialize(
            hyperlaneDSSOwner,
            coreAddress,
            minimumWeight,
            maxSlashablePercentageWad,
            quorum
        );
    }

    function test_Fail_updateQuorumConfig() public {
        HyperlaneDSSLib.Quorum memory newQuorum;
        newQuorum.assets = new HyperlaneDSSLib.AssetParams[](2);
        // unsorted array of assets
        newQuorum.assets[0].asset = address(9);
        newQuorum.assets[1].asset = address(8);
        vm.prank(hyperlaneDSSOwner);
        vm.expectRevert(NotSorted.selector);
        hyperlaneDSS.updateQuorumConfig(newQuorum, new address[](0));
        // Sum not equals `HyperlaneDSSConstants.BPS`
        newQuorum.assets[0].asset = address(8);
        newQuorum.assets[1].asset = address(9);
        vm.prank(hyperlaneDSSOwner);
        vm.expectRevert(InvalidQuorum.selector);
        hyperlaneDSS.updateQuorumConfig(newQuorum, new address[](0));
    }

    function test_updateQuorumConfig() public {
        HyperlaneDSSLib.Quorum memory newQuorum;
        newQuorum.assets = new HyperlaneDSSLib.AssetParams[](2);
        newQuorum.assets[0].asset = address(8);
        newQuorum.assets[0].weight = 5_000;
        newQuorum.assets[1].asset = address(9);
        newQuorum.assets[1].weight = 5_000;
        vm.prank(hyperlaneDSSOwner);
        hyperlaneDSS.updateQuorumConfig(newQuorum, new address[](0));
        assertEq(
            keccak256(abi.encode(newQuorum)),
            keccak256(abi.encode(hyperlaneDSS.quorum()))
        );
    }

    function test_registration(
        address operatorAddress,
        address signingKey
    ) public {
        vm.assume(operatorAddress != address(0) || signingKey != address(0));
        vm.prank(coreAddress);
        hyperlaneDSS.registrationHook(
            operatorAddress,
            abi.encode(operatorSigningKey)
        );
        assertTrue(hyperlaneDSS.isOperatorRegistered(operatorAddress));
        assertEq(
            hyperlaneDSS.getLastestOperatorSigningKey(operatorAddress),
            operatorSigningKey
        );
    }

    function test_unregistration(
        address operatorAddress,
        address signingKey
    ) public {
        vm.assume(operatorAddress != address(0) || signingKey != address(0));
        // register operator
        vm.prank(coreAddress);
        hyperlaneDSS.registrationHook(
            operatorAddress,
            abi.encode(operatorSigningKey)
        );
        assertTrue(hyperlaneDSS.isOperatorRegistered(operatorAddress));
        assertEq(
            hyperlaneDSS.getLastestOperatorSigningKey(operatorAddress),
            operatorSigningKey
        );
        // unregister operator
        vm.prank(coreAddress);
        hyperlaneDSS.unregistrationHook(operatorAddress);
        assertFalse(hyperlaneDSS.isOperatorRegistered(operatorAddress));
    }

    function test_challengerEnrollment(
        address operatorAddress,
        uint256 challengersCount,
        uint256 challengeDelayBlocks
    ) public {
        vm.assume(
            operatorAddress != address(0) &&
                operatorAddress != address(proxyAdmin)
        );
        challengersCount %= MAX_CHALLENGERS;
        challengersCount++;
        (
            IRemoteChallenger[] memory challengers,
            address[] memory challengerAddrArr
        ) = HyperlaneDSSHelper.deployChallengers(
                challengersCount,
                challengeDelayBlocks
            );

        vm.prank(coreAddress);
        hyperlaneDSS.registrationHook(
            operatorAddress,
            abi.encode(operatorAddress)
        );

        vm.prank(operatorAddress);
        hyperlaneDSS.enrollIntoChallengers(challengers);
        CommonUtils.assertEq(
            challengerAddrArr,
            hyperlaneDSS.getOperatorChallengers(operatorAddress)
        );
    }

    function test_challengerUnenrollment(
        address operatorAddress,
        uint256 challengersCount,
        uint256 challengeDelayBlocks
    ) public {
        vm.assume(
            operatorAddress != address(0) &&
                operatorAddress != address(proxyAdmin)
        );
        challengeDelayBlocks %= UINT256_MAX / 2;
        challengersCount %= MAX_CHALLENGERS;
        challengersCount++;
        (
            IRemoteChallenger[] memory challengers,
            address[] memory challengerAddrArr
        ) = HyperlaneDSSHelper.deployChallengers(
                challengersCount,
                challengeDelayBlocks
            );
        vm.prank(coreAddress);
        hyperlaneDSS.registrationHook(
            operatorAddress,
            abi.encode(operatorAddress)
        );
        vm.prank(operatorAddress);
        hyperlaneDSS.enrollIntoChallengers(challengers);
        // start unenrollment
        vm.prank(operatorAddress);
        hyperlaneDSS.startUnenrollment(challengers);
        vm.roll(block.number + challengeDelayBlocks);
        // finish unenrollment
        vm.prank(operatorAddress);
        hyperlaneDSS.completeUnenrollment(challengerAddrArr);
        assertEq(
            hyperlaneDSS.getOperatorChallengers(operatorAddress),
            new address[](0)
        );
    }

    function test_jailOperator(
        address operatorAddress,
        uint256 challengeDelayBlocks
    ) public {
        vm.assume(
            operatorAddress != address(0) &&
                operatorAddress != address(proxyAdmin)
        );
        vm.prank(coreAddress);
        hyperlaneDSS.registrationHook(
            operatorAddress,
            abi.encode(operatorAddress)
        );
        (
            IRemoteChallenger[] memory challengers,
            address[] memory challengersAddrArr
        ) = HyperlaneDSSHelper.deployChallengers(1, challengeDelayBlocks);
        vm.prank(operatorAddress);
        hyperlaneDSS.enrollIntoChallengers(challengers);

        vm.prank(address(challengers[0]));
        hyperlaneDSS.jailOperator(operatorAddress);
        assertTrue(hyperlaneDSS.isOperatorJailed(operatorAddress));

        address unenrolledChallenger = address(
            new TestChallenger(challengeDelayBlocks)
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                OperatorNotEnrolledWithChallenger.selector,
                (unenrolledChallenger)
            )
        );
        vm.prank(unenrolledChallenger);
        hyperlaneDSS.jailOperator(operatorAddress);
        // start unenrollment and then jail
        vm.prank(operatorAddress);
        hyperlaneDSS.startUnenrollment(challengers);
        vm.prank(address(challengers[0]));
        hyperlaneDSS.jailOperator(operatorAddress);
        // can't jail post complete unenrollment
        vm.roll(block.timestamp + challengeDelayBlocks);
        vm.prank(operatorAddress);
        hyperlaneDSS.completeUnenrollment(challengersAddrArr);
        vm.expectRevert(
            abi.encodeWithSelector(
                OperatorNotEnrolledWithChallenger.selector,
                (challengersAddrArr[0])
            )
        );
        vm.prank(address(challengers[0]));
        hyperlaneDSS.jailOperator(operatorAddress);
    }

    function test_operatorWeight(
        address operatorAddress,
        uint224 totalSupply,
        uint224 vaultBalance
    ) public {
        vm.assume(
            operatorAddress != address(0) &&
                operatorAddress != address(proxyAdmin)
        );
        vm.assume(totalSupply >= vaultBalance);
        vm.prank(coreAddress);
        hyperlaneDSS.registrationHook(
            operatorAddress,
            abi.encode(operatorAddress)
        );
        _addVault(operatorAddress, totalSupply, vaultBalance, asset);
        address[] memory operators = new address[](1);
        operators[0] = operatorAddress;
        hyperlaneDSS.updateOperators(operators);
        uint256 expectedWeight = totalSupply - vaultBalance >= minimumWeight
            ? totalSupply - vaultBalance
            : 0;
        assertEq(
            hyperlaneDSS.getLastCheckpointOperatorWeight(operatorAddress),
            expectedWeight
        );
    }

    function _addVault(
        address operatorAddr,
        uint256 totalSupply,
        uint256 vaultBal,
        address underlyingAsset
    ) public returns (address) {
        TestVault vault = new TestVault();
        vault.setAsset(underlyingAsset);
        vault.setTotalSupply(totalSupply);
        vault.setBalance(address(vault), vaultBal);
        IBaseDSS.QueuedStakeUpdate memory request;
        request.updateRequest.vault = address(vault);
        request.updateRequest.toStake = true;
        vm.prank(coreAddress);
        hyperlaneDSS.finishUpdateStakeHook(operatorAddr, request);
    }
}
