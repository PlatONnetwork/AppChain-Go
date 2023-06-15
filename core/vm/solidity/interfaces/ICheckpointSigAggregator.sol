// SPDX-License-Identifier: GPL-3.0

pragma solidity ^0.8.12;

interface ICheckpointSigAggregator {
    event CheckpointSigAggregated(
        address proposer,
        uint256 start,
        uint256 end,
        bytes32 root,
        uint256[] signedValidators,
        bytes signature
    );

    struct Checkpoint {
        address proposer;
        bytes32[] hashes;
        uint256 start;
        uint256 end;
        uint256[] current;
        uint256[] rewards;
        uint256 chainId;
        uint256[] slashing;
    }

    struct PendingCheckpoint {
        Checkpoint checkpoint;
        uint256 blockNum;
    }

    function propose(
        Checkpoint calldata cp,
        uint256 validatorId,
        bytes calldata signature
    ) external;

    function pendingCheckpoint()
        external
        view
        returns (PendingCheckpoint memory pcp);

    function shouldPropose(
        uint256 number,
        uint256 validatorId
    ) external view returns (bool);
}
