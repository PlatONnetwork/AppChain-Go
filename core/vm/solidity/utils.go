package solidity

import (
	"github.com/PlatONnetwork/PlatON-Go/core/vm/solidity/checkpoint"
	"github.com/PlatONnetwork/PlatON-Go/core/vm/solidity/types"
)

func ICheckpointToCheckpoint(cp *checkpoint.ICheckpointSigAggregatorCheckpoint) *types.Checkpoint {
	return &types.Checkpoint{
		Proposer:    cp.Proposer,
		Start:       cp.Start,
		End:         cp.End,
		RootHash:    cp.RootHash,
		AccountHash: cp.AccountHash,
		ChainId:     cp.ChainId,
		Current:     cp.Current,
		Rewards:     cp.Rewards,
		Slashing:    cp.Slashing,
	}
}
