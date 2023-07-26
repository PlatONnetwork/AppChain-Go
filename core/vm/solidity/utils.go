package solidity

import (
	"github.com/PlatONnetwork/AppChain-Go/common"
	"github.com/PlatONnetwork/AppChain-Go/core/vm/solidity/checkpoint"
	"github.com/PlatONnetwork/AppChain-Go/core/vm/solidity/types"
)

func ICheckpointToCheckpoint(cp *checkpoint.ICheckpointSigAggregatorCheckpoint) *types.Checkpoint {
	return &types.Checkpoint{
		Proposer: cp.Proposer,
		Hashes:   ToHashSlice(cp.Hashes),
		Start:    cp.Start,
		End:      cp.End,
		Current:  cp.Current,
		Rewards:  cp.Rewards,
		ChainId:  cp.ChainId,
		Slashing: cp.Slashing,
	}
}

func ToBytes32Slice(hashes []common.Hash) [][32]byte {
	a := make([][32]byte, len(hashes))
	for i, h := range hashes {
		a[i] = h
	}
	return a
}

func ToHashSlice(a [][32]byte) []common.Hash {
	hashes := make([]common.Hash, len(a))
	for i, v := range a {
		hashes[i] = v
	}
	return hashes
}
