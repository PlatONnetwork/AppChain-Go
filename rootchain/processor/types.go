package processor

import (
	"math/big"

	"github.com/PlatONnetwork/AppChain-Go/core/types"
	"github.com/PlatONnetwork/AppChain-Go/core/vm/solidity/checkpoint"
	stypes "github.com/PlatONnetwork/AppChain-Go/core/vm/solidity/types"
	"github.com/PlatONnetwork/AppChain-Go/event"
)

type PendingCheckpoint checkpoint.ICheckpointSigAggregatorPendingCheckpoint
type Checkpoint checkpoint.ICheckpointSigAggregatorCheckpoint

type ChainReader interface {
	CurrentHeader() *types.Header
	GetHeaderByNumber(number uint64) *types.Header
}

type TxSigner interface {
	Nonce() uint64
	Sign(tx *types.Transaction, chainId *big.Int) (*types.Transaction, error)
}

type NewHeaderBlockSubscriber interface {
	SubscribeEvents(chan *types.Log) event.Subscription
}

type CheckpointProposal struct {
	Checkpoint *stypes.Checkpoint
	BlockNum   uint64
}

type HeaderBlock struct {
	start  uint64
	end    uint64
	number *big.Int
}

type ContractCheckpoint struct {
	newStart           uint64
	newEnd             uint64
	currentHeaderBlock *HeaderBlock
}

func NewContractCheckpoint(newStart, newEnd uint64, currentHeaderBlock *HeaderBlock) *ContractCheckpoint {
	return &ContractCheckpoint{
		newStart,
		newEnd,
		currentHeaderBlock,
	}
}
