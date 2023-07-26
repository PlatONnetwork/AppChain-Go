package rootchain

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	vm2 "github.com/PlatONnetwork/AppChain-Go/common/vm"
	"github.com/PlatONnetwork/AppChain-Go/core/state"
	"github.com/PlatONnetwork/AppChain-Go/core/types"
	"github.com/PlatONnetwork/AppChain-Go/core/vm"
	"github.com/PlatONnetwork/AppChain-Go/innerbindings/helper"
	"github.com/PlatONnetwork/AppChain-Go/log"
	"math/big"
)

type RootChainReader interface {
	//get root chain stake logs, return logs, end block number
	GetStakeLogs(start *big.Int, limit uint64) ([]*types.Log, *big.Int, error)
	//get logs base on block height range
	GetStakeLogsRange(start, end *big.Int) ([]*types.Log, error)
}

type RootChainCheck interface {
	CheckStakeStateSyncExtra(parent *types.Block, header *types.Header, tx *types.Transaction) error
}
type StateReader interface {
	MakeStateDB(block *types.Block) (*state.StateDB, error)
}
type RootChain struct {
	stateReader  StateReader
	eventManager *EventManager
}

func NewRootChain(blockChainCache StateReader, eventManager *EventManager) (*RootChain, error) {
	return &RootChain{
		stateReader:  blockChainCache,
		eventManager: eventManager,
	}, nil
}

func (r RootChain) Start() error {
	go func() {
		if err := r.eventManager.Listen(); err != nil {
			log.Error("Listening for event failures on RootChain", "error", err)
		}
	}()
	return nil
}

func (r RootChain) CheckStakeStateSyncExtra(parent *types.Block, header *types.Header, tx *types.Transaction) error {
	end := types.DecodeStakeExtra(header.Extra)

	// If the condition is met, then there are no events to process.
	if tx == nil && end.Uint64() == 0 {
		return nil
	}
	// If there is a block height in extra, but the transaction is empty, it means that there are no events to pack,
	// but the block height of the finished listening event should be increased to avoid repeated listening after restart.
	// Fails if there is no block height in extra, but the transaction is not empty.
	if tx != nil && end.Uint64() == 0 {
		return fmt.Errorf("extra number is empty, but the transaction is not empty")
	}
	// There are no events to handle, but the height of the blocks already listened to needs to be increased.
	// So there must be a transaction that contains the height of the block.
	if tx == nil && end.Uint64() > 0 {
		return fmt.Errorf("extra number is not empty, but the transaction is empty")
	}

	stateDb, err := r.stateReader.MakeStateDB(parent)
	if err != nil {
		return err
	}
	// The new block height is not larger than the last block height, then it is abnormal.
	start := new(big.Int).SetBytes(stateDb.GetState(vm2.StakingContractAddr, vm.BlockNumberKey))
	if end.Uint64() <= start.Uint64() {
		return errors.New(fmt.Sprintf("the current event block height is no greater than the previous one, pre=%d, current=%d", start, end))
	}
	logs, err := r.GetStakeLogsRange(new(big.Int).SetUint64(start.Uint64()+1), end)
	if err != nil {
		return err
	}
	data, err := helper.EncodeStakeStateSync(end, logs)
	if err != nil {
		return err
	}
	if !bytes.Equal(tx.Data(), data) {
		errMsg := fmt.Sprintf("header extra check failed: expect tx data doesn't match actual tx data")
		log.Error(errMsg, "txData", hex.EncodeToString(tx.Data()), "data", hex.EncodeToString(data))
		return errors.New(errMsg)
	}
	log.Debug("verify that the rootChain's events pass", "blockNumber", header.Number, "eventStartBlockNumber", start, "eventEndBlockNumber", end,
		"logsSize", len(logs))
	return nil
}

func (r RootChain) GetStakeLogs(start *big.Int, limit uint64) ([]*types.Log, *big.Int, error) {
	endBlockNumber, logs, err := r.eventManager.BuildEventList(start.Uint64(), 0, limit)
	if err != nil {
		return nil, nil, err
	}
	return logs, endBlockNumber, nil
}

func (r RootChain) GetStakeLogsRange(start, end *big.Int) ([]*types.Log, error) {
	_, logs, err := r.eventManager.BuildEventList(start.Uint64(), end.Uint64(), 0)
	if err != nil {
		return nil, err
	}
	return logs, nil
}
