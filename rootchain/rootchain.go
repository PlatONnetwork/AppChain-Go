package rootchain

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/PlatONnetwork/PlatON-Go/common"
	vm2 "github.com/PlatONnetwork/PlatON-Go/common/vm"
	"github.com/PlatONnetwork/PlatON-Go/core/state"
	"github.com/PlatONnetwork/PlatON-Go/core/types"
	"github.com/PlatONnetwork/PlatON-Go/core/vm"
	"github.com/PlatONnetwork/PlatON-Go/innerbindings/helper"
	"github.com/PlatONnetwork/PlatON-Go/log"
	"math/big"
	"time"
)

type RootChainReader interface {
	//get root chain stake logs, return logs, end block number
	GetStakeLogs(start *big.Int, limit uint64) ([]*types.Log, *big.Int, error)
	//get logs base on block height range
	GetStakeLogsRange(start, end *big.Int) ([]*types.Log, error)
}

type RootChainCheck interface {
	CheckStakeStateSyncExtra(parent *types.Header, header *types.Header, tx *types.Transaction) error
}
type StateReader interface {
	StateAt(root common.Hash) (*state.StateDB, error)
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

func (r RootChain) CheckStakeStateSyncExtra(parent *types.Header, header *types.Header, tx *types.Transaction) error {
	end := types.DecodeStakeExtra(header.Extra)
	//if there is no stake tx in block, both tx and end is must empty
	if tx == nil {
		if end.Uint64() != 0 {
			return fmt.Errorf("stake tx is nil, but extra is not empty")
		}
		return nil
	}

	stateDb, err := r.stateReader.StateAt(parent.Root)
	if err != nil {
		return err
	}
	start := new(big.Int).SetBytes(stateDb.GetState(vm2.StakingContractAddr, vm.BlockNumberKey))
	logs, err := r.GetStakeLogsRange(big.NewInt(start.Int64()+1), end)
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
	startTime := time.Now()
	endBlockNumber, logs, err := r.eventManager.BuildEventList(start.Uint64(), 0, limit)
	if err != nil {
		return nil, nil, err
	}
	log.Info("haoshi", "time", time.Since(startTime))
	return logs, endBlockNumber, nil
}

func (r RootChain) GetStakeLogsRange(start, end *big.Int) ([]*types.Log, error) {
	_, logs, err := r.eventManager.BuildEventList(start.Uint64(), end.Uint64(), 0)
	if err != nil {
		return nil, err
	}
	return logs, nil
}
