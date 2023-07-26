package rootchain

import (
	"context"
	appchain "github.com/PlatONnetwork/AppChain-Go"
	"github.com/PlatONnetwork/AppChain-Go/common"
	comvm "github.com/PlatONnetwork/AppChain-Go/common/vm"
	"github.com/PlatONnetwork/AppChain-Go/core/types"
	"github.com/PlatONnetwork/AppChain-Go/core/vm"
	"github.com/PlatONnetwork/AppChain-Go/ethclient"
	"github.com/PlatONnetwork/AppChain-Go/ethdb"
	"github.com/PlatONnetwork/AppChain-Go/event"
	"github.com/PlatONnetwork/AppChain-Go/innerbindings/config"
	"github.com/PlatONnetwork/AppChain-Go/innerbindings/helper"
	"github.com/PlatONnetwork/AppChain-Go/log"
	"math/big"
	"sort"
	"sync"
)

// EventManager Managing events issued on the master chain.
// Includes listening for events, storing events and assembling a batch of packaged events.
type EventManager struct {
	exit     chan struct{}
	db       ethdb.Database
	RCConfig *config.RootChainContractConfig

	// Get events from the specified block height
	fromBlockNumber uint64
	// Event Storage
	blockLogs map[uint64][]*types.Log

	checkpointEventFeed event.Feed
	mu                  sync.RWMutex
}

func NewEventManager(stateDB vm.StateDB, db ethdb.Database, rcConfig *config.RootChainContractConfig) *EventManager {
	start := new(big.Int).SetBytes(stateDB.GetState(comvm.StakingContractAddr, vm.BlockNumberKey))
	eventManager := &EventManager{
		exit:            make(chan struct{}),
		db:              db,
		RCConfig:        rcConfig,
		fromBlockNumber: rcConfig.ContractDeployedNumber,
		blockLogs:       make(map[uint64][]*types.Log, 0),
	}
	if start.Uint64() > 0 {
		eventManager.fromBlockNumber = start.Uint64() + 1
	}
	return eventManager
}

// SubscribeEvents Subscribe to Checkpoint events that occur on RootChain.
func (em *EventManager) SubscribeEvents(ch chan *types.Log) event.Subscription {
	return em.checkpointEventFeed.Subscribe(ch)
}

type LogListSort []*types.Log

func (ls LogListSort) Len() int {
	return len(ls)
}

func (ls LogListSort) Less(i, j int) bool {
	return ls[i].Index < ls[j].Index
}

func (ls LogListSort) Swap(i, j int) {
	ls[i], ls[j] = ls[j], ls[i]
}

func (em *EventManager) Listen() error {
	// If it is an authenticator node, this rpc address needs to be configured.
	// Not required if it is a normal node.
	if em.RCConfig.PlatonRPCAddr == "" {
		log.Warn("the rpc address for platon is empty, please check if it is required")
		return nil
	}
	client, err := ethclient.Dial(em.RCConfig.PlatonRPCAddr)
	if err != nil {
		log.Error("Failed to connect to Platon's RPC address", "addr", em.RCConfig.PlatonRPCAddr, "error", err)
		return err
	}
	newHeadChan := make(chan *types.Header)
	client.SetNameSpace("platon")
	newHeadSubscribe, err := client.SubscribeNewHead(context.Background(), newHeadChan)
	if err != nil {
		close(newHeadChan)
		log.Error("listening to the block header fails", "error", err)
		return err
	}
	defer func() {
		newHeadSubscribe.Unsubscribe()
		client.Close()
	}()

	log.Info("Start listening for new blocks on RootChain", "platonRPCAddr", em.RCConfig.PlatonRPCAddr, "startBlockNumber", em.fromBlockNumber,
		"rootChainId", em.RCConfig.RootChainID, "stakingInfoAddress", em.RCConfig.StakingInfoAddress, "rootChainAddress", em.RCConfig.RootChainAddress)
	for {
		select {
		case <-em.exit:
			log.Warn("event listener exit")
			return nil
		case err := <-newHeadSubscribe.Err():
			log.Error("subscription failure", "error", err)
			// TODO 处理订阅区块头失败的情况
			return err
		case newHead := <-newHeadChan:
			log.Trace("listening for a new block", "blockNumber", newHead.Number, "blockHash", newHead.Hash().TerminalString())
			em.mu.RLock()
			fromBlockNumber := em.fromBlockNumber
			em.mu.RUnlock()
			filterParams := appchain.FilterQuery{
				FromBlock: new(big.Int).SetUint64(fromBlockNumber),
				ToBlock:   newHead.Number,
				Addresses: []common.Address{
					em.RCConfig.StakingInfoAddress,
					em.RCConfig.RootChainAddress,
				},
				Topics: [][]common.Hash{{helper.StakedID, helper.UnstakeInitID,
					helper.SignerChangeID, helper.StakeUpdateID, helper.NewHeaderBlockID}},
			}

			logs, err := client.FilterPlatONLogs(context.Background(), filterParams)
			if err != nil {
				log.Error("failed to get filtered logs", "fromBlock", filterParams.FromBlock, "toBlock", filterParams.ToBlock, "error", err)
				// TODO 处理获取事件失败的情况
				break
			}
			log.Debug("get event success", "fromBlock", filterParams.FromBlock, "toBlock", filterParams.ToBlock, "logLength", len(logs))
			blockLogsTemp := make(map[uint64]LogListSort)
			for _, log := range logs {
				// checkpoint events are not stored and are notified directly to the special handling logic.
				// feed.Send()
				tmpLog := log
				if tmpLog.Topics[0] == helper.NewHeaderBlockID {
					em.checkpointEventFeed.Send(&tmpLog)
					continue
				}

				logs, ok := blockLogsTemp[tmpLog.BlockNumber]
				if !ok {
					logs = make(LogListSort, 0)
				}
				logs = append(logs, &tmpLog)
				blockLogsTemp[tmpLog.BlockNumber] = logs
			}
			em.mu.Lock()
			// If a block that has already been listened to appears, it is skipped.
			// This does not occur normally.
			for k, v := range blockLogsTemp {
				if _, ok := em.blockLogs[k]; ok {
					continue
				}
				sort.Sort(&v)
				em.blockLogs[k] = v
			}
			// Make the latest block +1, as the starting block high for the next fetch event.
			em.fromBlockNumber = newHead.Number.Uint64() + 1
			em.mu.Unlock()
		}
	}
}

type BlockNumberListSort []uint64

func (bnl BlockNumberListSort) Len() int {
	return len(bnl)
}

func (bnl BlockNumberListSort) Less(i, j int) bool {
	return bnl[i] < bnl[j]
}

func (bnl BlockNumberListSort) Swap(i, j int) {
	bnl[i], bnl[j] = bnl[j], bnl[i]
}

// BuildEventList Get all the specified events in the range based on the start and end block heights.
func (em *EventManager) BuildEventList(startBlockNumber uint64, endBlockNumber uint64, limit uint64) (*big.Int, []*types.Log, error) {
	em.mu.RLock()
	defer em.mu.RUnlock()
	logList := make([]*types.Log, 0)
	if endBlockNumber == 0 {
		// If it is the node that is out of the block, that logic is taken.
		// Calculate the cut-off block height for packing events based on the estimated inter-node synchronization block delay.
		if em.fromBlockNumber > em.RCConfig.DelayNumbers {
			endBlockNumber = em.fromBlockNumber - em.RCConfig.DelayNumbers - 1
		}
	}
	if startBlockNumber > em.fromBlockNumber {
		log.Warn("starting block height is greater than the latest height listened to", "startBlockNumber", startBlockNumber, "latestHeight", em.fromBlockNumber-1)
		return nil, logList, nil
	}
	if endBlockNumber >= em.fromBlockNumber || endBlockNumber < startBlockNumber {
		log.Debug("Not enough events", "startBlockNumber", startBlockNumber, "latestHeight", em.fromBlockNumber-1,
			"backNumbers", em.RCConfig.DelayNumbers, "endBlockNumber", endBlockNumber)
		return nil, logList, nil
	}
	blockNumberList := make(BlockNumberListSort, 0)
	for blockNumber := range em.blockLogs {
		if blockNumber >= startBlockNumber && blockNumber <= endBlockNumber {
			blockNumberList = append(blockNumberList, blockNumber)
		}
	}
	sort.Sort(&blockNumberList)
	for _, blockNumber := range blockNumberList {
		logs := em.blockLogs[blockNumber]
		logList = append(logList, logs...)
		log.Debug("pack event", "blockNumber", blockNumber, "logsSize", len(logs), "totalSize", len(logList))
	}
	log.Debug("packing event complete", "startBlockNumber", startBlockNumber, "endBlockNumber", endBlockNumber, "totalSize", len(logList))
	return new(big.Int).SetUint64(endBlockNumber), logList, nil
}

func (em *EventManager) Stop() {
	close(em.exit)
}
