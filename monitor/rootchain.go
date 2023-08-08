package monitor

import (
	"context"
	"crypto/sha256"
	appchain "github.com/PlatONnetwork/AppChain-Go"
	"github.com/PlatONnetwork/AppChain-Go/common"
	"github.com/PlatONnetwork/AppChain-Go/common/hexutil"
	"github.com/PlatONnetwork/AppChain-Go/core/types"
	"github.com/PlatONnetwork/AppChain-Go/ethclient"
	"github.com/PlatONnetwork/AppChain-Go/log"
	"github.com/PlatONnetwork/AppChain-Go/p2p/discover"
	"github.com/PlatONnetwork/AppChain-Go/rootchain/innerbindings/config"
	"github.com/PlatONnetwork/AppChain-Go/rootchain/innerbindings/helper"
	"math/big"
)

func (m *Monitor) ConnectRootChain(rootChainConfig *config.RootChainContractConfig) {
	monitor.rootChainConfig = rootChainConfig
	if monitor.rootChainConfig.PlatonRPCAddr == "" {
		log.Warn("the rpc address for platon is empty, please check if it is required")
		return
	}
	client, err := ethclient.Dial(monitor.rootChainConfig.PlatonRPCAddr)
	if err != nil {
		log.Error("Failed to connect to Platon's RPC address", "addr", monitor.rootChainConfig.PlatonRPCAddr, "error", err)
		return
	}
	client.SetNameSpace("platon")
	monitor.rootChainClient = client
}

// func (m *Monitor) GetRootChainSortedLogs(startBlock, endBlock hexutil.Big) rootchain.LogListSort {
func (m *Monitor) GetRootChainLogs(startBlock, endBlock *big.Int) map[common.Hash]types.Log {
	filterParams := appchain.FilterQuery{
		FromBlock: startBlock,
		ToBlock:   endBlock,
		Addresses: []common.Address{
			monitor.rootChainConfig.StakingInfoAddress,
		},
		Topics: [][]common.Hash{{helper.StakedID, helper.UnstakeInitID, helper.SignerChangeID,
			helper.ShareMintedID, helper.ShareBurnedID}},
	}

	logs, err := monitor.rootChainClient.FilterLogs(context.Background(), filterParams)
	if err != nil {
		log.Error("failed to get filtered logs", "fromBlock", filterParams.FromBlock, "toBlock", filterParams.ToBlock, "error", err)
	}
	rootChainLogMap := make(map[common.Hash]types.Log)
	for _, vLog := range logs {
		rootChainLogMap[m.GetLogHash(vLog)] = vLog
	}

	return rootChainLogMap
	/*sortedLogs := make(rootchain.LogListSort, len(logs))
	for _, vLog := range logs {
		sortedLogs = append(sortedLogs, &vLog)
	}
	sort.Sort(&sortedLogs)
	return sortedLogs*/
}

func (m *Monitor) GetLogHash(vLog types.Log) common.Hash {
	bytes := make([]byte, 0)
	bytes = append(bytes, vLog.Address.Bytes()...)
	for _, topic := range vLog.Topics {
		bytes = append(bytes, topic.Bytes()...)
	}
	bytes = append(bytes, vLog.Data...)
	return common.Hash(sha256.Sum256(bytes))
}

type RootChainTxType int

const (
	Stake RootChainTxType = iota
	UnStake
	Delegate
	UnDelegate
)

/*type JsonBig big.Int
func (b JsonBig) MarshalText() (string, error) {
	return (hexutil.Big)(&b).String()

}
*/
/*// UnmarshalJSON implements json.Unmarshaler.
func (b *JsonBig) UnmarshalJSON(input [string) error {
	if !isString(input) {
		return errNonString(bigT)
	}
	return wrapTypeError(b.UnmarshalText(input[1:len(input)-1]), bigT)
}
*/
// 定义 RootChainTxType 类型的方法 String(), 返回字符串。
func (name RootChainTxType) String() string {
	return [...]string{
		"Stake",
		"UnStake",
		"Delegate",
		"UnDelegate",
	}[name]
}

type RootChainTx struct {
	TxType  RootChainTxType `json:"txType"`
	TxHash  common.Hash     `json:"txHash"`
	TxParam interface{}     `json:"txParam"`
	RootChainTxParam
}

type RootChainTxParam struct {
	RootChainBlockNumber uint64      `json:"rootChainBlockNumber"`
	RootChainTxHash      common.Hash `json:"rootChainTxHash"`
	RootChainTxIndex     uint        `json:"rootChainTxIndex"`
}

type Staking struct {
	StakingAddress common.Address  `json:"stakingAddress"`
	ValidatorId    uint64          `json:"validatorId"`
	NodeId         discover.NodeID `json:"nodeId"`
	Amount         uint64          `json:"amount"`
}

type UnStaking struct {
	ValidatorId *hexutil.Big `json:"validatorId,string"`
}

type Delegation struct {
	User                             common.Address `json:"user"`
	ValidatorId                      uint64         `json:"validatorId"`
	Amount                           uint64         `json:"amount"`
	TotalDelegationAmountOfValidator uint64         `json:"totalDelegationAmountOfValidator"`
}

type UnDelegation struct {
	User                             common.Address `json:"user"`
	ValidatorId                      uint64         `json:"validatorId"`
	Amount                           uint64         `json:"amount"`
	TotalDelegationAmountOfValidator uint64         `json:"totalDelegationAmountOfValidator"`
}

func (m *Monitor) CollectRootChainStakeTx(txHash common.Hash, stakingAddress common.Address, validatorId *big.Int, nodeId discover.NodeID, amount *big.Int, rootChainBlockNumber uint64, rootChainTxHash common.Hash, rootChainTxIndex uint) {
	staking := Staking{stakingAddress, validatorId.Uint64(), nodeId, amount.Uint64()}
	rootChainTxParam := RootChainTxParam{rootChainBlockNumber, rootChainTxHash, rootChainTxIndex}
	rootChainTx := &RootChainTx{Stake, txHash, staking, rootChainTxParam}
	m.saveRootChainTx(rootChainTx)
}

func (m *Monitor) CollectRootChainUnStakeTx(txHash common.Hash, validatorId *big.Int, rootChainBlockNumber uint64, rootChainTxHash common.Hash, rootChainTxIndex uint) {
	unstaking := UnStaking{(*hexutil.Big)(validatorId)}
	rootChainTxParam := RootChainTxParam{rootChainBlockNumber, rootChainTxHash, rootChainTxIndex}
	rootChainTx := &RootChainTx{UnStake, txHash, unstaking, rootChainTxParam}
	m.saveRootChainTx(rootChainTx)
}

func (m *Monitor) CollectRootChainDelegateTx(txHash common.Hash, user common.Address, validatorId *big.Int, amount *big.Int, totalDelegationAmountOfValidator *big.Int, rootChainBlockNumber uint64, rootChainTxHash common.Hash, rootChainTxIndex uint) {
	delegation := Delegation{user, validatorId.Uint64(), amount.Uint64(), totalDelegationAmountOfValidator.Uint64()}
	rootChainTxParam := RootChainTxParam{rootChainBlockNumber, rootChainTxHash, rootChainTxIndex}
	rootChainTx := &RootChainTx{Delegate, txHash, delegation, rootChainTxParam}
	m.saveRootChainTx(rootChainTx)
}

func (m *Monitor) CollectRootChainUnDelegateTx(txHash common.Hash, user common.Address, validatorId *big.Int, amount *big.Int, totalDelegationAmountOfValidator *big.Int, rootChainBlockNumber uint64, rootChainTxHash common.Hash, rootChainTxIndex uint) {
	undelegation := UnDelegation{user, validatorId.Uint64(), amount.Uint64(), totalDelegationAmountOfValidator.Uint64()}
	rootChainTxParam := RootChainTxParam{rootChainBlockNumber, rootChainTxHash, rootChainTxIndex}
	rootChainTx := &RootChainTx{UnDelegate, txHash, undelegation, rootChainTxParam}
	m.saveRootChainTx(rootChainTx)
}

func (m *Monitor) saveRootChainTx(rootChainTx *RootChainTx) {
	log.Debug("saveRootChainTx", "rootChainTx", ToJsonString(rootChainTx))
	dbKey := RootChainTxKey.String() + "_" + rootChainTx.TxHash.String()
	data, err := m.monitordb.Get([]byte(dbKey))
	if nil != err && err != ErrNotFound {
		log.Error("failed to load root chain transactions", "err", err)
		return
	}
	var rootChainTxList []*RootChainTx
	ParseJson(data, &rootChainTxList)

	rootChainTxList = append(rootChainTxList, rootChainTx)

	json := ToJson(rootChainTxList)
	if len(json) > 0 {
		m.monitordb.Put([]byte(dbKey), json)
		log.Debug("save root chain transactions success")
	}
}

func (m *Monitor) GetRootChainTx(txHash common.Hash) []*RootChainTx {
	log.Debug("GetRootChainTx", "txHash", txHash.String())

	dbKey := RootChainTxKey.String() + "_" + txHash.String()
	data, err := m.monitordb.Get([]byte(dbKey))
	if nil != err {
		if err == ErrNotFound {
			log.Debug("GetRootChainTx success: no data")
		} else {
			log.Error("GetRootChainTx failed", "err", err)
		}
		return nil
	}

	var rootChainTxList []*RootChainTx
	ParseJson(data, &rootChainTxList)

	log.Debug("GetRootChainTx success", "txHash", txHash.String(), "json", string(data))
	return rootChainTxList
}
