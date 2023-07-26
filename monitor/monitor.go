package monitor

import (
	"github.com/PlatONnetwork/AppChain-Go/common"
	"github.com/PlatONnetwork/AppChain-Go/core/state"
	"github.com/PlatONnetwork/AppChain-Go/log"
	"github.com/PlatONnetwork/AppChain-Go/x/staking"
	"github.com/PlatONnetwork/AppChain-Go/x/xcom"
	"github.com/PlatONnetwork/AppChain-Go/x/xutil"
	"math/big"
	"strconv"
	"sync"
)

type MonitorDbKey int

const (
	UnusualTransferKey MonitorDbKey = iota
	CreatedContractKey
	SuicidedContractKey
	ProxyPatternKey
	proxyPatternMapKey
	ValidatorsOfEpochKey
	VerifiersOfEpochKey
	EpochInfoKey
	SlashKey
	ImplicitPPOSTxKey
)

// 定义 MonitorDbKey 类型的方法 String(), 返回字符串。
func (dbKey MonitorDbKey) String() string {
	return [...]string{
		"UnusualTransferKey",
		"CreatedContractKey",
		"SuicidedContractKey",
		"ProxyPatternKey",
		"proxyPatternMapKey",
		"ValidatorsOfEpochKey",
		"VerifiersOfEpochKey",
		"EpochInfoKey",
		"YearKey",
		"InitNodeKey",
		"SlashKey",
		"ImplicitPPOSTxKey",
	}[dbKey]
}

type Monitor struct {
	statedb           *state.StateDB
	monitordb         *monitorDB
	stakingPlugin     Intf_stakingPlugin
	restrictingPlugin Intf_restrictingPlugin
}

var (
	onceMonitor sync.Once
	monitor     *Monitor
)

func InitMonitor(statedb *state.StateDB) {
	onceMonitor.Do(func() {
		if levelDB, err := openLevelDB(16, 500); err != nil {
			log.Crit("init monitor db fail", "err", err)
		} else {
			dbInstance := &monitorDB{path: dbFullPath, levelDB: levelDB, closed: false}
			monitor = &Monitor{statedb: statedb, monitordb: dbInstance}
		}

	})
}

func MonitorInstance() *Monitor {
	return monitor
}

func (m *Monitor) SetStakingPlugin(pluginImpl Intf_stakingPlugin) {
	monitor.stakingPlugin = pluginImpl
}
func (m *Monitor) SetRestrictingPlugin(pluginImpl Intf_restrictingPlugin) {
	monitor.restrictingPlugin = pluginImpl
}

// 收集非常规的转账交易
// 1. 用户发起的合约调用，参数携带了value值，造成向合约地址转账
// 2. 合约销毁时，合约上的原生代币，将转给合约的受益人（beneficiary，这个受益人，究竟是合约调用人？合约部署人？）
func (m *Monitor) CollectUnusualTransferTx(blockNumber uint64, txHash common.Hash, from, to common.Address, amount *big.Int) {
	log.Debug("CollectUnusualTransferTx", "blockNumber", blockNumber, "txHash", txHash.Hex(), "from", from.Bech32(), "to", to.Bech32(), "amount", amount)

	dbKey := UnusualTransferKey.String() + "_" + txHash.String()
	data, err := m.monitordb.Get([]byte(dbKey))
	if nil != err && err != ErrNotFound {
		log.Error("failed to load unusual transfers", "err", err)
		return
	}

	var unusualTransferTxList []*UnusualTransfer
	ParseJson(data, &unusualTransferTxList)

	unusualTransferTx := new(UnusualTransfer)
	unusualTransferTx.TxHash = txHash
	unusualTransferTx.From = from
	unusualTransferTx.To = to
	unusualTransferTx.Amount = amount

	unusualTransferTxList = append(unusualTransferTxList, unusualTransferTx)

	json := ToJson(unusualTransferTxList)
	if len(json) > 0 {
		m.monitordb.Put([]byte(dbKey), json)
		log.Debug("save unusual transfers success")
	}

}

// 查询非常规的转账交易
func (m *Monitor) GetUnusualTransfer(blockNumber uint64, txHash common.Hash) []*UnusualTransfer {
	log.Debug("GetUnusualTransfer", "blockNumber", blockNumber, "txHash", txHash.Hex())

	dbKey := UnusualTransferKey.String() + "_" + txHash.String()
	data, err := m.monitordb.Get([]byte(dbKey))
	if nil != err {
		log.Error("failed to load unusual transfers", "err", err)
		return nil
	}

	var unusualTransferTxList []*UnusualTransfer
	ParseJson(data, &unusualTransferTxList)
	return unusualTransferTxList
}

// 收集某个交易产生的新合约信息
// scan可以通过Rpc接口：GetExtReceipts，获取每个交易产生的新合约信息
func (m *Monitor) CollectCreatedContractInfo(txHash common.Hash, contractInfo *ContractInfo) {
	log.Debug("CollectCreatedContractInfo", "txHash", txHash.Hex(), "contractInfo", string(ToJson(contractInfo)))

	dbKey := CreatedContractKey.String() + "_" + txHash.String()
	data, err := m.monitordb.Get([]byte(dbKey))
	if nil != err && err != ErrNotFound {
		log.Error("failed to load created contracts", "err", err)
		return
	}
	var createdContractInfoList []*ContractInfo
	ParseJson(data, &createdContractInfoList)

	createdContractInfoList = append(createdContractInfoList, contractInfo)

	json := ToJson(createdContractInfoList)
	if len(json) > 0 {
		m.monitordb.Put([]byte(dbKey), json)
		log.Debug("save created contracts success")
	}
}

// 查询某个交易产生的新合约信息
// scan可以通过Rpc接口：GetExtReceipts，获取每个交易产生的新合约信息
func (m *Monitor) GetCreatedContracts(txHash common.Hash) []*ContractInfo {
	log.Debug("GetCreatedContract", "txHash", txHash.Hex())

	dbKey := CreatedContractKey.String() + "_" + txHash.String()
	data, err := m.monitordb.Get([]byte(dbKey))
	if nil != err && err != ErrNotFound {
		log.Error("failed to load created contracts", "err", err)
		return nil
	}
	var createdContractInfoList []*ContractInfo
	ParseJson(data, &createdContractInfoList)

	log.Debug("get created contracts success")
	return createdContractInfoList
}

// 收集某个交易造成的自杀合约的信息
// scan可以通过Rpc接口：GetExtReceipts，获取每个交易造成的自杀合约的信息
func (m *Monitor) CollectSuicidedContract(txHash common.Hash, suicidedContractAddr common.Address) {
	dbKey := SuicidedContractKey.String() + "_" + txHash.String()
	data, err := m.monitordb.Get([]byte(dbKey))
	if nil != err && err != ErrNotFound {
		log.Error("failed to load suicided contracts", "err", err)
		return
	}

	var suicidedContractInfoList []*ContractInfo
	ParseJson(data, &suicidedContractInfoList)

	suicidedContract := new(ContractInfo)
	suicidedContract.Address = suicidedContractAddr

	suicidedContractInfoList = append(suicidedContractInfoList, suicidedContract)

	json := ToJson(suicidedContractInfoList)
	if len(json) > 0 {
		m.monitordb.Put([]byte(dbKey), json)
		log.Debug("save suicided contracts success")
	}
}

// 查询某个交易产生的自杀合约的信息
// scan可以通过Rpc接口：GetExtReceipts，获取每个交易造成的自杀合约的信息
func (m *Monitor) GetSuicidedContracts(blockNumber uint64, txHash common.Hash) []*ContractInfo {
	log.Debug("GetSuicidedContract", "blockNumber", blockNumber, "txHash", txHash.Hex())

	dbKey := SuicidedContractKey.String() + "_" + txHash.String()
	data, err := m.monitordb.Get([]byte(dbKey))
	if nil != err && err != ErrNotFound {
		log.Error("failed to load suicided contracts", "err", err)
		return nil
	}
	var suicidedContractInfoList []*ContractInfo
	ParseJson(data, &suicidedContractInfoList)

	log.Debug("get suicided contracts success")
	return suicidedContractInfoList
}

// CollectProxyPattern 收集某个交易上发现的代理关系
// scan可以通过Rpc接口：GetExtReceipts，获取每个交易发现的代理关系
func (m *Monitor) CollectProxyPattern(txHash common.Hash, proxyContractInfo, implementationContractInfo *ContractInfo) {
	dbKey := ProxyPatternKey.String() + "_" + txHash.String()
	data, err := m.monitordb.Get([]byte(dbKey))
	if nil != err && err != ErrNotFound {
		log.Error("failed to load proxy patterns", "err", err)
		return
	}

	var proxyPatternList []*ProxyPattern
	ParseJson(data, &proxyPatternList)
	proxyPatternList = append(proxyPatternList, &ProxyPattern{Proxy: proxyContractInfo, Implementation: implementationContractInfo})

	json := ToJson(proxyPatternList)
	if len(json) > 0 {
		m.monitordb.Put([]byte(dbKey), json)
		log.Debug("save proxy patterns success")
	}

	// === to save the proxy map to local db

	dbMapKey := proxyPatternMapKey.String()
	data, err = m.monitordb.Get([]byte(dbMapKey))
	if nil != err && err != ErrNotFound {
		log.Error("failed to load proxy map", "err", err)
		return
	}

	var proxyPatternMap = make(map[common.Address]common.Address)
	ParseJson(data, &proxyPatternMap)
	proxyPatternMap[proxyContractInfo.Address] = implementationContractInfo.Address

	json = ToJson(proxyPatternMap)
	if len(json) > 0 {
		m.monitordb.Put([]byte(dbMapKey), json)
		log.Debug("save proxy map success")
	}
}

func (m *Monitor) IsProxied(self, target common.Address) bool {
	dbMapKey := proxyPatternMapKey.String()
	data, err := m.monitordb.Get([]byte(dbMapKey))
	if nil != err && err != ErrNotFound {
		log.Error("failed to load proxy map", "err", err)
		return false
	}

	var proxyPatternMap map[common.Address]common.Address
	ParseJson(data, &proxyPatternMap)
	if value, exist := proxyPatternMap[self]; exist {
		if value == target {
			return true
		}
	}
	return false
}

// GetProxyPatterns 查询某个交易上发现的代理关系
// scan可以通过Rpc接口：GetExtReceipts，获取每个交易发现的代理关系
func (m *Monitor) GetProxyPatterns(blockNumber uint64, txHash common.Hash) []*ProxyPattern {
	log.Debug("GetProxyPattern", "blockNumber", blockNumber, "txHash", txHash.Hex())

	dbKey := ProxyPatternKey.String() + "_" + txHash.String()
	data, err := m.monitordb.Get([]byte(dbKey))
	if nil != err && err != ErrNotFound {
		log.Error("failed to load proxy patterns", "err", err)
		return nil
	}
	var proxyPatternList []*ProxyPattern
	ParseJson(data, &proxyPatternList)

	log.Debug("get proxy patterns success")
	return proxyPatternList
}

// epoch切换时，收集下一个epoch的相关信息
func (m *Monitor) CollectionNextEpochInfo(epoch uint64, newBlockReward, epochTotalStakingReward *big.Int, chainAge uint32, yearStartBlockNumber uint64, remainEpochThisYear uint32, avgPackTime uint64) {
	view := EpochView{
		PackageReward:     newBlockReward,
		StakingReward:     epochTotalStakingReward,
		ChainAge:          chainAge + 1, // ChainAge starts from 1
		YearStartBlockNum: yearStartBlockNumber,
		YearEndBlockNum:   yearStartBlockNumber + uint64(remainEpochThisYear)*xutil.CalcBlocksEachEpoch(),
		RemainEpoch:       remainEpochThisYear,
		AvgPackTime:       avgPackTime,
	}
	json := ToJson(view)
	dbKey := EpochInfoKey.String() + "_" + strconv.FormatUint(epoch, 10)
	m.monitordb.Put([]byte(dbKey), json)
	log.Debug("CollectionNextEpochInfo", "data", string(json))
}
func (m *Monitor) CollectInitValidators(blockHash common.Hash, blockNumber uint64, queryStartNotIrr bool) {
	curValidators, err := m.stakingPlugin.GetCurrValList(blockHash, blockNumber, queryStartNotIrr)
	if nil != err {
		log.Error("Failed to CollectInitEpochValidators", "blockNumber", blockHash, "blockHash", blockNumber, "err", err)
		return
	}

	log.Info("CollectInitValidators:", "blockNumber", blockNumber, "size", len(curValidators.Arr))
	for idx, item := range curValidators.Arr {
		log.Info("CollectInitValidators:", "idx", idx, "nodeId", item.NodeId, "stakingBlockNum", item.StakingBlockNum)
	}

	validatorExQueue, err := m.convertToValidatorExQueue(blockHash, blockNumber, curValidators)
	if nil != err {
		log.Error("Failed to convertToValidatorExQueue", "blockNumber", blockNumber, "blockHash", blockHash.Hex(), "err", err)
		return
	}
	json := ToJson(validatorExQueue)

	dbKey := ValidatorsOfEpochKey.String() + strconv.FormatUint(0, 10)

	m.monitordb.Put([]byte(dbKey), json)
	log.Debug("success to CollectInitEpochValidators", "blockNumber", blockNumber, "blockHash", blockHash.String(), "dbKey", dbKey)
	return
}

// CollectNextEpochValidators 在上个epoch的结束块高上，收集新的validator名单（25名单，包含详细信息）
// epoch轮数从1开始，key的组成是：ValidatorsOfEpochKey+每个epoch轮的开始块高
func (m *Monitor) CollectNextEpochValidators(blockHash common.Hash, blockNumber uint64, queryStartNotIrr bool) {
	nextValidators, err := m.stakingPlugin.GetNextValList(blockHash, blockNumber, queryStartNotIrr)
	if nil != err {
		log.Error("Failed to CollectNextEpochValidators", "blockNumber", blockNumber, "blockHash", blockHash.Hex(), "err", err)
		return
	}
	log.Info("CollectNextEpochValidators:", "blockNumber", blockNumber, "size", len(nextValidators.Arr))
	for idx, item := range nextValidators.Arr {
		log.Info("CollectNextEpochValidators:", "idx", idx, "nodeId", item.NodeId, "stakingBlockNum", item.StakingBlockNum)
	}

	validatorExQueue, err := m.convertToValidatorExQueue(blockHash, blockNumber, nextValidators)
	if nil != err {
		log.Error("Failed to convertToValidatorExQueue", "blockNumber", blockNumber, "blockHash", blockHash.Hex(), "err", err)
		return
	}
	json := ToJson(validatorExQueue)

	dbKey := ValidatorsOfEpochKey.String() + strconv.FormatUint(blockNumber+xcom.ElectionDistance(), 10)

	m.monitordb.Put([]byte(dbKey), json)
	log.Debug("success to CollectNextEpochValidators", "blockNumber", blockNumber, "blockHash", blockHash.String(), "dbKey", dbKey)
	return
}

func (m *Monitor) CollectInitVerifiers(blockHash common.Hash, blockNumber uint64, queryStartNotIrr bool) {
	//获取201名单（只包含必要信息）
	verifiers, err := m.stakingPlugin.GetVerifierArray(blockHash, blockNumber, queryStartNotIrr)
	if nil != err {
		log.Error("Failed to Query Current Round verifiers on stakingPlugin Confirmed When Settletmetn block",
			"blockHash", blockHash.Hex(), "blockNumber", blockNumber, "err", err)
		return
	}

	log.Info("CollectInitVerifiers:", "blockNumber", blockNumber, "size", len(verifiers.Arr))
	for idx, item := range verifiers.Arr {
		log.Info("CollectInitVerifiers:", "idx", idx, "nodeId", item.NodeId, "stakingBlockNum", item.StakingBlockNum)
	}

	log.Debug("CollectInitVerifiers:", "size", len(verifiers.Arr), "data:", ToJson(verifiers))
	validatorExQueue, err := m.convertToValidatorExQueue(blockHash, blockNumber, verifiers)
	if nil != err {
		log.Error("failed to convertToValidatorExQueue", "blockHash", blockHash.Hex(), "blockNumber", blockNumber, "err", err)
		return
	}
	json := ToJson(validatorExQueue)

	dbKey := VerifiersOfEpochKey.String() + strconv.FormatUint(1, 10)

	m.monitordb.Put([]byte(dbKey), json)
	log.Debug("success to CollectInitVerifiers", "blockNumber", blockNumber, "blockHash", blockHash.String(), "dbKey", dbKey)
	return
}

// CollectNextEpochVerifiers 保存201名单（包含详细信息）
// CollectNextEpochVerifiers 在上个epoch的结束块高上，收集新的Verifiers名单（201名单，包含详细信息）
// epoch轮数从1开始，key的组成是：VerifiersOfEpochKey+每个epoch轮的开始块高
func (m *Monitor) CollectNextEpochVerifiers(blockHash common.Hash, blockNumber uint64, queryStartNotIrr bool) {
	//获取201名单（只包含必要信息）
	verifiers, err := m.stakingPlugin.GetVerifierArray(blockHash, blockNumber, queryStartNotIrr)
	if nil != err {
		log.Error("Failed to Query Current Round verifiers on stakingPlugin Confirmed When Settletmetn block",
			"blockHash", blockHash.Hex(), "blockNumber", blockNumber, "err", err)
		return
	}
	log.Debug("CollectNextEpochVerifiers:", "blockNumber", blockNumber, "size", len(verifiers.Arr))
	for idx, item := range verifiers.Arr {
		log.Info("CollectNextEpochVerifiers:", "idx", idx, "nodeId", item.NodeId, "stakingBlockNum", item.StakingBlockNum)
	}

	validatorExQueue, err := m.convertToValidatorExQueue(blockHash, blockNumber, verifiers)
	if nil != err {
		log.Error("failed to convertToValidatorExQueue", "blockNumber", blockNumber, "blockHash", blockHash.Hex(), "err", err)
		return
	}
	json := ToJson(validatorExQueue)

	nextEpoch := xutil.CalculateEpoch(blockNumber) + 1
	if blockNumber == 1 {
		nextEpoch = 1
	}
	dbKey := VerifiersOfEpochKey.String() + strconv.FormatUint(nextEpoch, 10)

	m.monitordb.Put([]byte(dbKey), json)
	log.Debug("success to CollectNextEpochVerifiers", "blockNumber", blockNumber, "blockHash", blockHash.String(), "dbKey", dbKey)
	return
}

func (m *Monitor) convertToValidatorExQueue(blockHash common.Hash, blockNumber uint64, validatorList *staking.ValidatorArray) (staking.ValidatorExQueue, error) {
	//获取所有质押节点（包含详细信息，25中的提出退出节点，不再存在此列表中）
	currentCandidate, err := m.stakingPlugin.GetCandidateList(blockHash, blockNumber)
	if nil != err {
		log.Error("Failed to GetCandidateList", "blockHash", blockHash.Hex(), "blockNumber", blockNumber, "err", err)
		return nil, err
	}
	validatorExQueue := make(staking.ValidatorExQueue, len(validatorList.Arr))
	for k, v := range validatorList.Arr {
		validatorExQueue[k] = &staking.ValidatorEx{
			ValidatorTerm:   v.ValidatorTerm,
			NodeId:          v.NodeId,
			StakingBlockNum: v.StakingBlockNum,
			ProgramVersion:  v.ProgramVersion,
			ValidatorId:     v.ValidatorId,
		}
		var notInCadidateList = true
		// 给ValidatorEx补充详细信息
		for _, cv := range currentCandidate {
			if cv.NodeId == v.NodeId {
				/*validatorExQueue[k].DelegateRewardTotal = cv.DelegateRewardTotal
				validatorExQueue[k].DelegateTotal = cv.DelegateTotal
				validatorExQueue[k].BenefitAddress = cv.BenefitAddress
				validatorExQueue[k].StakingAddress = cv.StakingAddress
				validatorExQueue[k].Website = cv.Website
				validatorExQueue[k].Description = cv.Description
				validatorExQueue[k].ExternalId = cv.ExternalId
				validatorExQueue[k].NodeName = cv.NodeName*/
				//validatorExQueue[k].StakingAddress = cv.StakingAddress
				notInCadidateList = false
				break
			}
		}
		if notInCadidateList {
			// 不在currentCandidate的verifier，需要额外补充详细信息
			//nodeIdAddr, err := xutil.NodeId2Addr(v.NodeId)
			nodeIdAddr := v.ValidatorId
			if nil != err {
				log.Error("Failed to NodeId2Addr: parse current nodeId is failed", "err", err)
			}
			can, err := m.stakingPlugin.GetCandidateInfo(blockHash, nodeIdAddr)
			if err != nil || can == nil {
				log.Error("Failed to Query Current Round candidate info on stakingPlugin Confirmed When Settletmetn block",
					"blockHash", blockHash.Hex(), "blockNumber", blockNumber, "err", err)
				log.Debug("Failed get can :", can)
			} else {
				/*validatorExQueue[k].DelegateRewardTotal = (*hexutil.Big)(can.DelegateRewardTotal)
				validatorExQueue[k].DelegateTotal = (*hexutil.Big)(can.DelegateTotal)
				validatorExQueue[k].BenefitAddress = can.BenefitAddress
				validatorExQueue[k].StakingAddress = can.StakingAddress
				validatorExQueue[k].Website = can.Website
				validatorExQueue[k].Description = can.Description
				validatorExQueue[k].ExternalId = can.ExternalId
				validatorExQueue[k].NodeName = can.NodeName*/
				validatorExQueue[k].StakingAddress = can.StakingAddress
				validatorExQueue[k].ProgramVersion = can.ProgramVersion
			}
		}
	}
	return validatorExQueue, nil
}

// 收集隐式的ppos交易数据
func (m *Monitor) CollectImplicitPPOSTx(blockNumber uint64, txHash common.Hash, from, to common.Address, input, result []byte) {
	dbKey := ImplicitPPOSTxKey.String() + "_" + strconv.FormatUint(blockNumber, 10)
	data, err := m.monitordb.Get([]byte(dbKey))
	if nil != err && err != ErrNotFound {
		log.Error("failed to load data from local db", "err", err)
		return
	}

	var implicitPPOSTx *ImplicitPPOSTx
	if len(data) == 0 {
		implicitPPOSTx = &ImplicitPPOSTx{PPOSTxMap: make(map[common.Hash][]*PPOSTx)}
	} else {
		ParseJson(data, &implicitPPOSTx)
	}
	contractTx := &PPOSTx{From: from, To: to, Input: input, Result: result}
	implicitPPOSTx.PPOSTxMap[txHash] = append(implicitPPOSTx.PPOSTxMap[txHash], contractTx)
	json := ToJson(implicitPPOSTx)
	if len(json) > 0 {
		m.monitordb.Put([]byte(dbKey), json)
	}
}

func (m *Monitor) CollectSlashInfo(electionBlockNumber uint64, slashQueue staking.SlashQueue) {
	if slashQueue == nil || len(slashQueue) == 0 {
		return
	}
	dbKey := SlashKey.String() + "_" + strconv.FormatUint(electionBlockNumber, 10)
	json := ToJson(slashQueue)

	err := m.monitordb.Put([]byte(dbKey), json)
	if nil != err && err != ErrNotFound {
		log.Error("failed to CollectSlashInfo", "electionBlockNumber", electionBlockNumber, "err", err)
		return
	}
}
