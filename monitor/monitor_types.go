package monitor

import (
	"github.com/PlatONnetwork/AppChain-Go/common"
	"github.com/PlatONnetwork/AppChain-Go/x/restricting"
	"github.com/PlatONnetwork/AppChain-Go/x/staking"
	"github.com/PlatONnetwork/AppChain-Go/x/xcom"
	"math/big"
)

type ContractRef interface {
	Address() common.Address
}

type Intf_stakingPlugin interface {
	GetNextValList(blockHash common.Hash, blockNumber uint64, isCommit bool) (*staking.ValidatorArray, error)
	GetCurrValList(common.Hash, uint64, bool) (*staking.ValidatorArray, error)
	GetVerifierArray(common.Hash, uint64, bool) (*staking.ValidatorArray, error)
	GetCandidateList(common.Hash, uint64) (staking.CandidateHexQueue, error)
	GetCandidateInfo(common.Hash, *big.Int) (*staking.Candidate, error)
	GetNodeVersion(blockHash common.Hash) (staking.ValidatorExQueue, error)
	GetGetDelegationLockCompactInfo(blockHash common.Hash, blockNumber uint64, delAddr common.Address) (*staking.DelegationLockHex, error)
}
type Intf_restrictingPlugin interface {
	MustGetRestrictingInfoByDecode(state xcom.StateDB, account common.Address) ([]byte, restricting.RestrictingInfo, *common.BizError)
}

// 隐含的PPOS交易。
// 通常来说，PPOS交易是有用户直接发给相应内置合约的。
// 不过，用户自己部署的智能合约，也可以调用内置合约。这样，区块中的交易，看上去是个普通合约调用，但实际上，隐式的调用了PPOS合约（包括多次调用），产生了隐式的PPOS交易（多条），SCAN需要知道这些隐式PPOS交易的相关信息
type PPOSTx struct {
	From   common.Address
	To     common.Address
	Input  []byte
	Result []byte
}

type ImplicitPPOSTx struct {
	//key=原始交易hash
	//value=PPOSTx
	PPOSTxMap map[common.Hash][]*PPOSTx
}

// 通常的转账交易是from/to/value，
// 而还有一些不寻常的交易会引起账户余额变化，比如：
// 1. 调用合约时，带上了value，evm执行时，会首先进行from/to的账户余额变动
// 2. 合约销毁时，引起账户余额变化
type UnusualTransfer struct {
	TxHash common.Hash    `json:"txHash,-"`
	From   common.Address `json:"from,omitempty"`
	To     common.Address `json:"to,omitempty"`
	Amount *big.Int       `json:"amount,omitempty"`
}

type ProxyPattern struct {
	Proxy          *ContractInfo `json:"proxy,omitempty"`
	Implementation *ContractInfo `json:"implementation,omitempty"`
}

type EpochView struct {
	NextPackageReward *big.Int `json:"nextPackageReward"`
	NextStakingReward *big.Int `json:"nextStakingReward"`
	PackageReward     *big.Int `json:"packageReward"`
	StakingReward     *big.Int `json:"stakingReward"`
	ChainAge          uint32   `json:"chainAge"` //starts from 1
	YearStartBlockNum uint64   `json:"yearStartBlockNum"`
	YearEndBlockNum   uint64   `json:"yearEndBlockNum"`
	RemainEpoch       uint32   `json:"remainEpoch"`
	AvgPackTime       uint64   `json:"avgPackTime"`
}

type AccountView struct {
	// 用户账户
	Account common.Address `json:"account"`
	// 账户余额
	FreeBalance *big.Int `json:"freeBalance"`
	// 锁仓锁定的余额
	RestrictingPlanLockedAmount *big.Int `json:"restrictingPlanLockedAmount,omitempty"`
	// 锁仓欠释放的余额
	RestrictingPlanPledgeAmount *big.Int `json:"restrictingPlanPledgeAmount,omitempty"`
	// 锁定结束的委托金，资金来源是用户账户余额
	DelegationUnLockedFreeBalance *big.Int `json:"delegationUnLockedFreeBalance,omitempty"`
	// 锁定结束的委托金，资金来源是锁仓计划。用户来领取委托金时，一部分可以直接释放到用户账户；一部分可能重新回到锁仓计划中
	DelegationUnLockedRestrictingPlanAmount *big.Int `json:"delegationUnLockedRestrictingPlanAmount,omitempty"`
	// 委托冻结冻结中明细
	DelegationLockedItems []DelegationLockedItem `json:"delegationLockedItems,omitempty"`
}

type DelegationLockedItem struct {
	// 锁定截止周期
	ExpiredEpoch uint32 `json:"expiredEpoch,omitempty"`
	// 处于锁定期的委托金，资金来源是用户账户余额
	FreeBalance *big.Int `json:"FreeBalance,omitempty"`
	//处于锁定期的委托金，资金来源是锁仓计划
	RestrictingPlanAmount *big.Int `json:"restrictingPlanAmount,omitempty"`
}

type ProposalParticipants struct {
	AccuVerifierAccount uint64 `json:"accuVerifierAccount,omitempty"` //累计验证人数量（去重后）
	Yeas                uint64 `json:"yeas,omitempty"`                //赞成数
	Nays                uint64 `json:"nays,omitempty"`                //反对数
	Abstentions         uint64 `json:"abstentions,omitempty"`         //弃权数
}
