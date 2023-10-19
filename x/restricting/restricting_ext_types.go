package restricting

import (
	"github.com/PlatONnetwork/PlatON-Go/common"
	"github.com/PlatONnetwork/PlatON-Go/common/hexutil"
)

type BalanceResult struct {
	// 用户账户
	Account common.Address `json:"account"`
	// 自由金余额
	FreeBalance *hexutil.Big `json:"freeBalance"`
	// 锁仓锁定的余额
	LockBalance *hexutil.Big `json:"lockBalance"`
	// 锁仓欠释放的余额
	PledgeBalance *hexutil.Big `json:"pledgeBalance"`
	// 委托冻结待提取的自由金约
	DLFreeBalance *hexutil.Big `json:"dlFreeBalance"`
	// 委托冻结待提取的锁仓金约
	DLRestrictingBalance *hexutil.Big `json:"dlRestrictingBalance"`
	// 委托冻结冻结中明细
	Locks []DelegationLockPeriodResult `json:"dlLocks"`
}

type DelegationLockPeriodResult struct {
	// 锁定截止周期
	Epoch uint32 `json:"epoch"`
	//处于锁定期的委托金,解锁后释放到用户余额
	Released *hexutil.Big `json:"freeBalance"`
	//处于锁定期的委托金,解锁后释放到用户锁仓账户
	RestrictingPlan *hexutil.Big `json:"lockBalance"`
}
