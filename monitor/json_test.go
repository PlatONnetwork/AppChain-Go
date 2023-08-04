package monitor

import (
	"github.com/PlatONnetwork/AppChain-Go/common"
	"github.com/PlatONnetwork/AppChain-Go/p2p/discover"
	"github.com/PlatONnetwork/AppChain-Go/x/staking"
	"math/big"
	"testing"
)

func TestJsonEncode(t *testing.T) {
	epochView := EpochView{
		PackageReward:     new(big.Int).SetUint64(uint64(12312312312312312)),
		StakingReward:     common.Big32,
		ChainAge:          4 + 1,
		YearStartBlockNum: 0,
		YearEndBlockNum:   1,
		RemainEpoch:       4,
		AvgPackTime:       2 * 1000,
	}
	dataReward := ToJson(epochView)
	t.Logf("dataReward:%s", string(dataReward))
}

func TestGetReceiptExt(t *testing.T) {
	fields := map[string]interface{}{
		"transactionHash":  common.Hash{0x01},
		"transactionIndex": int64(12),

		"gasUsed": uint64(12),

		"contractAddress": nil,
	}
	t.Logf("dataReward:%s", string(ToJson(fields)))
}
func TestAccountView(t *testing.T) {
	balance, _ := new(big.Int).SetString("20000000000000000000000000000", 10)
	accountView := &AccountView{
		Account:     common.Address{0x1},
		FreeBalance: balance,
		// 锁仓锁定的余额
		RestrictingPlanLockedAmount: new(big.Int).SetUint64(uint64(491292)),
		// 锁仓欠释放的余额
		RestrictingPlanPledgeAmount: new(big.Int).SetUint64(uint64(491292)),
		// 锁定结束的委托金，资金来源是用户账户余额
		DelegationUnLockedFreeBalance: new(big.Int).SetUint64(uint64(491292)),
		// 锁定结束的委托金，资金来源是锁仓计划。用户来领取委托金时，一部分可以直接释放到用户账户；一部分可能重新回到锁仓计划中
		DelegationUnLockedRestrictingPlanAmount: new(big.Int).SetUint64(uint64(491292)),
		// 委托冻结冻结中明细
		DelegationLockedItems: make([]DelegationLockedItem, 0),
	}

	lockItem := DelegationLockedItem{
		ExpiredEpoch:          uint32(12),
		FreeBalance:           new(big.Int).SetUint64(uint64(491292)),
		RestrictingPlanAmount: new(big.Int).SetUint64(uint64(491292)),
	}
	accountView.DelegationLockedItems = append(accountView.DelegationLockedItems, lockItem)
	jsonByte := ToJson(accountView)

	t.Logf("accountView:%s", string(jsonByte))
	var view AccountView
	ParseJson(jsonByte, &view)

	t.Logf("view:%s", view.Account.Hex())

}

func TestValidatorEx(t *testing.T) {
	/*desc := staking.Description{
		NodeName: "testNode",
		Website:  "http://url",
	}*/
	validatorEx := &staking.ValidatorEx{
		NodeId:         discover.MustHexID("0x362003c50ed3a523cdede37a001803b8f0fed27cb402b3d6127a1a96661ec202318f68f4c76d9b0bfbabfd551a178d4335eaeaa9b7981a4df30dfc8c0bfe3384"),
		StakingAddress: common.Address{0x01},
		//Description:    desc,
	}

	jsonByte := ToJson(validatorEx)

	t.Logf("validatorEx:%s", string(jsonByte))
	var view staking.ValidatorEx
	ParseJson(jsonByte, &view)

	t.Logf("validatorEx.name:%s", view.StakingAddress.Hex())
}

func TestRootChainTx_Staking(t *testing.T) {
	staking := Staking{common.Address{0x01}, uint64(1), discover.NodeID{0x02}, uint64(1443324423)}
	rootChainTxParam := RootChainTxParam{uint64(1000), common.Hash{0x1}, 1}
	rootChainTx := &RootChainTx{Stake, common.Hash{0x02}, staking, rootChainTxParam}

	jsonByte := ToJson(rootChainTx)
	t.Logf("jsonByte1:%s", string(jsonByte))
	var view RootChainTx
	ParseJson(jsonByte, &view)

	jsonByte2 := ToJson(view)
	t.Logf("jsonByte2:%s", string(jsonByte2))
}
