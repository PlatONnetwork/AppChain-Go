package helper

import (
	"github.com/PlatONnetwork/PlatON-Go/rootchain/innerbindings/innerstake"
	"github.com/PlatONnetwork/PlatON-Go/rootchain/innerbindings/rootchain"
	"github.com/PlatONnetwork/PlatON-Go/rootchain/innerbindings/stakinginfo"
)

var (
	latestListenBlockNumberKey = []byte("latestListenBlockNumber")

	InnerStakeAbi, _  = innerstake.InnerstakeMetaData.GetAbi()
	StakingInfoAbi, _ = stakinginfo.StakinginfoMetaData.GetAbi()
	RootChainAbi, _   = rootchain.RootchainMetaData.GetAbi()
	//质押
	Staked = "Staked"
	//发起解质押
	UnstakeInit = "UnstakeInit"
	//解质押锁定期结束后，赎回质押
	Unstaked = "Unstaked"
	//修改节点ID
	SignerChange = "SignerChange"
	//委托
	ShareMinted = "ShareMinted"
	//撤销委托
	ShareBurned    = "ShareBurned"
	NewHeaderBlock = "NewHeaderBlock"
	StakeStateSync = "stakeStateSync"
	BlockNumber    = "blockNumber"

	StakedID         = StakingInfoAbi.Events[Staked].ID
	UnstakeInitID    = StakingInfoAbi.Events[UnstakeInit].ID
	UnstakedID       = StakingInfoAbi.Events[Unstaked].ID
	SignerChangeID   = StakingInfoAbi.Events[SignerChange].ID
	ShareMintedID    = StakingInfoAbi.Events[ShareMinted].ID
	ShareBurnedID    = StakingInfoAbi.Events[ShareBurned].ID
	NewHeaderBlockID = RootChainAbi.Events[NewHeaderBlock].ID
)
