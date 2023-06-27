package helper

import (
	"github.com/PlatONnetwork/AppChain-Go/rootchain/innerbindings/innerstake"
	"github.com/PlatONnetwork/AppChain-Go/rootchain/innerbindings/rootchain"
	"github.com/PlatONnetwork/AppChain-Go/rootchain/innerbindings/stakinginfo"
)

var (
	latestListenBlockNumberKey = []byte("latestListenBlockNumber")

	InnerStakeAbi, _  = innerstake.InnerstakeMetaData.GetAbi()
	StakingInfoAbi, _ = stakinginfo.StakinginfoMetaData.GetAbi()
	RootChainAbi, _   = rootchain.RootchainMetaData.GetAbi()

	Staked         = "Staked"
	UnstakeInit    = "UnstakeInit"
	SignerChange   = "SignerChange"
	StakeUpdate    = "StakeUpdate"
	NewHeaderBlock = "NewHeaderBlock"
	StakeStateSync = "stakeStateSync"
	BlockNumber    = "blockNumber"

	StakedID         = StakingInfoAbi.Events[Staked].ID
	UnstakeInitID    = StakingInfoAbi.Events[UnstakeInit].ID
	SignerChangeID   = StakingInfoAbi.Events[SignerChange].ID
	StakeUpdateID    = StakingInfoAbi.Events[StakeUpdate].ID
	NewHeaderBlockID = RootChainAbi.Events[NewHeaderBlock].ID
)
