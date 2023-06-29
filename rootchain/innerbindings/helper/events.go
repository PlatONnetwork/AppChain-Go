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
	Unstaked       = "Unstaked"
	SignerChange   = "SignerChange"
	ShareMinted    = "ShareMinted"
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
