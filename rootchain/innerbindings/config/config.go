package config

import (
	"github.com/PlatONnetwork/AppChain-Go/common"
	"math/big"
)

type RootChainContractConfig struct {
	PlatonRPCAddr          string         `json:"rpcAddress"`
	ContractDeployedNumber uint64         `json:"contractDeployedNumber"`
	RootChainID            *big.Int       `json:"rootChainId"`
	StakingInfoAddress     common.Address `json:"stakingInfoAddress"`
	RootChainAddress       common.Address `json:"rootChainAddress"`
	// When packing events, the height of the latest listened event - x = the block height of the packing cut-off.
	DelayNumbers uint64 `json:"delayNumbers"`
}
