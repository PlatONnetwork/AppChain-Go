package helper

import (
	"bytes"
	"github.com/PlatONnetwork/AppChain-Go/common/vm"
	"github.com/PlatONnetwork/AppChain-Go/core/types"
	"math/big"
)

func EncodeStakeStateSync(blockNumber *big.Int, logs []*types.Log) ([]byte, error) {
	var events [][]byte
	for _, log := range logs {
		buffer := bytes.NewBuffer([]byte{})
		if err := log.EncodeRLP(buffer); err != nil {
			return nil, err
		}
		events = append(events, buffer.Bytes())
	}
	bytes, err := InnerStakeAbi.Pack(StakeStateSync, blockNumber, events)
	return bytes, err
}

func FindStakeStateSyncTxs(transactions types.Transactions) []*types.Transaction {
	var res []*types.Transaction
	for _, tx := range transactions {
		if *tx.To() == vm.StakingContractAddr && bytes.Equal(tx.Data()[0:4], InnerStakeAbi.Methods[StakeStateSync].ID) {
			res = append(res, tx)
		}
	}
	return res
}
