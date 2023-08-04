package monitor

import (
	"github.com/PlatONnetwork/AppChain-Go/common"
	"github.com/PlatONnetwork/AppChain-Go/core/rawdb"
	"github.com/PlatONnetwork/AppChain-Go/core/state"
	"github.com/PlatONnetwork/AppChain-Go/p2p/discover"
	"math/big"
	"testing"
)

func TestRootChainTx(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	stateDb, _ := state.New(common.Hash{}, state.NewDatabaseWithConfig(db, nil))
	SetDbFullPath("./log")
	InitMonitor(stateDb)

	txHash := common.Hash{0x01}
	dbKey := RootChainTxKey.String() + "_" + txHash.String()

	rootChainBlockNumber := uint64(100)
	rootChainTxHash := common.Hash{0x01, 0x02, 0x03, 0x04}
	rootChainTxIndex := uint(39121)

	validatorId, ok := (new(big.Int)).SetString("12727887085210734767457776618204906457722244067993100142821102040053426870704135847510776903723956104372058453245125889003054723215987990504359998922999102", 10)
	if !ok {
		t.Fatal("cannot cast to BigInteger")
	}

	monitor.CollectRootChainStakeTx(txHash, common.Address{0x01}, validatorId, discover.NodeID{0x02}, common.Big1, rootChainBlockNumber, rootChainTxHash, rootChainTxIndex)

	monitor.CollectRootChainUnStakeTx(txHash, validatorId, rootChainBlockNumber, rootChainTxHash, rootChainTxIndex)

	monitor.CollectRootChainUnStakeTx(txHash, validatorId, rootChainBlockNumber, rootChainTxHash, rootChainTxIndex)

	rootChainTxList := monitor.GetRootChainTx(uint64(12), txHash)

	txListBytes := ToJson(rootChainTxList)
	t.Logf("txlistBytes:%s", string(txListBytes))

	monitor.monitordb.Delete([]byte(dbKey))
}
