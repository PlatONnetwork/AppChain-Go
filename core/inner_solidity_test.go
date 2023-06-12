package core

import (
	"github.com/PlatONnetwork/PlatON-Go/common"
	"github.com/PlatONnetwork/PlatON-Go/common/vm"
	"github.com/PlatONnetwork/PlatON-Go/consensus"
	"github.com/PlatONnetwork/PlatON-Go/core/rawdb"
	"github.com/PlatONnetwork/PlatON-Go/core/state"
	"github.com/PlatONnetwork/PlatON-Go/core/types"
	vm2 "github.com/PlatONnetwork/PlatON-Go/core/vm"
	"github.com/PlatONnetwork/PlatON-Go/crypto"
	"github.com/PlatONnetwork/PlatON-Go/innerbindings/helper"
	"github.com/PlatONnetwork/PlatON-Go/innerbindings/innerstake"
	"github.com/PlatONnetwork/PlatON-Go/params"
	"github.com/stretchr/testify/require"
	"math/big"
	"testing"
)

var (
	private, _ = crypto.HexToECDSA("5cd44b68d91f4b42dc240c658fee14922a0e26245ed6f406c0015bb50cf66431")
	from       = crypto.PubkeyToAddress(private.PublicKey)
)

type MockChainContext struct {
}

func (m MockChainContext) Engine() consensus.Engine {
	return nil
}

func (m MockChainContext) GetHeader(hash common.Hash, n uint64) *types.Header {
	parentHash := common.Hash{}
	s := common.LeftPadBytes(big.NewInt(int64(n-1)).Bytes(), 32)
	copy(parentHash[:], s)
	header := types.Header{
		Coinbase:   common.HexToAddress("0x00000000000000000000000000000000deadbeef"),
		Number:     big.NewInt(int64(n)),
		ParentHash: parentHash,
		Time:       1000,
		Nonce:      types.BlockNonce{0x1},
		Extra:      []byte{},
		GasLimit:   100000,
	}
	return &header
}

func TestInnerStake(t *testing.T) {
	chainConfig := &params.ChainConfig{
		ChainID:     big.NewInt(101),
		PIP7ChainID: big.NewInt(101),
		AddressHRP:  "lat",
		EmptyBlock:  "",
		EIP155Block: big.NewInt(0),
		EWASMBlock:  big.NewInt(0),
		Clique:      nil,
		Cbft: &params.CbftConfig{
			Amount:        10,
			ValidatorMode: "ppos",
			Period:        20000,
		},
		GenesisVersion: 0,
	}
	signer = types.NewEIP155Signer(big.NewInt(101))

	chainContext := &MockChainContext{}
	gp := new(GasPool).AddGas(10000000000)
	sdb := state.NewDatabase(rawdb.NewMemoryDatabase())
	stateDb, _ := state.New(common.Hash{}, sdb)

	header := &types.Header{
		Coinbase:   common.HexToAddress("0x00000000000000000000000000000000deadbeef"),
		Number:     big.NewInt(int64(0)),
		ParentHash: common.Hash{},
		Time:       1000,
		Nonce:      types.BlockNonce{0x1},
		Extra:      []byte{},
		GasLimit:   100000,
	}
	usedGas := uint64(0)
	createTx := func() *types.Transaction {
		data, err := helper.EncodeStakeStateSync(big.NewInt(1), nil)
		require.Nil(t, err)
		tx := types.NewTransaction(0, vm.StakingContractAddr, nil, 100000, big.NewInt(0), data)
		require.Nil(t, err)
		tx, err = Sign(tx, nil)
		require.Nil(t, err)
		return tx
	}
	tx := createTx()
	stateDb.Prepare(tx.Hash(), header.Hash(), 0)
	receipts, err := ApplyTransaction(chainConfig, chainContext, gp, stateDb, header, tx, &usedGas, vm2.Config{})
	require.Nil(t, err)
	require.NotNil(t, receipts)
	require.Equal(t, 1, len(receipts.Logs))
	log := receipts.Logs[0]

	stake, err := innerstake.NewInnerstake(common.Address{}, nil)
	require.Nil(t, err)
	innerstake, err := stake.ParseStakeStateSync(*log)
	require.Nil(t, err)
	require.Equal(t, big.NewInt(0).Uint64(), innerstake.Start.Uint64())
	require.Equal(t, big.NewInt(1), innerstake.End)

}
func Sign(tx *types.Transaction, chainId *big.Int) (*types.Transaction, error) {
	signature, err := crypto.Sign(signer.Hash(tx, chainId).Bytes(), private)
	if err != nil {
		return nil, err
	}
	tx, err = tx.WithSignature(signer, signature)
	return tx, nil
}
