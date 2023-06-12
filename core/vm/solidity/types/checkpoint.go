package types

import (
	"bytes"
	"encoding/json"
	"math/big"
	"reflect"

	"github.com/PlatONnetwork/PlatON-Go/accounts/abi"
	"github.com/PlatONnetwork/PlatON-Go/common"
	"github.com/PlatONnetwork/PlatON-Go/common/hexutil"
)

var (
	// CheckpointPrimitives is the primitive ABI types for each Checkpoint field.
	CheckpointPrimitives = []abi.ArgumentMarshaling{
		{Name: "proposer", InternalType: "Proposer", Type: "address"},
		{Name: "start", InternalType: "Start", Type: "uint256"},
		{Name: "end", InternalType: "End", Type: "uint256"},
		{Name: "rootHash", InternalType: "RootHash", Type: "bytes32"},
		{Name: "accountHash", InternalType: "AccountHash", Type: "bytes32"},
		{Name: "chainId", InternalType: "ChainId", Type: "uint256"},
		{Name: "current", InternalType: "Current", Type: "uint256[]"},
		{Name: "rewards", InternalType: "Rewards", Type: "uint256[]"},
		{Name: "slashing", InternalType: "Slashing", Type: "uint256[]"},
	}

	// CheckpointType is the ABI type of a Checkpoint.
	CheckpointType, _ = abi.NewType("tuple", "checkpoint", CheckpointPrimitives)
)

func getAbiArgs() abi.Arguments {
	return abi.Arguments{
		{Name: "Checkpoint", Type: CheckpointType},
	}
}

// Checkpoint represents snapshots of the AppChain state and is supposed to be attested by 2/3+ of the
// validator set before it is validated and submitted on the contracts deployed on PlatON.
type Checkpoint struct {
	Proposer    common.Address `json:"proposer"`
	Start       *big.Int       `json:"start"`
	End         *big.Int       `json:"end"`
	RootHash    common.Hash    `json:"rootHash"`
	AccountHash common.Hash    `json:"accountHash"`
	ChainId     *big.Int       `json:"chainId"`
	Current     []*big.Int     `json:"current"`
	Rewards     []*big.Int     `json:"-"`
	Slashing    []*big.Int     `json:"-"`
}

func (cp *Checkpoint) String() string {
	b, _ := json.Marshal(cp)
	return string(b)
}

// Pack returns a standard message of the Checkpoint.
func (cp *Checkpoint) Pack() []byte {
	args := getAbiArgs()
	packed, _ := args.Pack(&struct {
		Proposer    common.Address
		Start       *big.Int
		End         *big.Int
		RootHash    common.Hash
		AccountHash common.Hash
		ChainId     *big.Int
		Current     []*big.Int
		Rewards     []*big.Int
		Slashing    []*big.Int
	}{
		cp.Proposer,
		cp.Start,
		cp.End,
		cp.RootHash,
		cp.AccountHash,
		cp.ChainId,
		cp.Current,
		cp.Rewards,
		cp.Slashing,
	})

	enc := hexutil.Encode(packed)
	enc = "0x" + enc[66:]
	return (hexutil.MustDecode(enc))

}

func (cp *Checkpoint) Equal(other *Checkpoint) bool {
	return bytes.Equal(cp.Proposer.Bytes(), other.Proposer.Bytes()) &&
		cp.Start.Cmp(other.Start) == 0 &&
		cp.End.Cmp(other.End) == 0 &&
		bytes.Equal(cp.RootHash.Bytes(), other.RootHash.Bytes()) &&
		bytes.Equal(cp.AccountHash.Bytes(), other.AccountHash.Bytes()) &&
		cp.ChainId.Cmp(other.ChainId) == 0 &&
		reflect.DeepEqual(cp.Current, other.Current) &&
		reflect.DeepEqual(cp.Rewards, other.Rewards) &&
		reflect.DeepEqual(cp.Slashing, other.Slashing)
}
