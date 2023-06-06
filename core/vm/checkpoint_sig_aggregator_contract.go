package vm

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"math/big"

	"github.com/PlatONnetwork/AppChain-Go/accounts/abi"
	"github.com/PlatONnetwork/AppChain-Go/common"
	cvm "github.com/PlatONnetwork/AppChain-Go/common/vm"
	ctypes "github.com/PlatONnetwork/AppChain-Go/core/types"
	"github.com/PlatONnetwork/AppChain-Go/core/vm/solidity"
	"github.com/PlatONnetwork/AppChain-Go/core/vm/solidity/checkpoint"
	"github.com/PlatONnetwork/AppChain-Go/core/vm/solidity/types"
	"github.com/PlatONnetwork/AppChain-Go/crypto"
	"github.com/PlatONnetwork/AppChain-Go/crypto/bls"
	"github.com/PlatONnetwork/AppChain-Go/log"
	"github.com/PlatONnetwork/AppChain-Go/rlp"
	"github.com/PlatONnetwork/AppChain-Go/x/plugin"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

var (
	cABI, _ = abi.JSON(strings.NewReader(checkpoint.CheckpointABI))

	pendingCheckpointKey = []byte("pending_checkpoint")
	latestCheckpointKey  = []byte("latest_checkpoint")

	ErrCheckpointNotFound = errors.New("checkpoint not found")
	ErrMethodNotFound     = errors.New("method not found")
	ErrValidatorNotFound  = errors.New("validator not found")
	ErrInvalidInput       = errors.New("invalid input")
	ErrInvalidCaller      = errors.New("invalid caller")
	ErrInvalidProposer    = errors.New("invalid proposer")
	ErrInvalidProposal    = errors.New("invalid proposal")
	ErrVerifySigFail      = errors.New("verfiy signature fail")
	ErrProposalTimeout    = errors.New("proposal timeout")
	ErrConfirmed          = errors.New("checkpoint proposal confirmed")
	ErrEmitted            = errors.New("already emitted")
)

const (
	NextProposeDelay = 10 // 10 blocks
)

func CheckpointABI() *abi.ABI {
	return &cABI
}

type StorageCheckpoint struct {
	types.Checkpoint
	SignedValidators []uint32
	AggSignature     []byte
	BlockNum         uint64
	Emitted          bool
}

type CheckpointSigAggregatorContract struct {
	Contract *Contract
	Evm      *EVM
}

func WritePendingCheckpoint(statedb StateDB, scp *StorageCheckpoint) error {
	return writeCheckpoint(statedb, pendingCheckpointKey, scp)
}

func ReadPendingCheckpoint(statedb StateDB) (*StorageCheckpoint, error) {
	return readCheckpoint(statedb, pendingCheckpointKey)
}

func WriteLatestCheckpoint(statedb StateDB, scp *StorageCheckpoint) error {
	return writeCheckpoint(statedb, latestCheckpointKey, scp)
}

func ReadLatestCheckpoint(statedb StateDB) (*StorageCheckpoint, error) {
	return readCheckpoint(statedb, latestCheckpointKey)
}

func writeCheckpoint(statedb StateDB, key []byte, scp *StorageCheckpoint) error {
	var val []byte
	var err error
	if scp != nil {
		val, err = rlp.EncodeToBytes(scp)
		if err != nil {
			return err
		}
	}
	statedb.SetState(cvm.CheckpointSigAggAddr, key, val)
	return nil
}

func readCheckpoint(statedb StateDB, key []byte) (*StorageCheckpoint, error) {
	val := statedb.GetState(cvm.CheckpointSigAggAddr, key)
	if len(val) == 0 {
		return nil, ErrCheckpointNotFound
	}
	var scp StorageCheckpoint
	err := rlp.DecodeBytes(val, &scp)
	return &scp, err
}

func (c *CheckpointSigAggregatorContract) RequiredGas([]byte) uint64 {
	return 0
}

func (c *CheckpointSigAggregatorContract) CheckGasPrice(*big.Int, uint16) error {
	return nil
}

func (c *CheckpointSigAggregatorContract) FnSigns() map[uint16]interface{} {
	return make(map[uint16]interface{})
}

func (c *CheckpointSigAggregatorContract) Run(input []byte) ([]byte, error) {
	if len(input) < 4 {
		return nil, ErrInvalidInput
	}

	method, err := CheckpointABI().MethodById(input[:4])
	if err != nil {
		log.Warn("CheckpointSigAggregator: method not found", "err", err)
		return nil, ErrMethodNotFound
	}

	_, err = method.Inputs.Unpack(input[4:])
	if err != nil {
		log.Warn("CheckpointSigAggregator: invalid input", "err", err)
		return nil, ErrInvalidInput
	}

	params := make([]reflect.Value, 0)
	if len(input[4:]) > 0 {
		params = append(params, reflect.ValueOf(input))
	}

	caser := cases.Title(language.English, cases.NoLower)
	fn := reflect.ValueOf(c).MethodByName(caser.String(method.Name))
	if !fn.IsValid() {
		return nil, ErrMethodNotFound
	}

	ret := fn.Call(params)
	if err, ok := ret[1].Interface().(error); ok {
		return nil, err
	}
	if buf, ok := ret[0].Interface().([]byte); ok {
		return buf, nil
	}
	return nil, nil
}

// solidity:
//
//	function propose(Checkpoint calldata cp, uint32 validatorId, bytes calldata signature) external
func (c *CheckpointSigAggregatorContract) Propose(input []byte) ([]byte, error) {
	validators, err := plugin.StakingInstance().GetValidator(c.Evm.Context.BlockNumber.Uint64())
	if err != nil {
		return nil, err
	}

	// Previous check in Run
	method, _ := CheckpointABI().MethodById(input[:4])
	inputs, _ := method.Inputs.Unpack(input[4:])

	var cp checkpoint.ICheckpointSigAggregatorCheckpoint
	var validatorId uint32
	var signature []byte

	abi.ConvertType(inputs[0], &cp)
	abi.ConvertType(inputs[1], &validatorId)
	abi.ConvertType(inputs[2], &signature)

	log.Debug("Propose checkpoint", "proposer", cp.Proposer, "start", cp.Start, "end", cp.End,
		"validatorId", validatorId, "signature", fmt.Sprintf("0x%x", signature))

	// FIXME:
	validator, err := validators.FindNodeByIndex(int(validatorId))
	if err != nil {
		log.Error("Cannot get the specified validator", "proposer", cp.Proposer, "start", cp.Start, "end", cp.End, "validatorId", validatorId)
		return nil, ErrValidatorNotFound
	}

	// FIXME: replace `Sender` to correct
	if !bytes.Equal(c.Contract.Caller().Bytes(), common.Address(validator.Address).Bytes()) {
		log.Error("Invalid caller", "proposer", cp.Proposer, "start", cp.Start, "end", cp.End, "caller", c.Contract.Caller(), "validatorId", validatorId)
		return nil, ErrInvalidCaller
	}

	// FIXME:
	if _, err := validators.FindNodeByAddress(common.NodeAddress(cp.Proposer)); err != nil {
		log.Error("The proposer not a validator", "proposer", cp.Proposer, "start", cp.Start, "end", cp.End)
		return nil, ErrInvalidProposer
	}

	tcp := solidity.ICheckpointToCheckpoint(&cp)
	packed := tcp.Pack()

	hash := crypto.Keccak256(packed)
	if err := validator.Verify(hash, signature); err != nil {
		log.Error("Verify proposer signature fail", "proposer", cp.Proposer, "start", cp.Start, "end", cp.End, "err", err)
		return nil, ErrVerifySigFail
	}

	latest, err := ReadLatestCheckpoint(c.Evm.StateDB)
	if err != nil && err != ErrCheckpointNotFound {
		return nil, err
	}

	if latest != nil && latest.End.Add(latest.End, big.NewInt(1)).Cmp(cp.Start) != 0 {
		log.Error("Invalid checkpoint proposal", "proposer", cp.Proposer, "latestEnd", latest.End, "start", cp.Start)
		return nil, ErrInvalidProposal
	}

	pending, err := ReadPendingCheckpoint(c.Evm.StateDB)
	if err != nil && err != ErrCheckpointNotFound {
		return nil, err
	}

	if pending != nil {
		if !bytes.Equal(pending.Proposer[:], cp.Proposer[:]) {
			if (c.Evm.Context.BlockNumber.Uint64() - pending.BlockNum) < NextProposeDelay {
				log.Warn("Pending proposal not timeout, discard this propose", "pending.proposer", pending.Proposer,
					"pending.blockNum", pending.BlockNum,
					"currentProposer", cp.Proposer,
					"currentBlock", c.Evm.Context.BlockNumber)
				return nil, ErrInvalidProposal
			} else {
				// Clearing pending for proposal new checkpoint
				pending = nil
			}
		} else {
			for _, signed := range pending.SignedValidators {
				if signed == validatorId {
					log.Error("The validator already signed", "proposer", pending.Proposer,
						"start", pending.Start,
						"end", pending.End,
						"validatorId", validatorId)
					return nil, ErrInvalidProposal
				}
			}

			if (c.Evm.Context.BlockNumber.Uint64() - pending.BlockNum) >= NextProposeDelay {
				log.Warn("Pending proposal timeout, discard this propose", "proposer", pending.Proposer, "blockNum", pending.BlockNum)
				return nil, ErrProposalTimeout
			}

			if !pending.Checkpoint.Equal(tcp) {
				log.Warn("The proposal not equal pending")
				return nil, ErrInvalidProposal
			}
		}
	} else {
		pending = &StorageCheckpoint{
			Checkpoint:       *tcp,
			SignedValidators: make([]uint32, 0),
			AggSignature:     make([]byte, 0),
			BlockNum:         c.Evm.Context.BlockNumber.Uint64(),
			Emitted:          false,
		}
	}

	if pending.Emitted {
		log.Warn("Pending checkpoint propose signatures already aggregated", "proposer", pending.Proposer,
			"start", pending.Start, "end", pending.End)
		return nil, ErrEmitted
	}

	var aggSig bls.Sign
	if len(pending.AggSignature) > 0 {
		if err := aggSig.Deserialize(pending.AggSignature); err != nil {
			return nil, err
		}

		var sig bls.Sign
		if err := sig.Deserialize(signature); err != nil {
			return nil, err
		}

		aggSig.Add(&sig)
	} else {
		if err := aggSig.Deserialize(signature); err != nil {
			return nil, err
		}
	}

	pending.AggSignature = aggSig.Serialize()
	pending.SignedValidators = append(pending.SignedValidators, validatorId)

	if len(pending.SignedValidators) >= c.threshold(validators.Len()) {
		event := CheckpointABI().Events["CheckpointSigAggregated"]
		topics := make([]common.Hash, 1)
		topics[0] = event.ID

		indexs, err := abi.MakeTopics([]interface{}{cp.Proposer})
		if err != nil {
			return nil, err
		}
		topics = append(topics, indexs[0]...)

		data, err := event.Inputs.Pack(cp.Start, cp.End, cp.RootHash, pending.SignedValidators, pending.AggSignature)
		if err != nil {
			return nil, err
		}
		c.Evm.StateDB.AddLog(&ctypes.Log{
			BlockNumber: c.Evm.Context.BlockNumber.Uint64(),
			Address:     c.Contract.Address(),
			Topics:      topics,
			Data:        data,
		})
		pending.Emitted = true
	}

	if err := WritePendingCheckpoint(c.Evm.StateDB, pending); err != nil {
		return nil, err
	}
	return nil, nil
}

// solidity:
//
//	function confirm(address proposer, bytes32 root) external
func (c *CheckpointSigAggregatorContract) Confirm(input []byte) ([]byte, error) {
	validators, err := plugin.StakingInstance().GetValidator(c.Evm.Context.BlockNumber.Uint64())
	if err != nil {
		log.Error("Get validator fail", "blockNumber", c.Evm.Context.BlockNumber, "err", err)
		return nil, err
	}

	// Previous check in Run
	method, _ := CheckpointABI().MethodById(input[:4])
	inputs, _ := method.Inputs.Unpack(input[4:])

	var proposer common.Address
	var root common.Hash

	abi.ConvertType(inputs[0], &proposer)
	abi.ConvertType(inputs[1], &root)

	log.Debug("Confirm propose", "proposer", proposer, "root", root)

	if !bytes.Equal(c.Contract.Caller().Bytes(), proposer.Bytes()) {
		log.Error("Invalid caller", "proposer", proposer, "caller", c.Contract.Caller())
		return nil, ErrInvalidCaller
	}

	// FIXME:
	if _, err := validators.FindNodeByAddress(common.NodeAddress(proposer)); err != nil {
		log.Error("The proposer not a validator", "proposer", proposer, "err", err)
		return nil, ErrInvalidProposer
	}

	latest, err := ReadLatestCheckpoint(c.Evm.StateDB)
	if err != nil && err != ErrCheckpointNotFound {
		return nil, err
	}

	if latest != nil &&
		bytes.Equal(latest.Proposer.Bytes(), proposer.Bytes()) &&
		bytes.Equal(latest.RootHash[:], root[:]) {
		log.Warn("Propose already confirmed", "proposer", proposer, "root", root)
		return nil, ErrConfirmed
	}

	pending, err := ReadPendingCheckpoint(c.Evm.StateDB)
	if err != nil {
		if err == ErrCheckpointNotFound {
			log.Warn("Please propose a checkpoint first", "proposer", proposer, "root", root)
			return nil, nil
		}
		return nil, err
	}

	if !bytes.Equal(pending.Proposer.Bytes(), proposer.Bytes()) ||
		!bytes.Equal(pending.RootHash[:], root[:]) {
		log.Warn("The confirm proposer not found", "proposer", proposer, "root", root)
		return nil, nil
	}

	err = WriteLatestCheckpoint(c.Evm.StateDB, pending)
	if err != nil {
		return nil, err
	}
	// Clear pending checkpoint
	err = WritePendingCheckpoint(c.Evm.StateDB, nil)
	if err != nil {
		return nil, err
	}
	return nil, nil
}

// solidity:
//
//	function latestCheckpoint() extenral view returns (Checkpoint memory cp)
func (c *CheckpointSigAggregatorContract) LatestCheckpoint() ([]byte, error) {
	scp, err := ReadLatestCheckpoint(c.Evm.StateDB)
	if err != nil {
		if err == ErrCheckpointNotFound {
			return nil, nil
		}
		return nil, err
	}
	out := CheckpointABI().Methods["latestCheckpoint"].Outputs
	cp := &checkpoint.ICheckpointSigAggregatorCheckpoint{
		Proposer: scp.Proposer,
		Start: scp.Start,
		End: scp.End,
		RootHash: scp.RootHash,
		AccountHash: scp.AccountHash,
		ChainId: scp.ChainId,
		Current: scp.Current,
		Rewards: scp.Rewards,
	}
	return out.Pack(cp)
}

// solidity:
//
//	function pendingCheckpoint() external view returns (PendingCheckpoint memory pcp)
func (c *CheckpointSigAggregatorContract) PendingCheckpoint() ([]byte, error) {
	pending, err := ReadPendingCheckpoint(c.Evm.StateDB)
	if err != nil {
		if err == ErrCheckpointNotFound {
			return nil, nil
		}
		return nil, err
	}

	out := CheckpointABI().Methods["pendingCheckpoint"].Outputs
	pcp := &checkpoint.ICheckpointSigAggregatorPendingCheckpoint{
		Checkpoint: checkpoint.ICheckpointSigAggregatorCheckpoint{
			Proposer:    pending.Proposer,
			Start:       pending.Start,
			End:         pending.End,
			RootHash:    pending.RootHash,
			AccountHash: pending.AccountHash,
			ChainId:     pending.ChainId,
			Current:     pending.Current,
			Rewards:     pending.Rewards,
		},
		BlockNum: big.NewInt(0).SetUint64(pending.BlockNum),
	}
	return out.Pack(pcp)
}

func (c *CheckpointSigAggregatorContract) threshold(num int) int {
	return num - (num-1)/3
}
