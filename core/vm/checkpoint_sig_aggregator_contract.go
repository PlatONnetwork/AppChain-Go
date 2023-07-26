package vm

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math/big"
	"reflect"
	"strings"

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
	*types.Checkpoint
	SignedValidators []*big.Int
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
	validatorId := new(big.Int)
	var signature []byte

	abi.ConvertType(inputs[0], &cp)
	abi.ConvertType(inputs[1], &validatorId)
	abi.ConvertType(inputs[2], &signature)

	log.Info("Propose checkpoint",
		"number", c.Evm.Context.BlockNumber,
		"proposer", cp.Proposer,
		"start", cp.Start,
		"end", cp.End,
		"validatorId", validatorId,
		"signature", hex.EncodeToString(signature),
	)

	validator, err := validators.FindNodeByValidatorId(uint32(validatorId.Uint64()))
	if err != nil {
		log.Error("Cannot get the specified validator", "proposer", cp.Proposer, "start", cp.Start, "end", cp.End, "validatorId", validatorId)
		return nil, ErrValidatorNotFound
	}

	if !bytes.Equal(c.Contract.Caller().Bytes(), common.Address(validator.StakingAddress).Bytes()) {
		log.Error("Invalid caller", "proposer", cp.Proposer, "start", cp.Start, "end", cp.End, "caller", c.Contract.Caller(), "validatorId", validatorId)
		return nil, ErrInvalidCaller
	}

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
			} else if !(cp.Start.Cmp(pending.Start) == 0 && cp.End.Cmp(pending.End) == 0) &&
				cp.Start.Cmp(new(big.Int).Add(pending.End, big1)) != 0 {
				log.Warn("Propose checkpoint not match pending", "pending.start", pending.Start,
					"pending.end", pending.End, "start", cp.Start, "end", cp.End)
				return nil, ErrInvalidProposal
			} else {
				// Clearing pending for proposal new checkpoint
				log.Debug("Clearing pending", "pending", pending.String())
				pending = nil
			}
		} else {
			// For single validator
			if (c.Evm.Context.BlockNumber.Uint64() - pending.BlockNum) >= NextProposeDelay {
				log.Debug("Clearing pending", "pending", pending.String())
				pending = nil
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
					log.Warn("The proposal not equal pending", "pending", pending.Checkpoint.String(), "checkpoint", tcp.String())
					return nil, ErrInvalidProposal
				}
			}
		}
	}

	if pending == nil {
		pending = &StorageCheckpoint{
			Checkpoint:       tcp,
			SignedValidators: make([]*big.Int, 0),
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

		data, err := event.Inputs.Pack(cp.Proposer, cp.Start, cp.End, cp.Hashes[0], pending.SignedValidators, pending.AggSignature)
		if err != nil {
			log.Error("Cannot pack CheckpointSigAggregated event", "err", err)
			return nil, err
		}
		c.Evm.StateDB.AddLog(&ctypes.Log{
			BlockNumber: c.Evm.Context.BlockNumber.Uint64(),
			Address:     c.Contract.Address(),
			Topics:      topics,
			Data:        data,
		})

		s := make([]string, 0)
		for _, id := range pending.SignedValidators {
			s = append(s, id.String())
		}
		log.Info("Emit CheckpointSigAggregated",
			"proposer", cp.Proposer,
			"start", cp.Start,
			"end", cp.End,
			"root", hex.EncodeToString(cp.Hashes[0][:]),
			"signedValidator", strings.Join(s, ","),
			"signature", hex.EncodeToString(pending.AggSignature),
		)
		pending.Emitted = true
	}

	if err := WritePendingCheckpoint(c.Evm.StateDB, pending); err != nil {
		log.Error("Write pending checkpoint error",
			"proposer", pending.Proposer,
			"start", pending.Start,
			"end", pending.End,
			"err", err)
		return nil, err
	}
	return nil, nil
}

// solidity:
//
//	function pendingCheckpoint() external view returns (PendingCheckpoint memory pcp)
func (c *CheckpointSigAggregatorContract) PendingCheckpoint() ([]byte, error) {
	pending, err := ReadPendingCheckpoint(c.Evm.StateDB)
	if err != nil {
		log.Debug("Cannot get pending checkpoint", "err", err, "number", c.Evm.Context.BlockNumber)
		if err == ErrCheckpointNotFound {
			return nil, nil
		}
		return nil, err
	}

	out := CheckpointABI().Methods["pendingCheckpoint"].Outputs
	pcp := &checkpoint.ICheckpointSigAggregatorPendingCheckpoint{
		Checkpoint: checkpoint.ICheckpointSigAggregatorCheckpoint{
			Proposer: pending.Proposer,
			Hashes:   solidity.ToBytes32Slice(pending.Hashes),
			Start:    pending.Start,
			End:      pending.End,
			Current:  pending.Current,
			Rewards:  pending.Rewards,
			ChainId:  pending.ChainId,
			Slashing: pending.Slashing,
		},
		BlockNum: big.NewInt(0).SetUint64(pending.BlockNum),
	}
	return out.Pack(pcp)
}

// solidity:
//
//	function shouldPropose(uint256 number, uint256 validatorId) external view returns (bool)
func (c *CheckpointSigAggregatorContract) ShouldPropose(input []byte) ([]byte, error) {
	method, _ := CheckpointABI().MethodById(input[:4])
	inputs, _ := method.Inputs.Unpack(input[4:])

	number := new(big.Int)
	validatorId := new(big.Int)

	abi.ConvertType(inputs[0], &number)
	abi.ConvertType(inputs[1], &validatorId)

	log.Debug("Should propose", "number", number, "validatorId", validatorId)

	pending, err := ReadPendingCheckpoint(c.Evm.StateDB)
	if err != nil {
		log.Debug("Cannot get pending checkpoint", "err", err)
		if err == ErrCheckpointNotFound {
			return method.Outputs.Pack(true)
		}
		return method.Outputs.Pack(false)
	}

	if number.Uint64() < pending.BlockNum || (number.Uint64()-pending.BlockNum < NextProposeDelay) {
		return method.Outputs.Pack(false)
	}
	return method.Outputs.Pack(true)
}

func (c *CheckpointSigAggregatorContract) threshold(num int) int {
	return num - (num-1)/3
}
