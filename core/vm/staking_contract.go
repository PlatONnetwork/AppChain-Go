// Copyright 2021 The PlatON Network Authors
// This file is part of the PlatON-Go library.
//
// The PlatON-Go library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The PlatON-Go library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the PlatON-Go library. If not, see <http://www.gnu.org/licenses/>.

package vm

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/PlatONnetwork/AppChain-Go/core/types"
	"github.com/PlatONnetwork/AppChain-Go/crypto"
	"github.com/PlatONnetwork/AppChain-Go/rlp"
	"github.com/PlatONnetwork/AppChain-Go/rootchain/innerbindings/helper"
	"github.com/PlatONnetwork/AppChain-Go/rootchain/innerbindings/stakinginfo"
	"math/big"

	"github.com/PlatONnetwork/AppChain-Go/x/xcom"

	"github.com/PlatONnetwork/AppChain-Go/common/hexutil"

	"github.com/PlatONnetwork/AppChain-Go/crypto/bls"

	"github.com/PlatONnetwork/AppChain-Go/params"

	"github.com/PlatONnetwork/AppChain-Go/common"
	"github.com/PlatONnetwork/AppChain-Go/common/vm"
	"github.com/PlatONnetwork/AppChain-Go/core/snapshotdb"
	"github.com/PlatONnetwork/AppChain-Go/log"
	"github.com/PlatONnetwork/AppChain-Go/p2p/discover"
	"github.com/PlatONnetwork/AppChain-Go/x/plugin"
	"github.com/PlatONnetwork/AppChain-Go/x/staking"
	"github.com/PlatONnetwork/AppChain-Go/x/xutil"
)

const (
	TxCreateStaking      = 1000
	TxEditorCandidate    = 1001
	TxIncreaseStaking    = 1002
	TxWithdrewCandidate  = 1003
	TxDelegate           = 1004
	TxWithdrewDelegation = 1005
	TxRedeemDelegation   = 1006
	QueryVerifierList    = 1100
	QueryValidatorList   = 1101
	QueryCandidateList   = 1102
	QueryRelateList      = 1103
	QueryDelegateInfo    = 1104
	QueryCandidateInfo   = 1105
	QueryDelegationLock  = 1106
	GetPackageReward     = 1200
	GetStakingReward     = 1201
	GetAvgPackTime       = 1202
)

const (
	BLSPUBKEYLEN = 96 //  the bls public key length must be 96 byte
	BLSPROOFLEN  = 64 // the bls proof length must be 64 byte
)

var (
	BlockNumberKey = crypto.Keccak256([]byte(helper.BlockNumber))
)

type StakingContract struct {
	Plugin   *plugin.StakingPlugin
	Contract *Contract
	Evm      *EVM
}

func (stkc *StakingContract) RequiredGas(input []byte) uint64 {
	return 0
}

func (stkc *StakingContract) Run(input []byte) ([]byte, error) {
	if checkInputEmpty(input) {
		return nil, nil
	}
	//adapt solidity contract
	solFunc := stkc.SolidityFunc()
	methodId := binary.BigEndian.Uint32(input[:4])
	if fn, ok := solFunc[methodId]; ok {
		return fn(input[4:])
	}

	return execPlatonContract(input, stkc.FnSigns())
}

func (stkc *StakingContract) SolidityFunc() map[uint32]func([]byte) ([]byte, error) {
	return map[uint32]func([]byte) ([]byte, error){
		binary.BigEndian.Uint32(helper.InnerStakeAbi.Methods[helper.StakeStateSync].ID): stkc.stakeStateSync,
		binary.BigEndian.Uint32(helper.InnerStakeAbi.Methods[helper.BlockNumber].ID): func(i []byte) ([]byte, error) {
			value := stkc.blockNumber()
			return value, nil
		},
	}
}

func (stkc *StakingContract) CheckGasPrice(gasPrice *big.Int, fcode uint16) error {
	return nil
}
func (stkc *StakingContract) stakeInfoFunc() map[common.Hash]func(*types.Log) ([]byte, error) {
	return map[common.Hash]func(*types.Log) ([]byte, error){
		helper.StakedID:       stkc.handleStaked,
		helper.UnstakeInitID:  stkc.handleUnstakeInit,
		helper.SignerChangeID: stkc.handleSignerChange,
		helper.ShareMintedID:  stkc.handleShareMinted,
		helper.ShareBurnedID:  stkc.handleShareShareBurned,
	}
}
func (stkc *StakingContract) handleStaked(vLog *types.Log) ([]byte, error) {
	txHash := stkc.Evm.StateDB.TxHash()
	txIndex := stkc.Evm.StateDB.TxIdx()
	blockNumber := stkc.Evm.Context.BlockNumber
	blockHash := stkc.Evm.Context.BlockHash
	state := stkc.Evm.StateDB

	event := new(stakinginfo.StakinginfoStaked)
	if err := helper.UnpackLog(helper.StakingInfoAbi, event, helper.Staked, vLog); err != nil {
		return nil, err
	}
	log.Debug("StakingOperation: staked event information", "blockNumber", blockNumber, "txHash", txHash.Hex(),
		"signer", event.Signer.Hex(), "validatorId", event.ValidatorId, "nonce", event.Nonce,
		"activationEpoch", event.ActivationEpoch, "amount", event.Amount, "totalStakedAmount", event.Total,
		"signerPubkey", hex.EncodeToString(event.Pubkeys[:64]), "blsPubkey", hex.EncodeToString(event.Pubkeys[64:]))

	// Query current active version
	originVersion := params.GenesisVersion

	var blsPubKey bls.PublicKeyHex
	copy(blsPubKey[:], event.Pubkeys[64:])

	canOld, err := stkc.Plugin.GetCandidateInfo(blockHash, event.ValidatorId)
	if snapshotdb.NonDbNotFoundErr(err) {
		log.Error("Failed to createStaking by GetCandidateInfo", "txHash", txHash,
			"blockNumber", blockNumber, "validatorId", event.ValidatorId, "err", err)
		return nil, err
	}

	if canOld.IsNotEmpty() {
		log.Error("candidate already exists", "blockNumber", blockNumber, "txHash", txHash.Hex(), "validatorId", event.ValidatorId)
		return nil, nil
	}

	// init candidate information
	nodeId, err := discover.BytesID(event.Pubkeys[:64])
	if err != nil {
		log.Error("invalid public key", "blockNumber", blockNumber, "txHash", txHash.Hex(), "pk", hex.EncodeToString(event.Pubkeys[:64]))
		return nil, nil
	}
	canBase := &staking.CandidateBase{
		ValidatorId:     event.ValidatorId,
		NodeId:          nodeId,
		BlsPubKey:       blsPubKey,
		StakingAddress:  event.Owner,
		BenefitAddress:  event.Owner,
		StakingBlockNum: blockNumber.Uint64(),
		StakingTxIndex:  txIndex,
		ProgramVersion:  originVersion,
	}

	amount := new(big.Int).Set(event.Amount)
	canMutable := &staking.CandidateMutable{
		Status:               staking.Valided,
		Shares:               amount,
		Released:             new(big.Int).SetInt64(0),
		ReleasedHes:          new(big.Int).SetInt64(0),
		RestrictingPlan:      new(big.Int).SetInt64(0),
		RestrictingPlanHes:   new(big.Int).SetInt64(0),
		RewardPerChangeEpoch: uint32(xutil.CalculateEpoch(blockNumber.Uint64())),
		DelegateRewardTotal:  new(big.Int).SetInt64(0),
	}

	can := &staking.Candidate{}
	can.CandidateBase = canBase
	can.CandidateMutable = canMutable

	err = stkc.Plugin.CreateCandidate(state, blockHash, blockNumber, event.ValidatorId, can)
	return nil, err
}

func (stkc *StakingContract) handleUnstakeInit(vLog *types.Log) ([]byte, error) {
	event := new(stakinginfo.StakinginfoUnstakeInit)
	if err := helper.UnpackLog(helper.StakingInfoAbi, event, helper.UnstakeInit, vLog); err != nil {
		return nil, err
	}
	txHash := stkc.Evm.StateDB.TxHash()
	blockNumber := stkc.Evm.Context.BlockNumber
	blockHash := stkc.Evm.Context.BlockHash
	state := stkc.Evm.StateDB
	log.Debug("StakingOperation: unstakeInit event information", "blockNumber", blockNumber, "txHash", txHash.Hex(),
		"validatorId", event.ValidatorId, "validatorOwner", event.User, "nonce", event.Nonce, "deactivationEpoch", event.DeactivationEpoch,
		"amount", event.Amount)
	if txHash == common.ZeroHash {
		return nil, nil
	}
	canOld, err := stkc.Plugin.GetCandidateInfo(blockHash, event.ValidatorId)
	if snapshotdb.NonDbNotFoundErr(err) {
		log.Error("Failed to update stakeInfo by GetCandidateInfo", "txHash", txHash,
			"blockNumber", blockNumber, "validatorId", event.ValidatorId, "err", err)
		return nil, err
	}

	if canOld.IsEmpty() {
		log.Error("candidate does not exist", "blockNumber", blockNumber, "txHash", txHash.Hex(), "validatorId", event.ValidatorId)
		return nil, nil
	}
	err = stkc.Plugin.UnStake(state, blockHash, blockNumber, event.ValidatorId, canOld)
	return nil, err
}

func (stkc *StakingContract) handleSignerChange(vLog *types.Log) ([]byte, error) {
	event := new(stakinginfo.StakinginfoSignerChange)
	if err := helper.UnpackLog(helper.StakingInfoAbi, event, helper.SignerChange, vLog); err != nil {
		return nil, err
	}
	return nil, nil
}

func (stkc *StakingContract) handleShareMinted(vLog *types.Log) ([]byte, error) {
	event := new(stakinginfo.StakinginfoShareMinted)
	if err := helper.UnpackLog(helper.StakingInfoAbi, event, helper.ShareMinted, vLog); err != nil {
		return nil, err
	}
	txHash := stkc.Evm.StateDB.TxHash()
	blockNumber := stkc.Evm.Context.BlockNumber
	blockHash := stkc.Evm.Context.BlockHash
	state := stkc.Evm.StateDB
	log.Debug("StakingOperation: shareMinted event information", "blockNumber", blockNumber, "txHash", txHash.Hex(),
		"validatorId", event.ValidatorId, "validatorOwner", event.User, "amount", event.Amount, "tokens", event.Tokens)
	canOld, err := stkc.Plugin.GetCandidateInfo(blockHash, event.ValidatorId)
	if snapshotdb.NonDbNotFoundErr(err) {
		log.Error("Failed to update stakeInfo by GetCandidateInfo", "txHash", txHash,
			"blockNumber", blockNumber, "validatorId", event.ValidatorId, "err", err)
		return nil, err
	}

	if canOld.IsEmpty() {
		log.Error("candidate does not exist", "blockNumber", blockNumber, "txHash", txHash.Hex(), "validatorId", event.ValidatorId)
		return nil, nil
	}
	if canOld.IsInvalid() {
		log.Info("candidate in non-modifiable status", "blockNumber", blockNumber, "txHash", txHash.Hex(), "validatorId", event.ValidatorId)
		return nil, nil
	}
	canOld.DelegateTotal = new(big.Int).Add(canOld.DelegateTotal, event.Amount)
	err = stkc.Plugin.StakeUpdateShares(state, blockHash, blockNumber, event.ValidatorId, new(big.Int).Add(canOld.Shares, event.Amount), canOld)
	return nil, err
}

func (stkc *StakingContract) handleShareShareBurned(vLog *types.Log) ([]byte, error) {
	event := new(stakinginfo.StakinginfoShareBurned)
	if err := helper.UnpackLog(helper.StakingInfoAbi, event, helper.ShareBurned, vLog); err != nil {
		return nil, err
	}
	txHash := stkc.Evm.StateDB.TxHash()
	blockNumber := stkc.Evm.Context.BlockNumber
	blockHash := stkc.Evm.Context.BlockHash
	state := stkc.Evm.StateDB
	log.Debug("StakingOperation: shareBurned event information", "blockNumber", blockNumber, "txHash", txHash.Hex(),
		"validatorId", event.ValidatorId, "validatorOwner", event.User, "amount", event.Amount, "tokens", event.Tokens)
	canOld, err := stkc.Plugin.GetCandidateInfo(blockHash, event.ValidatorId)
	if snapshotdb.NonDbNotFoundErr(err) {
		log.Error("Failed to update stakeInfo by GetCandidateInfo", "txHash", txHash,
			"blockNumber", blockNumber, "validatorId", event.ValidatorId, "err", err)
		return nil, err
	}

	if canOld.IsEmpty() {
		log.Error("candidate does not exist", "blockNumber", blockNumber, "txHash", txHash.Hex(), "validatorId", event.ValidatorId)
		return nil, nil
	}
	if canOld.IsInvalid() {
		log.Info("candidate in non-modifiable status", "blockNumber", blockNumber, "txHash", txHash.Hex(), "validatorId", event.ValidatorId)
		return nil, nil
	}
	canOld.DelegateTotal = new(big.Int).Sub(canOld.DelegateTotal, event.Amount)
	err = stkc.Plugin.StakeUpdateShares(state, blockHash, blockNumber, event.ValidatorId, new(big.Int).Sub(canOld.Shares, event.Amount), canOld)
	return nil, err
}

func (stkc *StakingContract) stakeStateSync(input []byte) ([]byte, error) {
	txHash := stkc.Evm.StateDB.TxHash()
	blockNumber := stkc.Evm.Context.BlockNumber
	blockHash := stkc.Evm.Context.BlockHash
	from := stkc.Contract.CallerAddress
	// If the interface is called for estimate, it simply returns.
	if txHash == common.ZeroHash {
		return nil, nil
	}
	// Only consensus nodes have permission to call this interface
	consensusList, err := stkc.Plugin.GetValidatorList(blockHash, blockNumber.Uint64(), plugin.CurrentRound, plugin.QueryStartNotIrr)
	if err != nil {
		return nil, err
	}
	isConsensusNode := false
	for _, node := range consensusList {
		if node.StakingAddress == from {
			isConsensusNode = true
		}
	}
	if !isConsensusNode {
		log.Error("Non-consensus node call interface", "blockNumber", blockNumber, "from", from, "consensusListLen", len(consensusList))
		return nil, errors.New("call without permission")
	}

	type InputArgs struct {
		BlockNumber *big.Int
		Events      [][]byte
	}
	var args InputArgs
	in, err := helper.InnerStakeAbi.Methods[helper.StakeStateSync].Inputs.Unpack(input)
	if err != nil {
		return nil, err
	}
	helper.InnerStakeAbi.Methods[helper.StakeStateSync].Inputs.Copy(&args, in)
	if err != nil {
		return nil, err
	}
	stakeFuncMap := stkc.stakeInfoFunc()
	for _, event := range args.Events {
		var rootChainLog types.Log
		if err := rootChainLog.DecodeRLP(rlp.NewStream(bytes.NewReader(event), 0)); err != nil {
			return nil, err
		}
		eventID := rootChainLog.Topics[0]
		if fn, ok := stakeFuncMap[eventID]; ok {
			if res, err := fn(&rootChainLog); err != nil {
				log.Error("Failed to execute rootChainEvent", "blockNumber", blockNumber, "eventId", eventID.Hex(),
					"result", hex.EncodeToString(res), "error", err)
				return nil, err
			}
		} else {
			log.Error("Unknown rootChainEvents", "blockNumber", blockNumber, "eventId", eventID.Hex())
		}
	}
	// Record the latest block height processed.
	stkc.SetBlockNumber(args.BlockNumber)
	if err := stkc.addStakeStateSyncLog(args.BlockNumber); err != nil {
		return nil, err
	}
	return nil, nil
}
func (stkc *StakingContract) addStakeStateSyncLog(end *big.Int) error {
	data, err := helper.InnerStakeAbi.Events["StakeStateSync"].Inputs.Pack(new(big.Int).SetBytes(stkc.blockNumber()), end)
	if err != nil {
		return err
	}
	stkc.Evm.StateDB.AddLog(&types.Log{
		Address: stkc.Contract.Address(),
		Topics:  []common.Hash{helper.InnerStakeAbi.Events["StakeStateSync"].ID},
		Data:    data,
		// This is a non-consensus field, but assigned here because
		// core/state doesn't know the current block number.
		BlockNumber: stkc.Evm.Context.BlockNumber.Uint64(),
	})
	return nil
}

func (stkc *StakingContract) SetBlockNumber(number *big.Int) error {
	stkc.Evm.StateDB.SetState(vm.StakingContractAddr, BlockNumberKey, number.Bytes())
	return nil
}
func (stkc *StakingContract) blockNumber() []byte {
	value := stkc.Evm.StateDB.GetState(vm.StakingContractAddr, BlockNumberKey)
	return value
}

func (stkc *StakingContract) FnSigns() map[uint16]interface{} {
	return map[uint16]interface{}{
		// Get
		QueryVerifierList:  stkc.getVerifierList,
		QueryValidatorList: stkc.getValidatorList,
		QueryCandidateList: stkc.getCandidateList,
		//QueryRelateList:    stkc.getRelatedListByDelAddr,
		QueryCandidateInfo: stkc.getCandidateInfo,

		GetPackageReward: stkc.getPackageReward,
		GetAvgPackTime:   stkc.getAvgPackTime,
	}
}

func verifyBlsProof(proofHex bls.SchnorrProofHex, pubKey *bls.PublicKey) error {
	proofByte, err := proofHex.MarshalText()
	if nil != err {
		return err
	}
	// proofHex to proof
	proof := new(bls.SchnorrProof)
	if err = proof.UnmarshalText(proofByte); nil != err {
		return err
	}
	// verify proof
	return proof.VerifySchnorrNIZK(*pubKey)
}

func verifyRewardPer(rewardPer uint16) bool {
	return rewardPer <= 10000 //	1BP(BasePoint)=0.01%
}

func (stkc *StakingContract) getVerifierList() ([]byte, error) {

	blockNumber := stkc.Evm.Context.BlockNumber
	blockHash := stkc.Evm.Context.BlockHash

	arr, err := stkc.Plugin.GetVerifierList(blockHash, blockNumber.Uint64(), plugin.QueryStartNotIrr)

	if snapshotdb.NonDbNotFoundErr(err) {
		return callResultHandler(stkc.Evm, "getVerifierList",
			arr, staking.ErrGetVerifierList.Wrap(err.Error())), nil
	}

	if snapshotdb.IsDbNotFoundErr(err) || arr.IsEmpty() {
		return callResultHandler(stkc.Evm, "getVerifierList",
			arr, staking.ErrGetVerifierList.Wrap("VerifierList info is not found")), nil
	}

	return callResultHandler(stkc.Evm, "getVerifierList",
		arr, nil), nil
}

func (stkc *StakingContract) getValidatorList() ([]byte, error) {

	blockNumber := stkc.Evm.Context.BlockNumber
	blockHash := stkc.Evm.Context.BlockHash

	arr, err := stkc.Plugin.GetValidatorList(blockHash, blockNumber.Uint64(), plugin.CurrentRound, plugin.QueryStartNotIrr)
	if snapshotdb.NonDbNotFoundErr(err) {

		return callResultHandler(stkc.Evm, "getValidatorList",
			arr, staking.ErrGetValidatorList.Wrap(err.Error())), nil
	}

	if snapshotdb.IsDbNotFoundErr(err) || arr.IsEmpty() {
		return callResultHandler(stkc.Evm, "getValidatorList",
			arr, staking.ErrGetValidatorList.Wrap("ValidatorList info is not found")), nil
	}

	return callResultHandler(stkc.Evm, "getValidatorList",
		arr, nil), nil
}

func (stkc *StakingContract) getCandidateList() ([]byte, error) {

	blockNumber := stkc.Evm.Context.BlockNumber
	blockHash := stkc.Evm.Context.BlockHash

	arr, err := stkc.Plugin.GetCandidateList(blockHash, blockNumber.Uint64())
	if snapshotdb.NonDbNotFoundErr(err) {
		return callResultHandler(stkc.Evm, "getCandidateList",
			arr, staking.ErrGetCandidateList.Wrap(err.Error())), nil
	}

	if snapshotdb.IsDbNotFoundErr(err) || arr.IsEmpty() {
		return callResultHandler(stkc.Evm, "getCandidateList",
			arr, staking.ErrGetCandidateList.Wrap("CandidateList info is not found")), nil
	}

	return callResultHandler(stkc.Evm, "getCandidateList",
		arr, nil), nil
}

func (stkc *StakingContract) getCandidateInfo(validatorId uint32) ([]byte, error) {
	blockNumber := stkc.Evm.Context.BlockNumber
	blockHash := stkc.Evm.Context.BlockHash

	can, err := stkc.Plugin.GetCandidateCompactInfo(blockHash, blockNumber.Uint64(), new(big.Int).SetUint64(uint64(validatorId)))
	if snapshotdb.NonDbNotFoundErr(err) {
		return callResultHandler(stkc.Evm, fmt.Sprintf("getCandidateInfo, validatorId: %d",
			validatorId), can, staking.ErrQueryCandidateInfo.Wrap(err.Error())), nil
	}

	if snapshotdb.IsDbNotFoundErr(err) || can.IsEmpty() {
		return callResultHandler(stkc.Evm, fmt.Sprintf("getCandidateInfo, validatorId: %d",
			validatorId), can, staking.ErrQueryCandidateInfo.Wrap("Candidate info is not found")), nil
	}

	return callResultHandler(stkc.Evm, fmt.Sprintf("getCandidateInfo, validatorId: %d",
		validatorId), can, nil), nil
}

func (stkc *StakingContract) getPackageReward() ([]byte, error) {
	packageReward, err := plugin.LoadNewBlockReward(common.ZeroHash, stkc.Evm.SnapshotDB)
	if nil != err {
		return callResultHandler(stkc.Evm, "getPackageReward", nil, common.NotFound.Wrap(err.Error())), nil
	}
	return callResultHandler(stkc.Evm, "getPackageReward", (*hexutil.Big)(packageReward), nil), nil
}

func (stkc *StakingContract) getStakingReward() ([]byte, error) {
	stakingReward, err := plugin.LoadStakingReward(common.ZeroHash, stkc.Evm.SnapshotDB)
	if nil != err {
		return callResultHandler(stkc.Evm, "getStakingReward", nil, common.NotFound.Wrap(err.Error())), nil
	}
	return callResultHandler(stkc.Evm, "getStakingReward", (*hexutil.Big)(stakingReward), nil), nil
}

func (stkc *StakingContract) getAvgPackTime() ([]byte, error) {
	avgPackTime, err := xcom.LoadCurrentAvgPackTime()
	if nil != err {
		return callResultHandler(stkc.Evm, "getAvgPackTime", nil, common.InternalError.Wrap(err.Error())), nil
	}
	return callResultHandler(stkc.Evm, "getAvgPackTime", avgPackTime, nil), nil
}
