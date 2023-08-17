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

package plugin

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/PlatONnetwork/AppChain-Go/ethdb/memorydb"
	"math/big"
	mrand "math/rand"
	"testing"
	"time"

	"github.com/PlatONnetwork/AppChain-Go/common/mock"
	"github.com/PlatONnetwork/AppChain-Go/trie"

	"github.com/PlatONnetwork/AppChain-Go/crypto/vrf"
	"github.com/PlatONnetwork/AppChain-Go/x/gov"

	"github.com/PlatONnetwork/AppChain-Go/params"

	"github.com/PlatONnetwork/AppChain-Go/x/reward"

	"github.com/PlatONnetwork/AppChain-Go/log"

	"github.com/PlatONnetwork/AppChain-Go/common/vm"

	"github.com/PlatONnetwork/AppChain-Go/x/handler"

	"github.com/stretchr/testify/assert"

	"github.com/PlatONnetwork/AppChain-Go/common"
	"github.com/PlatONnetwork/AppChain-Go/core/cbfttypes"
	"github.com/PlatONnetwork/AppChain-Go/core/snapshotdb"
	"github.com/PlatONnetwork/AppChain-Go/core/types"
	"github.com/PlatONnetwork/AppChain-Go/crypto"
	"github.com/PlatONnetwork/AppChain-Go/crypto/bls"
	"github.com/PlatONnetwork/AppChain-Go/event"
	"github.com/PlatONnetwork/AppChain-Go/p2p/discover"
	"github.com/PlatONnetwork/AppChain-Go/rlp"
	"github.com/PlatONnetwork/AppChain-Go/x/staking"
	"github.com/PlatONnetwork/AppChain-Go/x/xcom"
	"github.com/PlatONnetwork/AppChain-Go/x/xutil"
)

/*
*
test tool
*/
func Test_CleanSnapshotDB(t *testing.T) {
	sndb := snapshotdb.Instance()
	sndb.Clear()
}

func PrintObject(s string, obj interface{}) {
	objs, _ := json.Marshal(obj)
	log.Debug(s + " == " + string(objs))
}

func watching(eventMux *event.TypeMux, t *testing.T) {
	events := eventMux.Subscribe(cbfttypes.AddValidatorEvent{})
	defer events.Unsubscribe()

	for {
		select {
		case ev := <-events.Chan():
			if ev == nil {
				t.Error("ev is nil, may be Server closing")
				continue
			}

			switch ev.Data.(type) {
			case cbfttypes.AddValidatorEvent:
				addEv, ok := ev.Data.(cbfttypes.AddValidatorEvent)
				if !ok {
					t.Error("Received add validator event type error")
					continue
				}

				str, _ := json.Marshal(addEv)
				t.Log("P2P Received the add validator is:", string(str))
			default:
				t.Error("Received unexcepted event")
			}

		}
	}
}

func build_vrf_Nonce() ([]byte, [][]byte) {
	preNonces := make([][]byte, 0)
	curentNonce := crypto.Keccak256([]byte(string("nonce")))
	for i := 0; i < int(xcom.MaxValidators()); i++ {
		preNonces = append(preNonces, crypto.Keccak256([]byte(time.Now().Add(time.Duration(i)).String())[:]))
		time.Sleep(time.Microsecond * 10)
	}
	return curentNonce, preNonces
}

func buildPrepareData(genesis *types.Block, t *testing.T) (*types.Header, error) {
	// New VrfHandler instance by genesis block Hash
	handler.NewVrfHandler(genesis.Hash().Bytes())

	// build vrf proof
	// build ancestor nonces
	_, nonces := build_vrf_Nonce()
	enValue, err := rlp.EncodeToBytes(nonces)
	if nil != err {
		t.Error("Failed to rlp vrf nonces", "err", err)
		return nil, err
	}

	// build genesis veriferList and validatorList
	validatorQueue := make(staking.ValidatorQueue, xcom.MaxValidators())

	for j := 0; j < 1000; j++ {
		var index int = j % 25

		balance, _ := new(big.Int).SetString(balanceStr[index], 10)

		mrand.Seed(time.Now().UnixNano())

		weight := mrand.Intn(1000000000)

		ii := mrand.Intn(len(chaList))

		balance = new(big.Int).Add(balance, big.NewInt(int64(weight)))

		privateKey, err := crypto.GenerateKey()
		if nil != err {
			t.Errorf("Failed to generate random NodeId private key: %v", err)
			return nil, err
		}

		nodeId := discover.PubkeyID(&privateKey.PublicKey)

		privateKey, err = crypto.GenerateKey()
		if nil != err {
			t.Errorf("Failed to generate random Address private key: %v", err)
			return nil, err
		}

		addr := crypto.PubkeyToAddress(privateKey.PublicKey)

		var blsKey bls.SecretKey
		blsKey.SetByCSPRNG()
		var blsKeyHex bls.PublicKeyHex
		b, _ := blsKey.GetPublicKey().MarshalText()
		if err := blsKeyHex.UnmarshalText(b); nil != err {
			log.Error("Failed to blsKeyHex.UnmarshalText", "err", err)
			return nil, err
		}

		canTmp := &staking.Candidate{
			CandidateBase: &staking.CandidateBase{
				NodeId:          nodeId,
				BlsPubKey:       blsKeyHex,
				StakingAddress:  sender,
				BenefitAddress:  addr,
				StakingBlockNum: uint64(j),
				StakingTxIndex:  uint32(index),
				ProgramVersion:  xutil.CalcVersion(initProgramVersion),

				Description: staking.Description{
					NodeName:   nodeNameArr[index] + "_" + fmt.Sprint(j),
					ExternalId: nodeNameArr[index] + chaList[(len(chaList)-1)%(index+ii+1)] + "balabalala" + chaList[index],
					Website:    "www." + nodeNameArr[index] + "_" + fmt.Sprint(j) + ".org",
					Details:    "This is " + nodeNameArr[index] + "_" + fmt.Sprint(j) + " Super Node",
				},
			},
			CandidateMutable: &staking.CandidateMutable{
				Shares: balance,

				// Prevent null pointer initialization
				Released:           common.Big0,
				ReleasedHes:        common.Big0,
				RestrictingPlan:    common.Big0,
				RestrictingPlanHes: common.Big0,
			},
		}

		canAddr, _ := xutil.NodeId2Addr(canTmp.NodeId)

		// Store Candidate power
		powerKey := staking.TallyPowerKey(canTmp.ProgramVersion, canTmp.Shares, canTmp.StakingBlockNum, canTmp.StakingTxIndex, canTmp.NodeId)
		if err := sndb.PutBaseDB(powerKey, canAddr.Bytes()); nil != err {
			t.Errorf("Failed to Store Candidate Power: PutBaseDB failed. error:%s", err.Error())
			return nil, err
		}

		// Store Candidate Base info
		canBaseKey := staking.CanBaseKeyByAddr(canAddr.Big())
		if val, err := rlp.EncodeToBytes(canTmp.CandidateBase); nil != err {
			t.Errorf("Failed to Store CandidateBase info: PutBaseDB failed. error:%s", err.Error())
			return nil, err
		} else {

			if err := sndb.PutBaseDB(canBaseKey, val); nil != err {
				t.Errorf("Failed to Store CandidateBase info: PutBaseDB failed. error:%s", err.Error())
				return nil, err
			}
		}

		// Store Candidate Mutable info
		canMutableKey := staking.CanMutableKeyByAddr(canAddr.Big())
		if val, err := rlp.EncodeToBytes(canTmp.CandidateMutable); nil != err {
			t.Errorf("Failed to Store CandidateMutable info: PutBaseDB failed. error:%s", err.Error())
			return nil, err
		} else {

			if err := sndb.PutBaseDB(canMutableKey, val); nil != err {
				t.Errorf("Failed to Store CandidateMutable info: PutBaseDB failed. error:%s", err.Error())
				return nil, err
			}
		}

		if j < int(xcom.MaxValidators()) {
			v := &staking.Validator{
				NodeAddress:     canAddr,
				NodeId:          canTmp.NodeId,
				BlsPubKey:       canTmp.BlsPubKey,
				ProgramVersion:  canTmp.ProgramVersion,
				Shares:          canTmp.Shares,
				StakingBlockNum: canTmp.StakingBlockNum,
				StakingTxIndex:  canTmp.StakingTxIndex,
				ValidatorTerm:   0,
			}
			validatorQueue[j] = v
		}
	}

	/**
	*******
	build genesis epoch validators
	*******
	*/
	verifierIndex := &staking.ValArrIndex{
		Start: 1,
		End:   xutil.CalcBlocksEachEpoch(),
	}

	epochIndexArr := make(staking.ValArrIndexQueue, 0)
	epochIndexArr = append(epochIndexArr, verifierIndex)

	// current epoch start and end indexs
	epoch_index, err := rlp.EncodeToBytes(epochIndexArr)
	if nil != err {
		t.Errorf("Failed to Store Epoch Validators start and end index: rlp encodeing failed. error:%s", err.Error())
		return nil, err
	}
	if err := sndb.PutBaseDB(staking.GetEpochIndexKey(), epoch_index); nil != err {
		t.Errorf("Failed to Store Epoch Validators start and end index: PutBaseDB failed. error:%s", err.Error())
		return nil, err
	}

	epochArr, err := rlp.EncodeToBytes(validatorQueue)
	if nil != err {
		t.Errorf("Failed to rlp encodeing genesis validators. error:%s", err.Error())
		return nil, err
	}
	// Store Epoch validators
	if err := sndb.PutBaseDB(staking.GetEpochValArrKey(verifierIndex.Start, verifierIndex.End), epochArr); nil != err {
		t.Errorf("Failed to Store Epoch Validators: PutBaseDB failed. error:%s", err.Error())
		return nil, err
	}

	/**
	*******
	build genesis curr round validators
	*******
	*/
	curr_indexInfo := &staking.ValArrIndex{
		Start: 1,
		End:   xutil.ConsensusSize(),
	}
	roundIndexArr := make(staking.ValArrIndexQueue, 0)
	roundIndexArr = append(roundIndexArr, curr_indexInfo)

	// round index
	round_index, err := rlp.EncodeToBytes(roundIndexArr)
	if nil != err {
		t.Errorf("Failed to Store Round Validators start and end indexs: rlp encodeing failed. error:%s", err.Error())
		return nil, err
	}
	if err := sndb.PutBaseDB(staking.GetRoundIndexKey(), round_index); nil != err {
		t.Errorf("Failed to Store Round Validators start and end indexs: PutBaseDB failed. error:%s", err.Error())
		return nil, err
	}

	PrintObject("Test round", validatorQueue[:xcom.MaxConsensusVals()])
	roundArr, err := rlp.EncodeToBytes(validatorQueue[:xcom.MaxConsensusVals()])
	if nil != err {
		t.Errorf("Failed to rlp encodeing genesis validators. error:%s", err.Error())
		return nil, err
	}
	// Store Current Round validator
	if err := sndb.PutBaseDB(staking.GetRoundValArrKey(curr_indexInfo.Start, curr_indexInfo.End), roundArr); nil != err {
		t.Errorf("Failed to Store Current Round Validators: PutBaseDB failed. error:%s", err.Error())
		return nil, err
	}

	// Store vrf nonces
	if err := sndb.PutBaseDB(handler.NonceStorageKey, enValue); nil != err {
		t.Errorf("Failed to Store Current Vrf nonces : PutBaseDB failed. error:%s", err.Error())
		return nil, err
	}

	// SetCurrent to snapshotDB
	privateKey, err := crypto.GenerateKey()
	if nil != err {
		t.Errorf("Failed to generate random Address private key: %v", err)
		return nil, err
	}
	nodeId := discover.PubkeyID(&privateKey.PublicKey)
	currentHash := crypto.Keccak256Hash([]byte(nodeId.String()))
	newNumber := big.NewInt(int64(xutil.ConsensusSize() - xcom.ElectionDistance())) // 50
	preNum1 := new(big.Int).Sub(newNumber, big.NewInt(1))
	if err := sndb.SetCurrent(currentHash, *preNum1, *preNum1); nil != err {
		panic(fmt.Errorf("Failed to SetCurrent by snapshotdb. error:%s", err.Error()))
	}

	// new block
	nonce := crypto.Keccak256([]byte(time.Now().Add(time.Duration(1)).String()))[:]
	header := &types.Header{
		ParentHash:  currentHash,
		Coinbase:    sender,
		Root:        common.ZeroHash,
		TxHash:      types.EmptyRootHash,
		ReceiptHash: types.EmptyRootHash,
		Number:      newNumber,
		Time:        uint64(time.Now().UnixNano()),
		Extra:       make([]byte, 97),
		Nonce:       types.EncodeNonce(nonce),
	}
	currentHash = header.Hash()

	if err := sndb.NewBlock(newNumber, header.ParentHash, currentHash); nil != err {
		t.Errorf("Failed to snapshotDB New Block, err: %v", err)
		return nil, err
	}

	return header, err
}

func create_staking(state xcom.StateDB, blockNumber *big.Int, blockHash common.Hash, index int, typ uint16, t *testing.T) error {

	balance, _ := new(big.Int).SetString(balanceStr[index], 10)
	var blsKey bls.SecretKey
	blsKey.SetByCSPRNG()
	canTmp := &staking.Candidate{}

	var blsKeyHex bls.PublicKeyHex

	b, _ := blsKey.GetPublicKey().MarshalText()
	err := blsKeyHex.UnmarshalText(b)
	if nil != err {
		log.Error("Failed to blsKeyHex.UnmarshalText", "err", err)
		return err
	}

	canBase := &staking.CandidateBase{
		NodeId:          nodeIdArr[index],
		BlsPubKey:       blsKeyHex,
		StakingAddress:  sender,
		BenefitAddress:  addrArr[index],
		StakingBlockNum: blockNumber.Uint64(),
		StakingTxIndex:  uint32(index),
		ProgramVersion:  xutil.CalcVersion(initProgramVersion),

		// Prevent null pointer initialization

		Description: staking.Description{
			NodeName:   nodeNameArr[index],
			ExternalId: nodeNameArr[index] + chaList[(len(chaList)-1)%(index+1)] + "balabalala" + chaList[index],
			Website:    "www." + nodeNameArr[index] + ".org",
			Details:    "This is " + nodeNameArr[index] + " Super Node",
		},
	}

	canMutable := &staking.CandidateMutable{
		Shares: balance,
		// Prevent null pointer initialization
		Released:           common.Big0,
		ReleasedHes:        common.Big0,
		RestrictingPlan:    common.Big0,
		RestrictingPlanHes: common.Big0,
	}

	canTmp.CandidateBase = canBase
	canTmp.CandidateMutable = canMutable

	canAddr, _ := xutil.NodeId2Addr(canTmp.NodeId)

	return StakingInstance().CreateCandidate(state, blockHash, blockNumber, canAddr.Big(), canTmp)
}

func getCandidate(blockHash common.Hash, index int) (*staking.Candidate, error) {
	addr, _ := xutil.NodeId2Addr(nodeIdArr[index])

	if can, err := StakingInstance().GetCandidateInfo(blockHash, addr.Big()); nil != err {
		return nil, err
	} else {

		return can, nil
	}
}

func getDelegate(blockHash common.Hash, stakingNum uint64, index int, t *testing.T) *staking.Delegation {

	del, err := StakingInstance().GetDelegateInfo(blockHash, addrArr[index+1], nodeIdArr[index], stakingNum)
	if nil != err {
		t.Log("Failed to GetDelegateInfo:", err)
	} else {
		delByte, _ := json.Marshal(del)
		t.Log("Get Delegate Info is:", string(delByte))
	}
	return del
}

/**
Standard test cases
*/

func TestStakingPlugin_BeginBlock(t *testing.T) {
	// nothings in that
}

func TestStakingPlugin_EndBlock(t *testing.T) {

	state, genesis, err := newChainState()
	if nil != err {
		t.Error("Failed to build the state", err)
		return
	}
	newPlugins()

	build_gov_data(state)

	sndb := snapshotdb.Instance()
	defer func() {
		sndb.Clear()
	}()

	// New VrfHandler instance by genesis block Hash
	handler.NewVrfHandler(genesis.Hash().Bytes())

	// build vrf proof
	// build ancestor nonces
	_, nonces := build_vrf_Nonce()
	enValue, err := rlp.EncodeToBytes(nonces)

	if !assert.Nil(t, err, fmt.Sprintf("Failed to rlp vrf nonces: %v", err)) {
		return
	}

	// new block
	privateKey, err := crypto.GenerateKey()

	if !assert.Nil(t, err, fmt.Sprintf("Failed to generate random Address private key: %v", err)) {
		return
	}

	nodeId := discover.PubkeyID(&privateKey.PublicKey)
	currentHash := crypto.Keccak256Hash([]byte(nodeId.String()))
	currentNumber := big.NewInt(1)

	// build genesis veriferList and validatorList
	validatorQueue := make(staking.ValidatorQueue, xcom.MaxValidators())

	for j := 0; j < 1000; j++ {
		var index int = j % 25

		balance, _ := new(big.Int).SetString(balanceStr[index], 10)

		mrand.Seed(time.Now().UnixNano())

		weight := mrand.Intn(1000000000)

		ii := mrand.Intn(len(chaList))

		balance = new(big.Int).Add(balance, big.NewInt(int64(weight)))

		privateKey, err := crypto.GenerateKey()
		if !assert.Nil(t, err, fmt.Sprintf("Failed to generate random NodeId private key: %v", err)) {
			return
		}

		nodeId := discover.PubkeyID(&privateKey.PublicKey)

		privateKey, err = crypto.GenerateKey()
		if !assert.Nil(t, err, fmt.Sprintf("Failed to generate random Address private key: %v", err)) {
			return
		}
		addr := crypto.PubkeyToAddress(privateKey.PublicKey)

		var blsKey bls.SecretKey
		blsKey.SetByCSPRNG()
		var blsKeyHex bls.PublicKeyHex
		err = blsKeyHex.UnmarshalText(blsKey.Serialize())
		if nil != err {
			return
		}

		canBase := &staking.CandidateBase{
			NodeId:          nodeId,
			BlsPubKey:       blsKeyHex,
			StakingAddress:  sender,
			BenefitAddress:  addr,
			StakingBlockNum: uint64(1),
			StakingTxIndex:  uint32(index),
			ProgramVersion:  xutil.CalcVersion(initProgramVersion),

			Description: staking.Description{
				NodeName:   nodeNameArr[index] + "_" + fmt.Sprint(j),
				ExternalId: nodeNameArr[index] + chaList[(len(chaList)-1)%(index+ii+1)] + "balabalala" + chaList[index],
				Website:    "www." + nodeNameArr[index] + "_" + fmt.Sprint(j) + ".org",
				Details:    "This is " + nodeNameArr[index] + "_" + fmt.Sprint(j) + " Super Node",
			},
		}
		canMutable := &staking.CandidateMutable{
			Shares: balance,
			// Prevent null pointer initialization
			Released:           common.Big0,
			ReleasedHes:        common.Big0,
			RestrictingPlan:    common.Big0,
			RestrictingPlanHes: common.Big0,
		}

		canAddr, _ := xutil.NodeId2Addr(canBase.NodeId)

		// Store Candidate power
		powerKey := staking.TallyPowerKey(canBase.ProgramVersion, canMutable.Shares, canBase.StakingBlockNum, canBase.StakingTxIndex, canBase.NodeId)
		if err := sndb.PutBaseDB(powerKey, canAddr.Bytes()); nil != err {
			t.Errorf("Failed to Store Candidate Power: PutBaseDB failed. error:%s", err.Error())
			return
		}

		// Store CandidateBase info
		canBaseKey := staking.CanBaseKeyByAddr(canAddr.Big())
		if val, err := rlp.EncodeToBytes(canBase); nil != err {
			t.Errorf("Failed to Store Candidate Base info: PutBaseDB failed. error:%s", err.Error())
			return
		} else {

			if err := sndb.PutBaseDB(canBaseKey, val); nil != err {
				t.Errorf("Failed to Store Candidate Base info: PutBaseDB failed. error:%s", err.Error())
				return
			}
		}

		// Store CandidateMutable info
		canMutableKey := staking.CanMutableKeyByAddr(canAddr.Big())
		if val, err := rlp.EncodeToBytes(canMutable); nil != err {
			t.Errorf("Failed to Store Candidate Mutable info: PutBaseDB failed. error:%s", err.Error())
			return
		} else {

			if err := sndb.PutBaseDB(canMutableKey, val); nil != err {
				t.Errorf("Failed to Store Candidate Mutable info: PutBaseDB failed. error:%s", err.Error())
				return
			}
		}

		if j < int(xcom.MaxValidators()) {
			v := &staking.Validator{
				NodeAddress:     canAddr,
				NodeId:          canBase.NodeId,
				BlsPubKey:       canBase.BlsPubKey,
				ProgramVersion:  canBase.ProgramVersion,
				Shares:          canMutable.Shares,
				StakingBlockNum: canBase.StakingBlockNum,
				StakingTxIndex:  canBase.StakingTxIndex,

				ValidatorTerm: 0,
			}
			validatorQueue[j] = v
		}

	}

	/**
	*******
	build genesis epoch validators
	*******
	*/
	verifierIndex := &staking.ValArrIndex{
		Start: 1,
		End:   xutil.CalcBlocksEachEpoch(),
	}

	epochIndexArr := make(staking.ValArrIndexQueue, 0)
	epochIndexArr = append(epochIndexArr, verifierIndex)

	// current epoch start and end indexs
	epoch_index, err := rlp.EncodeToBytes(epochIndexArr)
	if nil != err {
		t.Errorf("Failed to Store Epoch Validators start and end index: rlp encodeing failed. error:%s", err.Error())
		return
	}
	if err := sndb.PutBaseDB(staking.GetEpochIndexKey(), epoch_index); nil != err {
		t.Errorf("Failed to Store Epoch Validators start and end index: PutBaseDB failed. error:%s", err.Error())
		return
	}

	epochArr, err := rlp.EncodeToBytes(validatorQueue)
	if nil != err {
		t.Errorf("Failed to rlp encodeing genesis validators. error:%s", err.Error())
		return
	}
	// Store Epoch validators
	if err := sndb.PutBaseDB(staking.GetEpochValArrKey(verifierIndex.Start, verifierIndex.End), epochArr); nil != err {
		t.Errorf("Failed to Store Epoch Validators: PutBaseDB failed. error:%s", err.Error())
		return
	}

	/**
	*******
	build genesis curr round validators
	*******
	*/
	curr_indexInfo := &staking.ValArrIndex{
		Start: 1,
		End:   xutil.ConsensusSize(),
	}
	roundIndexArr := make(staking.ValArrIndexQueue, 0)
	roundIndexArr = append(roundIndexArr, curr_indexInfo)

	// round index
	round_index, err := rlp.EncodeToBytes(roundIndexArr)
	if !assert.Nil(t, err, fmt.Sprintf("Failed to Store Round Validators start and end indexs: rlp encodeing failed. error: %v", err)) {
		return
	}
	if err := sndb.PutBaseDB(staking.GetRoundIndexKey(), round_index); nil != err {
		t.Errorf("Failed to Store Round Validators start and end indexs: PutBaseDB failed. error:%s", err.Error())
		return
	}

	PrintObject("Test round", validatorQueue[:xcom.MaxConsensusVals()])
	roundArr, err := rlp.EncodeToBytes(validatorQueue[:xcom.MaxConsensusVals()])
	if !assert.Nil(t, err, fmt.Sprintf("Failed to rlp encodeing genesis validators. error: %v", err)) {
		return
	}
	// Store Current Round validator
	if err := sndb.PutBaseDB(staking.GetRoundValArrKey(curr_indexInfo.Start, curr_indexInfo.End), roundArr); nil != err {
		t.Errorf("Failed to Store Current Round Validators: PutBaseDB failed. error:%s", err.Error())
		return
	}

	// Store vrf nonces
	if err := sndb.PutBaseDB(handler.NonceStorageKey, enValue); nil != err {
		t.Errorf("Failed to Store Current Vrf nonces : PutBaseDB failed. error:%s", err.Error())
		return
	}

	// SetCurrent to snapshotDB
	currentNumber = big.NewInt(int64(xutil.ConsensusSize() - xcom.ElectionDistance())) // 50
	preNum1 := new(big.Int).Sub(currentNumber, big.NewInt(1))
	if err := sndb.SetCurrent(currentHash, *preNum1, *preNum1); nil != err {
		t.Errorf("Failed to SetCurrent by snapshotdb. error:%s", err.Error())
		return
	}

	/**
	EndBlock to Election()
	*/
	// new block
	currentNumber = big.NewInt(int64(xutil.ConsensusSize() - xcom.ElectionDistance())) // 50

	nonce := crypto.Keccak256([]byte(time.Now().Add(time.Duration(1)).String()))[:]
	header := &types.Header{
		ParentHash:  currentHash,
		Coinbase:    sender,
		Root:        common.ZeroHash,
		TxHash:      types.EmptyRootHash,
		ReceiptHash: types.EmptyRootHash,
		Number:      currentNumber,
		Time:        uint64(time.Now().UnixNano()),
		Extra:       make([]byte, 97),
		Nonce:       types.EncodeNonce(nonce),
	}
	currentHash = header.Hash()

	if err := sndb.NewBlock(currentNumber, header.ParentHash, currentHash); nil != err {
		t.Errorf("Failed to snapshotDB New Block, err: %v", err)
		return
	}

	err = StakingInstance().EndBlock(currentHash, header, state)
	if !assert.Nil(t, err, fmt.Sprintf("Failed to EndBlock, blockNumber: %d, err: %v", currentNumber, err)) {
		return
	}

	if err := sndb.Commit(currentHash); nil != err {
		t.Errorf("Failed to Commit, blockNumber: %d, blockHHash: %s, err: %v", currentNumber, currentHash.Hex(), err)
		return
	}

	if err := sndb.Compaction(); nil != err {
		t.Errorf("Failed to Compaction, blockNumber: %d, blockHHash: %s, err: %v", currentNumber, currentHash.Hex(), err)
		return
	}

	// new block
	privateKey2, err := crypto.GenerateKey()
	if nil != err {
		t.Errorf("Failed to generate random Address private key: %v", err)
		return
	}
	nodeId2 := discover.PubkeyID(&privateKey2.PublicKey)
	currentHash = crypto.Keccak256Hash([]byte(nodeId2.String()))

	/**
	Elect Epoch validator list  == ElectionNextList()
	*/
	// new block
	currentNumber = big.NewInt(int64(xutil.ConsensusSize() * xutil.EpochSize())) // 600

	preNum := new(big.Int).Sub(currentNumber, big.NewInt(1)) // 599

	if err := sndb.SetCurrent(currentHash, *preNum, *preNum); nil != err {
		panic(fmt.Errorf("Failed to SetCurrent by snapshotdb. error:%s", err.Error()))
	}

	nonce = crypto.Keccak256([]byte(time.Now().Add(time.Duration(1)).String()))[:]
	header = &types.Header{
		ParentHash:  currentHash,
		Coinbase:    sender,
		Root:        common.ZeroHash,
		TxHash:      types.EmptyRootHash,
		ReceiptHash: types.EmptyRootHash,
		Number:      currentNumber,
		Time:        uint64(time.Now().UnixNano()),
		Extra:       make([]byte, 97),
		Nonce:       types.EncodeNonce(nonce),
	}
	currentHash = header.Hash()

	if err := sndb.NewBlock(currentNumber, header.ParentHash, currentHash); nil != err {
		t.Errorf("Failed to snapshotDB New Block, err: %v", err)
		return
	}

	err = StakingInstance().EndBlock(currentHash, header, state)
	assert.Nil(t, err, fmt.Sprintf("Failed to Election, blockNumber: %d, err: %v", currentNumber, err))
}

func TestStakingPlugin_Confirmed(t *testing.T) {

	state, genesis, err := newChainState()
	if nil != err {
		t.Error("Failed to build the state", err)
		return
	}
	newPlugins()

	build_gov_data(state)

	sndb := snapshotdb.Instance()
	defer func() {
		sndb.Clear()
	}()

	// New VrfHandler instance by genesis block Hash
	handler.NewVrfHandler(genesis.Hash().Bytes())

	// build vrf proof
	// build ancestor nonces
	_, nonces := build_vrf_Nonce()
	enValue, err := rlp.EncodeToBytes(nonces)
	if !assert.Nil(t, err, fmt.Sprintf("Failed to rlp vrf nonces: %v", err)) {
		return
	}

	// new block
	privateKey, err := crypto.GenerateKey()
	if !assert.Nil(t, err, fmt.Sprintf("Failed to generate random Address private key: %v", err)) {
		return
	}

	nodeId := discover.PubkeyID(&privateKey.PublicKey)
	currentHash := crypto.Keccak256Hash([]byte(nodeId.String()))
	currentNumber := big.NewInt(1)

	// build genesis veriferList and validatorList
	validatorQueue := make(staking.ValidatorQueue, xcom.MaxValidators())

	for j := 0; j < 1000; j++ {
		var index int = j % 25

		balance, _ := new(big.Int).SetString(balanceStr[index], 10)

		mrand.Seed(time.Now().UnixNano())

		weight := mrand.Intn(1000000000)

		ii := mrand.Intn(len(chaList))

		balance = new(big.Int).Add(balance, big.NewInt(int64(weight)))

		privateKey, err := crypto.GenerateKey()
		if nil != err {
			t.Errorf("Failed to generate random NodeId private key: %v", err)
			return
		}

		nodeId := discover.PubkeyID(&privateKey.PublicKey)

		privateKey, err = crypto.GenerateKey()
		if !assert.Nil(t, err, fmt.Sprintf("Failed to generate random Address private key: %v", err)) {
			return
		}

		addr := crypto.PubkeyToAddress(privateKey.PublicKey)

		var blsKey bls.SecretKey
		blsKey.SetByCSPRNG()
		var blsKeyHex bls.PublicKeyHex
		err = blsKeyHex.UnmarshalText(blsKey.Serialize())
		if nil != err {
			return
		}

		canBase := &staking.CandidateBase{
			NodeId:          nodeId,
			BlsPubKey:       blsKeyHex,
			StakingAddress:  sender,
			BenefitAddress:  addr,
			StakingBlockNum: uint64(1),
			StakingTxIndex:  uint32(index),
			ProgramVersion:  xutil.CalcVersion(initProgramVersion),

			Description: staking.Description{
				NodeName:   nodeNameArr[index] + "_" + fmt.Sprint(j),
				ExternalId: nodeNameArr[index] + chaList[(len(chaList)-1)%(index+ii+1)] + "balabalala" + chaList[index],
				Website:    "www." + nodeNameArr[index] + "_" + fmt.Sprint(j) + ".org",
				Details:    "This is " + nodeNameArr[index] + "_" + fmt.Sprint(j) + " Super Node",
			},
		}
		canMutable := &staking.CandidateMutable{
			Shares: balance,
			// Prevent null pointer initialization
			Released:           common.Big0,
			ReleasedHes:        common.Big0,
			RestrictingPlan:    common.Big0,
			RestrictingPlanHes: common.Big0,
		}

		canAddr, _ := xutil.NodeId2Addr(canBase.NodeId)

		// Store Candidate power
		powerKey := staking.TallyPowerKey(canBase.ProgramVersion, canMutable.Shares, canBase.StakingBlockNum, canBase.StakingTxIndex, canBase.NodeId)
		if err := sndb.PutBaseDB(powerKey, canAddr.Bytes()); nil != err {
			t.Errorf("Failed to Store Candidate Power: PutBaseDB failed. error:%s", err.Error())
			return
		}

		// Store CandidateBase info
		canBaseKey := staking.CanBaseKeyByAddr(canAddr.Big())
		if val, err := rlp.EncodeToBytes(canBase); nil != err {
			t.Errorf("Failed to Store Candidate Base info: PutBaseDB failed. error:%s", err.Error())
			return
		} else {

			if err := sndb.PutBaseDB(canBaseKey, val); nil != err {
				t.Errorf("Failed to Store Candidate Base info: PutBaseDB failed. error:%s", err.Error())
				return
			}
		}

		// Store CandidateMutable info
		canMutableKey := staking.CanMutableKeyByAddr(canAddr.Big())
		if val, err := rlp.EncodeToBytes(canMutable); nil != err {
			t.Errorf("Failed to Store Candidate Mutable info: PutBaseDB failed. error:%s", err.Error())
			return
		} else {

			if err := sndb.PutBaseDB(canMutableKey, val); nil != err {
				t.Errorf("Failed to Store Candidate Mutable info: PutBaseDB failed. error:%s", err.Error())
				return
			}
		}

		if j < int(xcom.MaxValidators()) {
			v := &staking.Validator{
				NodeAddress:     canAddr,
				NodeId:          canBase.NodeId,
				BlsPubKey:       canBase.BlsPubKey,
				ProgramVersion:  canBase.ProgramVersion,
				Shares:          canMutable.Shares,
				StakingBlockNum: canBase.StakingBlockNum,
				StakingTxIndex:  canBase.StakingTxIndex,

				ValidatorTerm: 0,
			}
			validatorQueue[j] = v
		}
	}
	/**
	*******
	build genesis epoch validators
	*******
	*/
	verifierIndex := &staking.ValArrIndex{
		Start: 1,
		End:   xutil.CalcBlocksEachEpoch(),
	}

	epochIndexArr := make(staking.ValArrIndexQueue, 0)
	epochIndexArr = append(epochIndexArr, verifierIndex)

	// current epoch start and end indexs
	epoch_index, err := rlp.EncodeToBytes(epochIndexArr)
	if !assert.Nil(t, err, fmt.Sprintf("Failed to Store Epoch Validators start and end index: rlp encodeing failed. error: %v", err)) {
		return
	}

	if err := sndb.PutBaseDB(staking.GetEpochIndexKey(), epoch_index); nil != err {
		t.Errorf("Failed to Store Epoch Validators start and end index: PutBaseDB failed. error:%s", err.Error())
		return
	}

	epochArr, err := rlp.EncodeToBytes(validatorQueue)
	if !assert.Nil(t, err, fmt.Sprintf("Failed to rlp encodeing genesis validators. error: %v", err)) {
		return
	}
	// Store Epoch validators
	if err := sndb.PutBaseDB(staking.GetEpochValArrKey(verifierIndex.Start, verifierIndex.End), epochArr); nil != err {
		t.Errorf("Failed to Store Epoch Validators: PutBaseDB failed. error:%s", err.Error())
		return
	}

	/**
	*******
	build genesis curr round validators
	*******
	*/
	curr_indexInfo := &staking.ValArrIndex{
		Start: 1,
		End:   xutil.ConsensusSize(),
	}
	roundIndexArr := make(staking.ValArrIndexQueue, 0)
	roundIndexArr = append(roundIndexArr, curr_indexInfo)

	// round index
	round_index, err := rlp.EncodeToBytes(roundIndexArr)
	if !assert.Nil(t, err, fmt.Sprintf("Failed to Store Round Validators start and end indexs: rlp encodeing failed. error: %v", err)) {
		return
	}

	if err := sndb.PutBaseDB(staking.GetRoundIndexKey(), round_index); nil != err {
		t.Errorf("Failed to Store Round Validators start and end indexs: PutBaseDB failed. error:%s", err.Error())
		return
	}

	PrintObject("Test round", validatorQueue[:xcom.MaxConsensusVals()])
	roundArr, err := rlp.EncodeToBytes(validatorQueue[:xcom.MaxConsensusVals()])
	if !assert.Nil(t, err, fmt.Sprintf("Failed to rlp encodeing genesis validators. error: %v", err)) {
		return
	}
	// Store Current Round validator
	if err := sndb.PutBaseDB(staking.GetRoundValArrKey(curr_indexInfo.Start, curr_indexInfo.End), roundArr); nil != err {
		t.Errorf("Failed to Store Current Round Validators: PutBaseDB failed. error:%s", err.Error())
		return
	}

	// Store vrf nonces
	if err := sndb.PutBaseDB(handler.NonceStorageKey, enValue); nil != err {
		t.Errorf("Failed to Store Current Vrf nonces : PutBaseDB failed. error:%s", err.Error())
		return
	}

	// SetCurrent to snapshotDB
	currentNumber = big.NewInt(int64(xutil.ConsensusSize() - xcom.ElectionDistance())) // 50
	preNum1 := new(big.Int).Sub(currentNumber, big.NewInt(1))
	if err := sndb.SetCurrent(currentHash, *preNum1, *preNum1); nil != err {
		t.Errorf("Failed to SetCurrent by snapshotdb. error:%s", err.Error())
		return
	}

	/**
	EndBlock to Election()
	*/
	// new block
	currentNumber = big.NewInt(int64(xutil.ConsensusSize() - xcom.ElectionDistance())) // 50

	nonce := crypto.Keccak256([]byte(time.Now().Add(time.Duration(1)).String()))[:]
	header := &types.Header{
		ParentHash:  currentHash,
		Coinbase:    sender,
		Root:        common.ZeroHash,
		TxHash:      types.EmptyRootHash,
		ReceiptHash: types.EmptyRootHash,
		Number:      currentNumber,
		Time:        uint64(time.Now().UnixNano()),
		Extra:       make([]byte, 97),
		Nonce:       types.EncodeNonce(nonce),
	}
	currentHash = header.Hash()

	if err := sndb.NewBlock(currentNumber, header.ParentHash, currentHash); nil != err {
		t.Errorf("Failed to snapshotDB New Block, err: %v", err)
		return
	}

	err = StakingInstance().EndBlock(currentHash, header, state)
	if !assert.Nil(t, err, fmt.Sprintf("Failed to EndBlock, blockNumber: %d, err: %v", currentNumber, err)) {
		return
	}

	/**
	Start Confirmed
	*/

	eventMux := &event.TypeMux{}
	StakingInstance().SetEventMux(eventMux)
	go watching(eventMux, t)

	blockElection := types.NewBlock(header, nil, nil, new(trie.Trie))

	next, err := StakingInstance().getNextValList(blockElection.Hash(), blockElection.Number().Uint64(), QueryStartNotIrr)

	assert.Nil(t, err, fmt.Sprintf("Failed to getNextValList, blockNumber: %d, err: %v", blockElection.Number().Uint64(), err))

	err = StakingInstance().Confirmed(next.Arr[0].NodeId, blockElection)
	assert.Nil(t, err, fmt.Sprintf("Failed to Confirmed, blockNumber: %d, err: %v", blockElection.Number().Uint64(), err))

}

func TestStakingPlugin_CreateCandidate(t *testing.T) {

	state, genesis, err := newChainState()
	if nil != err {
		t.Error("Failed to build the state", err)
		return
	}

	newPlugins()

	build_gov_data(state)

	sndb := snapshotdb.Instance()
	defer func() {
		sndb.Clear()
	}()

	if err := sndb.NewBlock(blockNumber, genesis.Hash(), blockHash); nil != err {
		t.Error("newBlock err", err)
		return
	}

	/**
	Start Create Staking
	*/
	err = create_staking(state, blockNumber, blockHash, 1, 0, t)
	assert.Nil(t, err, fmt.Sprintf("Failed to Create Staking: %v", err))
}

func TestStakingPlugin_GetCandidateInfo(t *testing.T) {

	state, genesis, err := newChainState()
	if nil != err {
		t.Error("Failed to build the state", err)
		return
	}
	newPlugins()

	build_gov_data(state)

	sndb := snapshotdb.Instance()
	defer func() {
		sndb.Clear()
	}()

	if err := sndb.NewBlock(blockNumber, genesis.Hash(), blockHash); nil != err {
		t.Error("newBlock err", err)
		return
	}

	index := 1

	if err := create_staking(state, blockNumber, blockHash, index, 0, t); nil != err {
		t.Error("Failed to Create Staking", err)
		return
	}

	if err := sndb.Commit(blockHash); nil != err {
		t.Error("Commit 1 err", err)
		return
	}

	/**
	Start Get Candidate Info
	*/
	can, err := getCandidate(blockHash, index)
	assert.Nil(t, err, fmt.Sprintf("Failed to getCandidate: %v", err))
	assert.True(t, nil != can)
	t.Log("Get Candidate Info is:", can)

}

func TestStakingPlugin_GetCandidateInfoByIrr(t *testing.T) {

	state, genesis, err := newChainState()
	if nil != err {
		t.Error("Failed to build the state", err)
		return
	}
	newPlugins()

	build_gov_data(state)

	sndb := snapshotdb.Instance()
	defer func() {
		sndb.Clear()
	}()

	if err := sndb.NewBlock(blockNumber, genesis.Hash(), blockHash); nil != err {
		t.Error("newBlock err", err)
		return
	}

	index := 1

	if err := create_staking(state, blockNumber, blockHash, index, 0, t); nil != err {
		t.Error("Failed to Create Staking", err)
		return
	}

	if err := sndb.Commit(blockHash); nil != err {
		t.Error("Commit 1 err", err)
		return
	}

	/**
	Start GetCandidateInfoByIrr

	Get Candidate Info
	*/
	addr, _ := xutil.NodeId2Addr(nodeIdArr[index])

	can, err := StakingInstance().GetCandidateInfoByIrr(addr.Big())

	assert.Nil(t, err, fmt.Sprintf("Failed to GetCandidateInfoByIrr: %v", err))
	assert.True(t, nil != can)
	t.Log("Get Candidate Info is:", can)

}

func TestStakingPlugin_GetCandidateList(t *testing.T) {

	state, genesis, err := newChainState()
	if nil != err {
		t.Error("Failed to build the state", err)
		return
	}
	newPlugins()

	build_gov_data(state)

	sndb := snapshotdb.Instance()
	defer func() {
		sndb.Clear()
	}()

	if err := sndb.NewBlock(blockNumber, genesis.Hash(), blockHash); nil != err {
		t.Error("newBlock err", err)
		return
	}

	count := 0
	for i := 0; i < 4; i++ {
		if err := create_staking(state, blockNumber, blockHash, i, 0, t); nil != err {
			t.Error("Failed to Create num: "+fmt.Sprint(i)+" Staking", err)
			return
		}
		count++
	}

	if err := sndb.Commit(blockHash); nil != err {
		t.Error("Commit 1 err", err)
		return
	}

	/**
	Start GetCandidateList
	*/

	queue, err := StakingInstance().GetCandidateList(blockHash, blockNumber.Uint64())
	assert.Nil(t, err, fmt.Sprintf("Failed to GetCandidateList: %v", err))
	assert.Equal(t, count, len(queue))
	queueByte, _ := json.Marshal(queue)
	t.Log("Get CandidateList Info is:", string(queueByte))
}

func TestStakingPlugin_ElectNextVerifierList(t *testing.T) {

	state, genesis, err := newChainState()
	if nil != err {
		t.Error("Failed to build the state", err)
		return
	}
	newPlugins()

	build_gov_data(state)

	sndb := snapshotdb.Instance()
	defer func() {
		sndb.Clear()
	}()

	if err := sndb.NewBlock(blockNumber, genesis.Hash(), blockHash); nil != err {
		t.Error("newBlock err", err)
		return
	}

	for i := 0; i < 1000; i++ {

		var index int
		if i >= len(balanceStr) {
			index = i % (len(balanceStr) - 1)
		}

		balance, _ := new(big.Int).SetString(balanceStr[index], 10)

		mrand.Seed(time.Now().UnixNano())

		weight := mrand.Intn(1000000000)

		ii := mrand.Intn(len(chaList))

		balance = new(big.Int).Add(balance, big.NewInt(int64(weight)))

		privateKey, err := crypto.GenerateKey()
		if nil != err {
			t.Errorf("Failed to generate random NodeId private key: %v", err)
			return
		}

		nodeId := discover.PubkeyID(&privateKey.PublicKey)

		privateKey, err = crypto.GenerateKey()
		if nil != err {
			t.Errorf("Failed to generate random Address private key: %v", err)
			return
		}

		addr := crypto.PubkeyToAddress(privateKey.PublicKey)

		var blsKey bls.SecretKey
		blsKey.SetByCSPRNG()
		var blsKeyHex bls.PublicKeyHex
		b, _ := blsKey.GetPublicKey().MarshalText()
		if err := blsKeyHex.UnmarshalText(b); nil != err {
			log.Error("Failed to blsKeyHex.UnmarshalText", "err", err)
			return
		}

		canTmp := &staking.Candidate{
			CandidateBase: &staking.CandidateBase{
				NodeId:          nodeId,
				BlsPubKey:       blsKeyHex,
				StakingAddress:  sender,
				BenefitAddress:  addr,
				StakingBlockNum: uint64(i),
				StakingTxIndex:  uint32(index),
				ProgramVersion:  xutil.CalcVersion(initProgramVersion),

				Description: staking.Description{
					NodeName:   nodeNameArr[index] + "_" + fmt.Sprint(i),
					ExternalId: nodeNameArr[index] + chaList[(len(chaList)-1)%(index+ii+1)] + "balabalala" + chaList[index],
					Website:    "www." + nodeNameArr[index] + "_" + fmt.Sprint(i) + ".org",
					Details:    "This is " + nodeNameArr[index] + "_" + fmt.Sprint(i) + " Super Node",
				},
			},
			CandidateMutable: &staking.CandidateMutable{
				Shares: balance,

				// Prevent null pointer initialization
				Released:           common.Big0,
				ReleasedHes:        common.Big0,
				RestrictingPlan:    common.Big0,
				RestrictingPlanHes: common.Big0,
			},
		}

		canAddr, _ := xutil.NodeId2Addr(canTmp.NodeId)
		err = StakingInstance().CreateCandidate(state, blockHash, blockNumber, canAddr.Big(), canTmp)

		if nil != err {
			t.Errorf("Failed to Create Staking, num: %d, err: %v", i, err)
			return
		}
	}

	stakingDB := staking.NewStakingDB()

	// build genesis VerifierList
	start := uint64(1)
	end := xutil.EpochSize() * xutil.ConsensusSize()

	new_verifierArr := &staking.ValidatorArray{
		Start: start,
		End:   end,
	}

	queue := make(staking.ValidatorQueue, 0)

	iter := sndb.Ranking(blockHash, staking.CanPowerKeyPrefix, 0)
	if err := iter.Error(); nil != err {
		t.Errorf("Failed to build genesis VerifierList, the iter is  err: %v", err)
		return
	}

	defer iter.Release()

	// for count := 0; iterator.Valid() && count < int(maxValidators); iterator.Next() {

	count := 0
	for iter.Valid(); iter.Next(); {
		if uint64(count) == xcom.MaxValidators() {
			break
		}
		addrSuffix := iter.Value()
		var can *staking.Candidate

		can, err := stakingDB.GetCandidateStoreWithSuffix(blockHash, addrSuffix)
		if nil != err {
			t.Error("Failed to ElectNextVerifierList", "canAddr", common.BytesToNodeAddress(addrSuffix).Hex(), "err", err)
			return
		}

		addr := common.BytesToNodeAddress(addrSuffix)

		val := &staking.Validator{
			NodeAddress:     addr,
			NodeId:          can.NodeId,
			BlsPubKey:       can.BlsPubKey,
			ProgramVersion:  can.ProgramVersion,
			Shares:          can.Shares,
			StakingBlockNum: can.StakingBlockNum,
			StakingTxIndex:  can.StakingTxIndex,
			ValidatorTerm:   0,
		}
		queue = append(queue, val)
		count++
	}

	new_verifierArr.Arr = queue

	err = setVerifierList(blockHash, new_verifierArr)

	if !assert.Nil(t, err, fmt.Sprintf("Failed to VerifierList: %v", err)) {
		return
	}

	if err := sndb.Commit(blockHash); nil != err {
		t.Error("Commit 1 err", err)
		return
	}

	/*
		Start ElectNextVerifierList
	*/
	targetNum := xutil.EpochSize() * xutil.ConsensusSize()

	targetNumInt := big.NewInt(int64(targetNum))

	if err := sndb.NewBlock(blockNumber2, blockHash, blockHash2); nil != err {
		t.Error("newBlock 2 err", err)
		return
	}

	err = StakingInstance().ElectNextVerifierList(blockHash2, targetNumInt.Uint64(), state)

	assert.Nil(t, err, fmt.Sprintf("Failed to ElectNextVerifierList: %v", err))

}

func TestStakingPlugin_Election(t *testing.T) {

	state, genesis, err := newChainState()
	if nil != err {
		t.Error("Failed to build the state", err)
		return
	}
	newPlugins()

	build_gov_data(state)

	sndb := snapshotdb.Instance()
	defer func() {
		sndb.Clear()
	}()

	// Must new VrfHandler instance by genesis block Hash
	handler.NewVrfHandler(genesis.Hash().Bytes())

	if err := sndb.NewBlock(blockNumber, genesis.Hash(), blockHash); nil != err {
		t.Error("newBlock err", err)
		return
	}

	for i := 0; i < 1000; i++ {

		var index int
		if i >= len(balanceStr) {
			index = i % (len(balanceStr) - 1)
		}

		balance, _ := new(big.Int).SetString(balanceStr[index], 10)

		mrand.Seed(time.Now().UnixNano())

		weight := mrand.Intn(1000000000)

		ii := mrand.Intn(len(chaList))

		balance = new(big.Int).Add(balance, big.NewInt(int64(weight)))

		privateKey, err := crypto.GenerateKey()
		if nil != err {
			t.Errorf("Failed to generate random NodeId private key: %v", err)
			return
		}

		nodeId := discover.PubkeyID(&privateKey.PublicKey)

		privateKey, err = crypto.GenerateKey()
		if nil != err {
			t.Errorf("Failed to generate random Address private key: %v", err)
			return
		}

		addr := crypto.PubkeyToAddress(privateKey.PublicKey)

		var blsKey bls.SecretKey
		blsKey.SetByCSPRNG()
		var blsKeyHex bls.PublicKeyHex
		b, _ := blsKey.GetPublicKey().MarshalText()
		if err := blsKeyHex.UnmarshalText(b); nil != err {
			log.Error("Failed to blsKeyHex.UnmarshalText", "err", err)
			return
		}

		canTmp := &staking.Candidate{
			CandidateBase: &staking.CandidateBase{
				NodeId:          nodeId,
				BlsPubKey:       blsKeyHex,
				StakingAddress:  sender,
				BenefitAddress:  addr,
				StakingBlockNum: uint64(i),
				StakingTxIndex:  uint32(index),
				ProgramVersion:  xutil.CalcVersion(initProgramVersion),

				Description: staking.Description{
					NodeName:   nodeNameArr[index] + "_" + fmt.Sprint(i),
					ExternalId: nodeNameArr[index] + chaList[(len(chaList)-1)%(index+ii+1)] + "balabalala" + chaList[index],
					Website:    "www." + nodeNameArr[index] + "_" + fmt.Sprint(i) + ".org",
					Details:    "This is " + nodeNameArr[index] + "_" + fmt.Sprint(i) + " Super Node",
				},
			},
			CandidateMutable: &staking.CandidateMutable{
				Shares: balance,

				// Prevent null pointer initialization
				Released:           common.Big0,
				ReleasedHes:        common.Big0,
				RestrictingPlan:    common.Big0,
				RestrictingPlanHes: common.Big0,
			},
		}

		canAddr, _ := xutil.NodeId2Addr(canTmp.NodeId)
		err = StakingInstance().CreateCandidate(state, blockHash, blockNumber, canAddr.Big(), canTmp)

		if nil != err {
			t.Errorf("Failed to Create Staking, num: %d, err: %v", i, err)
			return
		}
	}

	stakingDB := staking.NewStakingDB()

	// build genesis VerifierList

	start := uint64(1)
	end := xutil.EpochSize() * xutil.ConsensusSize()

	new_verifierArr := &staking.ValidatorArray{
		Start: start,
		End:   end,
	}

	queue := make(staking.ValidatorQueue, 0)

	iter := sndb.Ranking(blockHash, staking.CanPowerKeyPrefix, 0)
	if err := iter.Error(); nil != err {
		t.Errorf("Failed to build genesis VerifierList, the iter is  err: %v", err)
		return
	}

	defer iter.Release()

	count := 0
	for iter.Valid(); iter.Next(); {
		if uint64(count) == xcom.MaxValidators() {
			break
		}
		addrSuffix := iter.Value()
		var can *staking.Candidate

		can, err := stakingDB.GetCandidateStoreWithSuffix(blockHash, addrSuffix)
		if nil != err {
			t.Error("Failed to ElectNextVerifierList", "canAddr", common.BytesToNodeAddress(addrSuffix).Hex(), "err", err)
			return
		}

		addr := common.BytesToNodeAddress(addrSuffix)

		val := &staking.Validator{
			NodeAddress:     addr,
			NodeId:          can.NodeId,
			BlsPubKey:       can.BlsPubKey,
			ProgramVersion:  can.ProgramVersion,
			Shares:          can.Shares,
			StakingBlockNum: can.StakingBlockNum,
			StakingTxIndex:  can.StakingTxIndex,
			ValidatorTerm:   0,
		}
		queue = append(queue, val)
		count++
	}

	new_verifierArr.Arr = queue

	err = setVerifierList(blockHash, new_verifierArr)
	if nil != err {
		t.Errorf("Failed to Set Genesis VerfierList, err: %v", err)
		return
	}

	// build gensis current validatorList
	new_validatorArr := &staking.ValidatorArray{
		Start: start,
		End:   xutil.ConsensusSize(),
	}

	new_validatorArr.Arr = queue[:int(xcom.MaxConsensusVals())]

	err = setRoundValList(blockHash, new_validatorArr)
	if nil != err {
		t.Errorf("Failed to Set Genesis current round validatorList, err: %v", err)
		return
	}

	// build ancestor nonces
	currNonce, nonces := build_vrf_Nonce()
	if enValue, err := rlp.EncodeToBytes(nonces); nil != err {
		t.Error("Storage previous nonce failed", "err", err)
		return
	} else {
		sndb.Put(blockHash, handler.NonceStorageKey, enValue)
	}

	if err := sndb.Commit(blockHash); nil != err {
		t.Error("Commit 1 err", err)
		return
	}

	/*
		Start Election
	*/
	if err := sndb.NewBlock(blockNumber2, blockHash, blockHash2); nil != err {
		t.Error("newBlock 2 err", err)
		return
	}

	header := &types.Header{
		ParentHash: blockHash,
		Number:     big.NewInt(int64(xutil.ConsensusSize() - xcom.ElectionDistance())),
		Nonce:      types.EncodeNonce(currNonce),
	}

	err = StakingInstance().Election(blockHash2, header, state)

	assert.Nil(t, err, fmt.Sprintf("Failed to Election: %v", err))

}

func TestStakingPlugin_SlashCandidates(t *testing.T) {

	state, genesis, err := newChainState()
	if nil != err {
		t.Error("Failed to build the state", err)
		return
	}
	newPlugins()

	build_gov_data(state)

	sndb := snapshotdb.Instance()
	defer func() {
		sndb.Clear()
	}()

	if err := sndb.NewBlock(blockNumber, genesis.Hash(), blockHash); nil != err {
		t.Error("newBlock err", err)
		return
	}

	// Will be Slashing candidate
	slashQueue := make(staking.CandidateQueue, 5)

	for i := 0; i < 1000; i++ {

		var index int
		if i >= len(balanceStr) {
			index = i % (len(balanceStr) - 1)
		}

		balance, _ := new(big.Int).SetString(balanceStr[index], 10)

		mrand.Seed(time.Now().UnixNano())

		weight := mrand.Intn(1000000000)

		ii := mrand.Intn(len(chaList))

		balance = new(big.Int).Add(balance, big.NewInt(int64(weight)))

		privateKey, err := crypto.GenerateKey()
		if nil != err {
			t.Errorf("Failed to generate random NodeId private key: %v", err)
			return
		}

		nodeId := discover.PubkeyID(&privateKey.PublicKey)

		privateKey, err = crypto.GenerateKey()
		if nil != err {
			t.Errorf("Failed to generate random Address private key: %v", err)
			return
		}

		addr := crypto.PubkeyToAddress(privateKey.PublicKey)

		var blsKey bls.SecretKey
		blsKey.SetByCSPRNG()
		var blsKeyHex bls.PublicKeyHex
		b, _ := blsKey.GetPublicKey().MarshalText()
		if err := blsKeyHex.UnmarshalText(b); nil != err {
			log.Error("Failed to blsKeyHex.UnmarshalText", "err", err)
			return
		}

		releasedHes := new(big.Int).SetUint64(10000)
		canTmp := &staking.Candidate{
			CandidateBase: &staking.CandidateBase{
				NodeId:          nodeId,
				BlsPubKey:       blsKeyHex,
				StakingAddress:  sender,
				BenefitAddress:  addr,
				StakingBlockNum: uint64(i),
				StakingTxIndex:  uint32(index),
				ProgramVersion:  xutil.CalcVersion(initProgramVersion),

				Description: staking.Description{
					NodeName:   nodeNameArr[index] + "_" + fmt.Sprint(i),
					ExternalId: nodeNameArr[index] + chaList[(len(chaList)-1)%(index+ii+1)] + "balabalala" + chaList[index],
					Website:    "www." + nodeNameArr[index] + "_" + fmt.Sprint(i) + ".org",
					Details:    "This is " + nodeNameArr[index] + "_" + fmt.Sprint(i) + " Super Node",
				},
			},
			CandidateMutable: &staking.CandidateMutable{
				Shares: new(big.Int).Add(balance, releasedHes),

				// Prevent null pointer initialization
				Released:           new(big.Int).Set(balance),
				ReleasedHes:        releasedHes,
				RestrictingPlan:    common.Big0,
				RestrictingPlanHes: common.Big0,
			},
		}

		canAddr, _ := xutil.NodeId2Addr(canTmp.NodeId)
		err = StakingInstance().CreateCandidate(state, blockHash, blockNumber, canAddr.Big(), canTmp)

		if nil != err {
			t.Errorf("Failed to Create Staking, num: %d, err: %v", i, err)
			return
		}
		if i < len(slashQueue) {
			slashQueue[i] = canTmp
		}
	}

	stakingDB := staking.NewStakingDB()

	// build genesis VerifierList

	start := uint64(1)
	end := xutil.EpochSize() * xutil.ConsensusSize()

	new_verifierArr := &staking.ValidatorArray{
		Start: start,
		End:   end,
	}

	queue := make(staking.ValidatorQueue, 0)

	iter := sndb.Ranking(blockHash, staking.CanPowerKeyPrefix, 0)
	if err := iter.Error(); nil != err {
		t.Errorf("Failed to build genesis VerifierList, the iter is  err: %v", err)
		return
	}

	defer iter.Release()

	// for count := 0; iterator.Valid() && count < int(maxValidators); iterator.Next() {

	count := 0
	for iter.Valid(); iter.Next(); {
		if uint64(count) == xcom.MaxValidators() {
			break
		}
		addrSuffix := iter.Value()
		var can *staking.Candidate

		can, err := stakingDB.GetCandidateStoreWithSuffix(blockHash, addrSuffix)
		if nil != err {
			t.Error("Failed to ElectNextVerifierList", "canAddr", common.BytesToNodeAddress(addrSuffix).Hex(), "err", err)
			return
		}

		addr := common.BytesToNodeAddress(addrSuffix)

		val := &staking.Validator{
			NodeAddress:     addr,
			NodeId:          can.NodeId,
			BlsPubKey:       can.BlsPubKey,
			ProgramVersion:  can.ProgramVersion,
			Shares:          can.Shares,
			StakingBlockNum: can.StakingBlockNum,
			StakingTxIndex:  can.StakingTxIndex,
			ValidatorTerm:   0,
		}
		queue = append(queue, val)
		count++
	}

	new_verifierArr.Arr = queue

	err = setVerifierList(blockHash, new_verifierArr)
	if nil != err {
		t.Errorf("Failed to Set Genesis VerfierList, err: %v", err)
		return
	}

	if err := sndb.Commit(blockHash); nil != err {
		t.Error("Commit 1 err", err)
		return
	}

	/**
	Start SlashCandidates
	*/
	if err := sndb.NewBlock(blockNumber2, blockHash, blockHash2); nil != err {
		t.Error("newBlock err", err)
		return
	}

	slash1 := slashQueue[0]
	slash2 := slashQueue[1]

	slashItemQueue := make(staking.SlashQueue, 0)

	// Be punished for less than the quality deposit
	slashItem1 := &staking.SlashNodeItem{
		NodeId:      slash1.NodeId,
		Amount:      slash1.Released,
		SlashType:   staking.LowRatio,
		BenefitAddr: vm.RewardManagerPoolAddr,
	}

	// Double sign penalty
	sla := new(big.Int).Div(slash2.Released, big.NewInt(10))
	caller := common.MustBech32ToAddress("lax1uj3zd9yz00axz7ls88ynwsp3jprhjd9ldx9qpm")
	slashItem2 := &staking.SlashNodeItem{
		NodeId:      slash2.NodeId,
		Amount:      sla,
		SlashType:   staking.DuplicateSign,
		BenefitAddr: caller,
	}
	slashItemQueue = append(slashItemQueue, slashItem1)
	slashItemQueue = append(slashItemQueue, slashItem2)

	// Penalty for two low block rates
	slash3 := slashQueue[2]
	slashAmount3 := new(big.Int).Div(slash3.Released, big.NewInt(10))
	slashItem3_1 := &staking.SlashNodeItem{
		NodeId:      slash3.NodeId,
		Amount:      slashAmount3,
		SlashType:   staking.LowRatio,
		BenefitAddr: vm.RewardManagerPoolAddr,
	}
	slashItem3_2 := &staking.SlashNodeItem{
		NodeId:      slash3.NodeId,
		Amount:      slashAmount3,
		SlashType:   staking.LowRatio,
		BenefitAddr: vm.RewardManagerPoolAddr,
	}
	slashItemQueue = append(slashItemQueue, slashItem3_1)
	slashItemQueue = append(slashItemQueue, slashItem3_2)

	// Penalty for low block rate first, and then trigger double sign penalty
	slash4 := slashQueue[3]
	slashAmount4 := new(big.Int).Div(slash4.Released, big.NewInt(10))
	slashItem4_1 := &staking.SlashNodeItem{
		NodeId:      slash4.NodeId,
		Amount:      slashAmount4,
		SlashType:   staking.LowRatio,
		BenefitAddr: vm.RewardManagerPoolAddr,
	}
	slashItem4_2 := &staking.SlashNodeItem{
		NodeId:      slash4.NodeId,
		Amount:      slashAmount4,
		SlashType:   staking.DuplicateSign,
		BenefitAddr: caller,
	}
	slashItemQueue = append(slashItemQueue, slashItem4_1)
	slashItemQueue = append(slashItemQueue, slashItem4_2)

	// Double signing penalty first, and then triggering low block rate penalty
	slash5 := slashQueue[4]
	slashAmount5 := new(big.Int).Div(slash5.Released, big.NewInt(10))
	slashItem5_1 := &staking.SlashNodeItem{
		NodeId:      slash5.NodeId,
		Amount:      slashAmount5,
		SlashType:   staking.DuplicateSign,
		BenefitAddr: caller,
	}
	slashItem5_2 := &staking.SlashNodeItem{
		NodeId:      slash5.NodeId,
		Amount:      slashAmount5,
		SlashType:   staking.LowRatio,
		BenefitAddr: vm.RewardManagerPoolAddr,
	}
	slashItemQueue = append(slashItemQueue, slashItem5_1)
	slashItemQueue = append(slashItemQueue, slashItem5_2)

	err = StakingInstance().SlashCandidates(state, blockHash2, blockNumber2.Uint64(), slashItemQueue...)
	assert.Nil(t, err, fmt.Sprintf("Failed to SlashCandidates Second can (DuplicateSign), err: %v", err))

	canAddr1, _ := xutil.NodeId2Addr(slash1.NodeId)
	can1, err := StakingInstance().GetCandidateInfo(blockHash2, canAddr1.Big())
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, can1.Released.Cmp(new(big.Int).Sub(slash1.Released, slashItem1.Amount)) == 0)
	assert.True(t, can1.ReleasedHes.Cmp(slash1.ReleasedHes) == 0)
	assert.True(t, can1.Shares.Cmp(common.Big0) > 0)

	canAddr2, _ := xutil.NodeId2Addr(slash2.NodeId)
	can2, err := StakingInstance().GetCandidateInfo(blockHash2, canAddr2.Big())
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, can2.Released.Cmp(new(big.Int).Sub(slash2.Released, slashItem2.Amount)) == 0)
	assert.True(t, can2.ReleasedHes.Cmp(common.Big0) == 0)
	assert.True(t, can2.Shares.Cmp(common.Big0) == 0)

	canAddr3, _ := xutil.NodeId2Addr(slash3.NodeId)
	can3, err := StakingInstance().GetCandidateInfo(blockHash2, canAddr3.Big())
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, can3.Released.Cmp(new(big.Int).Sub(slash3.Released, slashAmount3)) == 0)
	assert.True(t, can3.ReleasedHes.Cmp(slash3.ReleasedHes) == 0)
	assert.True(t, can3.Shares.Cmp(common.Big0) > 0)
	assert.True(t, can3.IsInvalidLowRatio())

	canAddr4, _ := xutil.NodeId2Addr(slash4.NodeId)
	can4, err := StakingInstance().GetCandidateInfo(blockHash2, canAddr4.Big())
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, can4.Released.Cmp(new(big.Int).Sub(slash4.Released, new(big.Int).Add(slashAmount4, slashAmount4))) == 0)
	assert.True(t, can4.ReleasedHes.Cmp(common.Big0) == 0)
	assert.True(t, can4.Shares.Cmp(common.Big0) == 0)
	assert.True(t, can4.IsInvalidLowRatio() && can4.IsInvalidDuplicateSign())

	canAddr5, _ := xutil.NodeId2Addr(slash5.NodeId)
	can5, err := StakingInstance().GetCandidateInfo(blockHash2, canAddr5.Big())
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, can5.Released.Cmp(new(big.Int).Sub(slash5.Released, new(big.Int).Add(slashAmount5, slashAmount5))) == 0)
	assert.True(t, can5.ReleasedHes.Cmp(common.Big0) == 0)
	assert.True(t, can5.Shares.Cmp(common.Big0) == 0)
	assert.True(t, can5.IsInvalidLowRatio() && can5.IsInvalidDuplicateSign())
}

func TestStakingPlugin_DeclarePromoteNotify(t *testing.T) {

	state, genesis, err := newChainState()
	if nil != err {
		t.Error("Failed to build the state", err)
		return
	}
	newPlugins()

	build_gov_data(state)

	sndb := snapshotdb.Instance()
	defer func() {
		sndb.Clear()
	}()

	handler.NewVrfHandler(genesis.Hash().Bytes())

	if err := sndb.NewBlock(blockNumber, genesis.Hash(), blockHash); nil != err {
		t.Error("newBlock err", err)
		return
	}

	queue := make(staking.CandidateQueue, 0)
	for i := 0; i < 1000; i++ {

		var index int
		if i >= len(balanceStr) {
			index = i % (len(balanceStr) - 1)
		}

		balance, _ := new(big.Int).SetString(balanceStr[index], 10)

		mrand.Seed(time.Now().UnixNano())

		weight := mrand.Intn(1000000000)

		ii := mrand.Intn(len(chaList))

		balance = new(big.Int).Add(balance, big.NewInt(int64(weight)))

		privateKey, err := crypto.GenerateKey()
		if nil != err {
			t.Errorf("Failed to generate random NodeId private key: %v", err)
			return
		}

		nodeId := discover.PubkeyID(&privateKey.PublicKey)

		privateKey, err = crypto.GenerateKey()
		if nil != err {
			t.Errorf("Failed to generate random Address private key: %v", err)
			return
		}

		addr := crypto.PubkeyToAddress(privateKey.PublicKey)

		var blsKey bls.SecretKey
		blsKey.SetByCSPRNG()
		var blsKeyHex bls.PublicKeyHex
		b, _ := blsKey.GetPublicKey().MarshalText()
		if err := blsKeyHex.UnmarshalText(b); nil != err {
			log.Error("Failed to blsKeyHex.UnmarshalText", "err", err)
			return
		}

		canTmp := &staking.Candidate{
			CandidateBase: &staking.CandidateBase{
				NodeId:          nodeId,
				BlsPubKey:       blsKeyHex,
				StakingAddress:  sender,
				BenefitAddress:  addr,
				StakingBlockNum: uint64(i),
				StakingTxIndex:  uint32(index),
				ProgramVersion:  xutil.CalcVersion(initProgramVersion),

				Description: staking.Description{
					NodeName:   nodeNameArr[index] + "_" + fmt.Sprint(i),
					ExternalId: nodeNameArr[index] + chaList[(len(chaList)-1)%(index+ii+1)] + "balabalala" + chaList[index],
					Website:    "www." + nodeNameArr[index] + "_" + fmt.Sprint(i) + ".org",
					Details:    "This is " + nodeNameArr[index] + "_" + fmt.Sprint(i) + " Super Node",
				},
			},
			CandidateMutable: &staking.CandidateMutable{
				Shares: balance,

				// Prevent null pointer initialization
				Released:           common.Big0,
				ReleasedHes:        common.Big0,
				RestrictingPlan:    common.Big0,
				RestrictingPlanHes: common.Big0,
			},
		}

		canAddr, _ := xutil.NodeId2Addr(canTmp.NodeId)
		err = StakingInstance().CreateCandidate(state, blockHash, blockNumber, canAddr.Big(), canTmp)

		if nil != err {
			t.Errorf("Failed to Create Staking, num: %d, err: %v", i, err)
			return
		}

		if i < 20 {
			queue = append(queue, canTmp)
		}
	}

	// Commit Block 1
	if err := sndb.Commit(blockHash); nil != err {
		t.Error("Commit 1 err", err)
		return
	}

	if err := sndb.NewBlock(blockNumber2, blockHash, blockHash2); nil != err {
		t.Error("newBlock 2 err", err)
		return
	}

	/**
	Start DeclarePromoteNotify
	*/
	for i, can := range queue {
		err = StakingInstance().DeclarePromoteNotify(blockHash2, blockNumber2.Uint64(), can.NodeId, promoteVersion)

		assert.Nil(t, err, fmt.Sprintf("Failed to DeclarePromoteNotify, index: %d, err: %v", i, err))
	}

}

func TestStakingPlugin_ProposalPassedNotify(t *testing.T) {

	state, genesis, err := newChainState()
	if nil != err {
		t.Error("Failed to build the state", err)
		return
	}

	newPlugins()

	build_gov_data(state)

	sndb := snapshotdb.Instance()
	defer func() {
		sndb.Clear()
	}()

	handler.NewVrfHandler(genesis.Hash().Bytes())

	if err := sndb.NewBlock(blockNumber, genesis.Hash(), blockHash); nil != err {
		t.Error("newBlock err", err)
		return
	}

	validatorQueue := make(staking.ValidatorQueue, 0)

	nodeIdArr := make([]discover.NodeID, 0)
	for i := 0; i < 1000; i++ {

		var index int
		if i >= len(balanceStr) {
			index = i % (len(balanceStr) - 1)
		}

		balance, _ := new(big.Int).SetString(balanceStr[index], 10)

		mrand.Seed(time.Now().UnixNano())

		weight := mrand.Intn(1000000000)

		ii := mrand.Intn(len(chaList))

		balance = new(big.Int).Add(balance, big.NewInt(int64(weight)))

		privateKey, err := crypto.GenerateKey()
		if nil != err {
			t.Errorf("Failed to generate random NodeId private key: %v", err)
			return
		}

		nodeId := discover.PubkeyID(&privateKey.PublicKey)

		privateKey, err = crypto.GenerateKey()
		if nil != err {
			t.Errorf("Failed to generate random Address private key: %v", err)
			return
		}

		addr := crypto.PubkeyToAddress(privateKey.PublicKey)

		var blsKey bls.SecretKey
		blsKey.SetByCSPRNG()
		var blsKeyHex bls.PublicKeyHex
		b, _ := blsKey.GetPublicKey().MarshalText()
		if err := blsKeyHex.UnmarshalText(b); nil != err {
			log.Error("Failed to blsKeyHex.UnmarshalText", "err", err)
			return
		}

		canTmp := &staking.Candidate{
			CandidateBase: &staking.CandidateBase{
				NodeId:          nodeId,
				BlsPubKey:       blsKeyHex,
				StakingAddress:  sender,
				BenefitAddress:  addr,
				StakingBlockNum: uint64(i),
				StakingTxIndex:  uint32(index),
				ProgramVersion:  xutil.CalcVersion(initProgramVersion),

				Description: staking.Description{
					NodeName:   nodeNameArr[index] + "_" + fmt.Sprint(i),
					ExternalId: nodeNameArr[index] + chaList[(len(chaList)-1)%(index+ii+1)] + "balabalala" + chaList[index],
					Website:    "www." + nodeNameArr[index] + "_" + fmt.Sprint(i) + ".org",
					Details:    "This is " + nodeNameArr[index] + "_" + fmt.Sprint(i) + " Super Node",
				},
			},
			CandidateMutable: &staking.CandidateMutable{
				Shares: balance,

				// Prevent null pointer initialization
				Released:           common.Big0,
				ReleasedHes:        common.Big0,
				RestrictingPlan:    common.Big0,
				RestrictingPlanHes: common.Big0,
			},
		}

		canAddr, _ := xutil.NodeId2Addr(canTmp.NodeId)
		if i == 0 {
			canTmp.AppendStatus(staking.Invalided)
		}
		err = StakingInstance().CreateCandidate(state, blockHash, blockNumber, canAddr.Big(), canTmp)

		if !assert.Nil(t, err, fmt.Sprintf("Failed to Create Staking, num: %d, err: %v", i, err)) {
			return
		}

		if i < 20 {
			nodeIdArr = append(nodeIdArr, canTmp.NodeId)
		}

		v := &staking.Validator{
			NodeAddress:     canAddr,
			NodeId:          canTmp.NodeId,
			BlsPubKey:       canTmp.BlsPubKey,
			ProgramVersion:  canTmp.ProgramVersion,
			Shares:          canTmp.Shares,
			StakingBlockNum: canTmp.StakingBlockNum,
			StakingTxIndex:  canTmp.StakingTxIndex,
			ValidatorTerm:   0,
		}

		validatorQueue = append(validatorQueue, v)
	}

	epoch_Arr := &staking.ValidatorArray{
		Start: 1,
		End:   xutil.CalcBlocksEachEpoch(),
		Arr:   validatorQueue,
	}

	curr_Arr := &staking.ValidatorArray{
		Start: 1,
		End:   xutil.ConsensusSize(),
		Arr:   validatorQueue,
	}

	t.Log("Store Curr Epoch VerifierList", "len", len(epoch_Arr.Arr))
	if err := setVerifierList(blockHash, epoch_Arr); nil != err {
		log.Error("Failed to setVerifierList", err)
		return
	}

	t.Log("Store CuRR Round Validator", "len", len(epoch_Arr.Arr))
	if err := setRoundValList(blockHash, curr_Arr); nil != err {
		log.Error("Failed to setVerifierList", err)
		return
	}

	// Commit Block 1
	if err := sndb.Commit(blockHash); nil != err {
		t.Error("Commit 1 err", err)
		return
	}

	if err := sndb.NewBlock(blockNumber2, blockHash, blockHash2); nil != err {
		t.Error("newBlock 2 err", err)
		return
	}

	/**
	Start ProposalPassedNotify
	*/
	err = StakingInstance().ProposalPassedNotify(blockHash2, blockNumber2.Uint64(), nodeIdArr, promoteVersion)

	assert.Nil(t, err, fmt.Sprintf("Failed to ProposalPassedNotify, err: %v", err))
	for _, nodeId := range nodeIdArr {
		addr, _ := xutil.NodeId2Addr(nodeId)
		can, err := StakingInstance().GetCanBase(blockHash2, addr.Big())
		assert.Nil(t, err)
		assert.True(t, can.ProgramVersion == promoteVersion)
	}
}

func TestStakingPlugin_GetCandidateONEpoch(t *testing.T) {

	state, genesis, err := newChainState()
	if nil != err {
		t.Error("Failed to build the state", err)
		return
	}
	newPlugins()

	build_gov_data(state)

	sndb := snapshotdb.Instance()
	defer func() {
		sndb.Clear()
	}()

	header, err := buildPrepareData(genesis, t)

	/**
	Start GetCandidateONEpoch
	*/
	canNotIrrQueue, err := StakingInstance().GetCandidateONEpoch(header.Hash(), header.Number.Uint64(), QueryStartNotIrr)

	assert.Nil(t, err, fmt.Sprintf("Failed to GetCandidateONEpoch by QueryStartNotIrr, err: %v", err))
	assert.True(t, 0 != len(canNotIrrQueue))
	t.Log("GetCandidateONEpoch by QueryStartNotIrr:", canNotIrrQueue)

	canQueue, err := StakingInstance().GetCandidateONEpoch(header.Hash(), header.Number.Uint64(), QueryStartIrr)

	assert.Nil(t, err, fmt.Sprintf("Failed to GetCandidateONEpoch by QueryStartIrr, err: %v", err))
	assert.True(t, 0 != len(canQueue))
	t.Log("GetCandidateONEpoch by QueryStartIrr:", canQueue)
}

func TestStakingPlugin_GetCandidateONRound(t *testing.T) {

	state, genesis, err := newChainState()
	if nil != err {
		t.Error("Failed to build the state", err)
		return
	}
	newPlugins()

	build_gov_data(state)

	sndb := snapshotdb.Instance()
	defer func() {
		sndb.Clear()
	}()

	header, err := buildPrepareData(genesis, t)
	if nil != err {
		return
	}

	/**
	Start GetCandidateONRound
	*/
	canNotIrrQueue, err := StakingInstance().GetCandidateONRound(header.Hash(), header.Number.Uint64(), CurrentRound, QueryStartNotIrr)

	assert.Nil(t, err, fmt.Sprintf("Failed to GetCandidateONRound by QueryStartNotIrr, err: %v", err))
	assert.True(t, 0 != len(canNotIrrQueue))
	t.Log("GetCandidateONRound by QueryStartNotIrr:", canNotIrrQueue)

	canQueue, err := StakingInstance().GetCandidateONRound(header.Hash(), header.Number.Uint64(), CurrentRound, QueryStartIrr)

	assert.Nil(t, err, fmt.Sprintf("Failed to GetCandidateONRound by QueryStartIrr, err: %v", err))

	assert.True(t, 0 != len(canQueue))
	t.Log("GetCandidateONRound by QueryStartIrr:", canQueue)

}

func TestStakingPlugin_GetValidatorList(t *testing.T) {

	state, genesis, err := newChainState()
	if nil != err {
		t.Error("Failed to build the state", err)
		return
	}
	newPlugins()

	build_gov_data(state)

	sndb := snapshotdb.Instance()
	defer func() {
		sndb.Clear()
	}()

	header, err := buildPrepareData(genesis, t)
	if nil != err {
		return
	}

	/**
	Start  GetValidatorList
	*/
	validatorNotIrrExQueue, err := StakingInstance().GetValidatorList(header.Hash(), header.Number.Uint64(), CurrentRound, QueryStartNotIrr)

	assert.Nil(t, err, fmt.Sprintf("Failed to GetValidatorList by QueryStartNotIrr, err: %v", err))
	assert.True(t, 0 != len(validatorNotIrrExQueue))
	t.Log("GetValidatorList by QueryStartNotIrr:", validatorNotIrrExQueue)

	validatorExQueue, err := StakingInstance().GetValidatorList(header.Hash(), header.Number.Uint64(), CurrentRound, QueryStartIrr)
	if nil != err {
		t.Errorf("Failed to GetValidatorList by QueryStartIrr, err: %v", err)
		return
	}

	assert.Nil(t, err, fmt.Sprintf("Failed to GetValidatorList by QueryStartIrr, err: %v", err))
	assert.True(t, 0 != len(validatorExQueue))
	t.Log("GetValidatorList by QueryStartIrr:", validatorExQueue)

}

func TestStakingPlugin_GetVerifierList(t *testing.T) {

	state, genesis, err := newChainState()
	if nil != err {
		t.Error("Failed to build the state", err)
		return
	}
	newPlugins()

	build_gov_data(state)

	sndb := snapshotdb.Instance()
	defer func() {
		sndb.Clear()
	}()

	header, err := buildPrepareData(genesis, t)
	if nil != err {
		return
	}

	/**
	Start GetVerifierList
	*/
	validatorNotIrrExQueue, err := StakingInstance().GetVerifierList(header.Hash(), header.Number.Uint64(), QueryStartNotIrr)

	assert.Nil(t, err, fmt.Sprintf("Failed to GetVerifierList by QueryStartNotIrr, err: %v", err))
	assert.True(t, 0 != len(validatorNotIrrExQueue))
	t.Log("GetVerifierList by QueryStartNotIrr:", validatorNotIrrExQueue)

	validatorExQueue, err := StakingInstance().GetVerifierList(header.Hash(), header.Number.Uint64(), QueryStartIrr)

	assert.Nil(t, err, fmt.Sprintf("Failed to GetVerifierList by QueryStartIrr, err: %v", err))
	assert.True(t, 0 != len(validatorExQueue))
	t.Log("GetVerifierList by QueryStartIrr:", validatorExQueue)

}

func TestStakingPlugin_ListCurrentValidatorID(t *testing.T) {

	state, genesis, err := newChainState()
	if nil != err {
		t.Error("Failed to build the state", err)
		return
	}
	newPlugins()

	build_gov_data(state)

	sndb := snapshotdb.Instance()
	defer func() {
		sndb.Clear()
	}()

	header, err := buildPrepareData(genesis, t)
	if nil != err {
		return
	}

	/**
	Start  ListCurrentValidatorID
	*/
	validatorIdQueue, err := StakingInstance().ListCurrentValidatorID(header.Hash(), header.Number.Uint64())

	assert.Nil(t, err, fmt.Sprintf("Failed to ListCurrentValidatorID, err: %v", err))
	assert.True(t, 0 != len(validatorIdQueue))
	t.Log("ListCurrentValidatorID:", validatorIdQueue)

}

func TestStakingPlugin_ListVerifierNodeID(t *testing.T) {

	state, genesis, err := newChainState()
	if nil != err {
		t.Error("Failed to build the state", err)
		return
	}
	newPlugins()

	build_gov_data(state)

	sndb := snapshotdb.Instance()
	defer func() {
		sndb.Clear()
	}()

	header, err := buildPrepareData(genesis, t)
	if nil != err {
		return
	}

	/**
	Start ListVerifierNodeId
	*/

	/**
	Start  ListVerifierNodeID
	*/
	validatorIdQueue, err := StakingInstance().ListVerifierNodeID(header.Hash(), header.Number.Uint64())

	assert.Nil(t, err, fmt.Sprintf("Failed to ListVerifierNodeID, err: %v", err))
	assert.True(t, 0 != len(validatorIdQueue))
	t.Log("ListVerifierNodeID:", validatorIdQueue)
}

func TestStakingPlugin_IsCandidate(t *testing.T) {

	state, genesis, err := newChainState()
	if nil != err {
		t.Error("Failed to build the state", err)
		return
	}
	newPlugins()

	build_gov_data(state)

	sndb := snapshotdb.Instance()
	defer func() {
		sndb.Clear()
	}()

	handler.NewVrfHandler(genesis.Hash().Bytes())

	if err := sndb.NewBlock(blockNumber, genesis.Hash(), blockHash); nil != err {
		t.Error("newBlock err", err)
		return
	}

	nodeIdArr := make([]discover.NodeID, 0)

	for i := 0; i < 1000; i++ {

		var index int
		if i >= len(balanceStr) {
			index = i % (len(balanceStr) - 1)
		}

		balance, _ := new(big.Int).SetString(balanceStr[index], 10)

		mrand.Seed(time.Now().UnixNano())

		weight := mrand.Intn(1000000000)

		ii := mrand.Intn(len(chaList))

		balance = new(big.Int).Add(balance, big.NewInt(int64(weight)))

		privateKey, err := crypto.GenerateKey()
		if nil != err {
			t.Errorf("Failed to generate random NodeId private key: %v", err)
			return
		}

		nodeId := discover.PubkeyID(&privateKey.PublicKey)

		privateKey, err = crypto.GenerateKey()
		if nil != err {
			t.Errorf("Failed to generate random Address private key: %v", err)
			return
		}

		addr := crypto.PubkeyToAddress(privateKey.PublicKey)

		var blsKey bls.SecretKey
		blsKey.SetByCSPRNG()

		var blsKeyHex bls.PublicKeyHex
		b, _ := blsKey.GetPublicKey().MarshalText()
		if err := blsKeyHex.UnmarshalText(b); nil != err {
			log.Error("Failed to blsKeyHex.UnmarshalText", "err", err)
			return
		}

		canTmp := &staking.Candidate{
			CandidateBase: &staking.CandidateBase{
				NodeId:          nodeId,
				BlsPubKey:       blsKeyHex,
				StakingAddress:  sender,
				BenefitAddress:  addr,
				StakingBlockNum: uint64(i),
				StakingTxIndex:  uint32(index),
				ProgramVersion:  xutil.CalcVersion(initProgramVersion),

				Description: staking.Description{
					NodeName:   nodeNameArr[index] + "_" + fmt.Sprint(i),
					ExternalId: nodeNameArr[index] + chaList[(len(chaList)-1)%(index+ii+1)] + "balabalala" + chaList[index],
					Website:    "www." + nodeNameArr[index] + "_" + fmt.Sprint(i) + ".org",
					Details:    "This is " + nodeNameArr[index] + "_" + fmt.Sprint(i) + " Super Node",
				},
			},
			CandidateMutable: &staking.CandidateMutable{
				Shares: balance,

				// Prevent null pointer initialization
				Released:           common.Big0,
				ReleasedHes:        common.Big0,
				RestrictingPlan:    common.Big0,
				RestrictingPlanHes: common.Big0,
			},
		}

		canAddr, _ := xutil.NodeId2Addr(canTmp.NodeId)

		err = StakingInstance().CreateCandidate(state, blockHash, blockNumber, canAddr.Big(), canTmp)

		if nil != err {
			t.Errorf("Failed to Create Staking, num: %d, err: %v", i, err)
			return
		}

		if i < 20 {
			nodeIdArr = append(nodeIdArr, canTmp.NodeId)
		}
	}

	if err := sndb.Commit(blockHash); nil != err {
		t.Error("Commit 1 err", err)
		return
	}
	if err := sndb.NewBlock(blockNumber2, blockHash, blockHash2); nil != err {
		t.Error("newBlock 2 err", err)
		return
	}

	/**
	Start  IsCandidate
	*/
	for i, nodeId := range nodeIdArr {

		yes, err := StakingInstance().IsCandidate(blockHash2, new(big.Int).SetBytes(nodeID.Bytes()), QueryStartNotIrr)
		if nil != err {
			t.Errorf("Failed to IsCandidate, index: %d, err: %v", i, err)
			return
		}
		if !yes {
			t.Logf("The NodeId is not a Id of Candidate, nodeId: %s", nodeId.String())
		}
	}
}

func TestStakingPlugin_IsCurrValidator(t *testing.T) {

	state, genesis, err := newChainState()
	if nil != err {
		t.Error("Failed to build the state", err)
		return
	}
	newPlugins()

	build_gov_data(state)

	sndb := snapshotdb.Instance()
	defer func() {
		sndb.Clear()
	}()

	header, err := buildPrepareData(genesis, t)
	if nil != err {
		return
	}
	/**
	Start  IsCurrValidator
	*/
	for i, nodeId := range nodeIdArr {
		yes, err := StakingInstance().IsCurrValidator(header.Hash(), header.Number.Uint64(), nodeId, QueryStartNotIrr)
		if nil != err {
			t.Errorf("Failed to IsCurrValidator, index: %d, err: %v", i, err)
			return
		}
		if !yes {
			t.Logf("The NodeId is not a Id of current round validator, nodeId: %s", nodeId.String())
		}
	}

}

func TestStakingPlugin_IsCurrVerifier(t *testing.T) {

	state, genesis, err := newChainState()
	if nil != err {
		t.Error("Failed to build the state", err)
		return
	}
	newPlugins()

	build_gov_data(state)

	sndb := snapshotdb.Instance()
	defer func() {
		sndb.Clear()
	}()

	header, err := buildPrepareData(genesis, t)
	if nil != err {
		return
	}

	/**
	Start  IsCurrVerifier
	*/
	for i, nodeId := range nodeIdArr {
		yes, err := StakingInstance().IsCurrVerifier(header.Hash(), header.Number.Uint64(), nodeId, QueryStartNotIrr)
		if nil != err {
			t.Errorf("Failed to IsCurrVerifier, index: %d, err: %v", i, err)
			return
		}
		if !yes {
			t.Logf("The NodeId is not a Id of Epoch validator, nodeId: %s", nodeId.String())
		}
	}
}

// for consensus
func TestStakingPlugin_GetLastNumber(t *testing.T) {

	state, genesis, err := newChainState()
	if nil != err {
		t.Error("Failed to build the state", err)
		return
	}
	newPlugins()

	build_gov_data(state)

	sndb := snapshotdb.Instance()
	defer func() {
		sndb.Clear()
	}()

	header, err := buildPrepareData(genesis, t)
	if nil != err {
		return
	}
	/**
	Start  GetLastNumber
	*/
	endNumber := StakingInstance().GetLastNumber(header.Number.Uint64())

	round := xutil.CalculateRound(header.Number.Uint64())
	blockNum := round * xutil.ConsensusSize()
	assert.True(t, endNumber == blockNum, fmt.Sprintf("currentNumber: %d, currentRound: %d endNumber: %d, targetNumber: %d", header.Number, round, endNumber, blockNum))

}

func TestStakingPlugin_GetValidator(t *testing.T) {

	state, genesis, err := newChainState()
	if nil != err {
		t.Error("Failed to build the state", err)
		return
	}
	newPlugins()

	build_gov_data(state)

	sndb := snapshotdb.Instance()
	defer func() {
		sndb.Clear()
	}()

	header, err := buildPrepareData(genesis, t)
	if nil != err {
		return
	}

	/**
	Start  GetValidator
	*/
	valArr, err := StakingInstance().GetValidator(header.Number.Uint64())

	assert.Nil(t, err, fmt.Sprintf("Failed to GetValidator, err: %v", err))
	assert.True(t, nil != valArr)
	t.Log("GetValidator the validators is:", valArr)

}

func TestStakingPlugin_IsCandidateNode(t *testing.T) {

	state, genesis, err := newChainState()
	if nil != err {
		t.Error("Failed to build the state", err)
		return
	}
	newPlugins()

	build_gov_data(state)

	sndb := snapshotdb.Instance()
	defer func() {
		sndb.Clear()
	}()

	if _, err := buildPrepareData(genesis, t); nil != err {
		return
	}
	/**
	Start  IsCandidateNode
	*/
	yes := StakingInstance().IsCandidateNode(nodeIdArr[0])

	t.Log("IsCandidateNode the flag is:", yes)

}

func TestStakingPlugin_ProbabilityElection(t *testing.T) {

	newChainState()

	curve := crypto.S256()
	vqList := make(staking.ValidatorQueue, 0)
	preNonces := make([][]byte, 0)
	currentNonce := crypto.Keccak256([]byte(string("nonce")))
	for i := 0; i < int(xcom.MaxValidators()); i++ {

		mrand.Seed(time.Now().UnixNano())
		v1 := new(big.Int).SetInt64(time.Now().UnixNano())
		v1.Mul(v1, new(big.Int).SetInt64(1e18))
		v1.Add(v1, new(big.Int).SetInt64(int64(mrand.Intn(1000))))

		var blsKey bls.SecretKey
		blsKey.SetByCSPRNG()
		privKey, _ := ecdsa.GenerateKey(curve, rand.Reader)
		nodeId := discover.PubkeyID(&privKey.PublicKey)
		addr := crypto.PubkeyToNodeAddress(privKey.PublicKey)

		var blsKeyHex bls.PublicKeyHex
		b, _ := blsKey.GetPublicKey().MarshalText()
		if err := blsKeyHex.UnmarshalText(b); nil != err {
			log.Error("Failed to blsKeyHex.UnmarshalText", "err", err)
			return
		}

		v := &staking.Validator{
			NodeAddress: addr,
			NodeId:      nodeId,
			BlsPubKey:   blsKeyHex,

			ProgramVersion:  uint32(mrand.Intn(5) + 1),
			Shares:          v1.SetInt64(10),
			StakingBlockNum: uint64(mrand.Intn(230)),
			StakingTxIndex:  uint32(mrand.Intn(1000)),
			ValidatorTerm:   1,
		}
		vqList = append(vqList, v)
		preNonces = append(preNonces, crypto.Keccak256(common.Int64ToBytes(time.Now().UnixNano() + int64(i)))[:])
		time.Sleep(time.Microsecond * 10)
	}

	result, err := probabilityElection(vqList, int(xcom.ShiftValidatorNum()), currentNonce, preNonces, 1, params.GenesisVersion)
	assert.Nil(t, err, fmt.Sprintf("Failed to probabilityElection, err: %v", err))
	assert.True(t, nil != result, "the result is nil")

}

func TestStakingPlugin_ProbabilityElectionDifferentWeights(t *testing.T) {

	newChainState()

	curve := crypto.S256()

	currentNonce := crypto.Keccak256([]byte("nonce"))

	buildCandidate := func(stakeThreshold int) (staking.ValidatorQueue, [][]byte) {
		preNonces := make([][]byte, 0)
		vqList := make(staking.ValidatorQueue, 0)
		candidateNumber := 101
		for i := 0; i < candidateNumber; i++ {
			shares := new(big.Int).SetUint64(uint64(stakeThreshold))
			shares.Mul(shares, new(big.Int).SetInt64(1e18))

			mrand.Seed(time.Now().UnixNano())

			var blsKey bls.SecretKey
			blsKey.SetByCSPRNG()
			privKey, _ := ecdsa.GenerateKey(curve, rand.Reader)
			nodeId := discover.PubkeyID(&privKey.PublicKey)
			addr := crypto.PubkeyToNodeAddress(privKey.PublicKey)

			var blsKeyHex bls.PublicKeyHex
			b, _ := blsKey.GetPublicKey().MarshalText()
			if err := blsKeyHex.UnmarshalText(b); nil != err {
				log.Error("Failed to blsKeyHex.UnmarshalText", "err", err)
				return nil, nil
			}

			v := &staking.Validator{
				NodeAddress: addr,
				NodeId:      nodeId,
				BlsPubKey:   blsKeyHex,

				ProgramVersion:  uint32(mrand.Intn(5) + 1),
				Shares:          shares,
				StakingBlockNum: uint64(mrand.Intn(230)),
				StakingTxIndex:  uint32(mrand.Intn(1000)),
				ValidatorTerm:   1,
			}
			vqList = append(vqList, v)
			preNonces = append(preNonces, crypto.Keccak256(common.Int64ToBytes(time.Now().UnixNano() + int64(i)))[:])
			time.Sleep(time.Microsecond * 10)
		}
		return vqList, preNonces
	}

	stakeThreshold := 1000000
	for i := 0; i < 3; i++ {
		vqList, preNonceList := buildCandidate(stakeThreshold)
		stakeThreshold *= 10
		t.Run(fmt.Sprintf("Election_%d", i+1), func(t *testing.T) {
			result, err := probabilityElection(vqList, int(xcom.ShiftValidatorNum()), currentNonce, preNonceList, 1, params.GenesisVersion)
			assert.Nil(t, err, fmt.Sprintf("Failed to probabilityElection, err: %v", err))
			assert.True(t, nil != result, "the result is nil")
		})
	}

}

func TestStakingPlugin_RandomOrderValidatorQueue(t *testing.T) {
	newPlugins()
	handler.NewVrfHandler(make([]byte, 0))
	defer func() {
		slash.db.Clear()
	}()

	gov.InitGenesisGovernParam(common.ZeroHash, slash.db, 2048)

	privateKey, _ := crypto.GenerateKey()
	vqList := make(staking.ValidatorQueue, 0)
	dataList := make([][]byte, 0)
	data := common.Int64ToBytes(time.Now().UnixNano())
	if err := slash.db.NewBlock(new(big.Int).SetUint64(1), blockHash, common.ZeroHash); nil != err {
		t.Fatal(err)
	}
	for i := 0; i < int(xcom.MaxConsensusVals()); i++ {
		vrfData, err := vrf.Prove(privateKey, data)
		if nil != err {
			t.Fatal(err)
		}
		data = vrf.ProofToHash(vrfData)
		dataList = append(dataList, data)

		tempPrivateKey, _ := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
		nodeId := discover.PubkeyID(&tempPrivateKey.PublicKey)
		addr := crypto.PubkeyToNodeAddress(tempPrivateKey.PublicKey)
		v := &staking.Validator{
			NodeAddress: addr,
			NodeId:      nodeId,
		}
		vqList = append(vqList, v)
	}
	if enValue, err := rlp.EncodeToBytes(dataList); nil != err {
		t.Fatal(err)
	} else {
		if err := slash.db.Put(common.ZeroHash, handler.NonceStorageKey, enValue); nil != err {
			t.Fatal(err)
		}
	}
	resultQueue, err := randomOrderValidatorQueue(1, common.ZeroHash, vqList)
	if nil != err {
		t.Fatal(err)
	}
	assert.True(t, len(resultQueue) == len(vqList))
}

/**
Expand test cases
*/

func Test_IteratorCandidate(t *testing.T) {

	state, genesis, err := newChainState()
	if nil != err {
		t.Error("Failed to build the state", err)
		return
	}
	newPlugins()

	build_gov_data(state)

	sndb := snapshotdb.Instance()
	defer func() {
		sndb.Clear()
	}()

	if err := sndb.NewBlock(blockNumber, genesis.Hash(), blockHash); nil != err {
		t.Error("newBlock err", err)
		return
	}

	for i := 0; i < 1000; i++ {

		var index int
		if i >= len(balanceStr) {
			index = i % (len(balanceStr) - 1)
		}

		//t.Log("Create Staking num:", index)

		balance, _ := new(big.Int).SetString(balanceStr[index], 10)

		mrand.Seed(time.Now().UnixNano())

		weight := mrand.Intn(1000000000)

		ii := mrand.Intn(len(chaList))

		balance = new(big.Int).Add(balance, big.NewInt(int64(weight)))

		privateKey, err := crypto.GenerateKey()
		if nil != err {
			t.Errorf("Failed to generate random NodeId private key: %v", err)
			return
		}

		nodeId := discover.PubkeyID(&privateKey.PublicKey)

		privateKey, err = crypto.GenerateKey()
		if nil != err {
			t.Errorf("Failed to generate random Address private key: %v", err)
			return
		}

		addr := crypto.PubkeyToAddress(privateKey.PublicKey)

		var blsKey bls.SecretKey
		blsKey.SetByCSPRNG()
		var blsKeyHex bls.PublicKeyHex
		b, _ := blsKey.GetPublicKey().MarshalText()
		if err := blsKeyHex.UnmarshalText(b); nil != err {
			log.Error("Failed to blsKeyHex.UnmarshalText", "err", err)
			return
		}

		canTmp := &staking.Candidate{
			CandidateBase: &staking.CandidateBase{
				NodeId:          nodeId,
				BlsPubKey:       blsKeyHex,
				StakingAddress:  sender,
				BenefitAddress:  addr,
				StakingBlockNum: uint64(i),
				StakingTxIndex:  uint32(index),
				ProgramVersion:  xutil.CalcVersion(initProgramVersion),

				Description: staking.Description{
					NodeName:   nodeNameArr[index] + "_" + fmt.Sprint(i),
					ExternalId: nodeNameArr[index] + chaList[(len(chaList)-1)%(index+ii+1)] + "balabalala" + chaList[index],
					Website:    "www." + nodeNameArr[index] + "_" + fmt.Sprint(i) + ".org",
					Details:    "This is " + nodeNameArr[index] + "_" + fmt.Sprint(i) + " Super Node",
				},
			},
			CandidateMutable: &staking.CandidateMutable{
				Shares: balance,

				// Prevent null pointer initialization
				Released:           common.Big0,
				ReleasedHes:        common.Big0,
				RestrictingPlan:    common.Big0,
				RestrictingPlanHes: common.Big0,
			},
		}

		canAddr, _ := xutil.NodeId2Addr(canTmp.NodeId)

		err = StakingInstance().CreateCandidate(state, blockHash, blockNumber, canAddr.Big(), canTmp)

		if nil != err {
			t.Errorf("Failed to Create Staking, num: %d, err: %v", i, err)
			return
		}
	}

	// commit
	if err := sndb.Commit(blockHash); nil != err {
		t.Error("Commit 1 err", err)
		return
	}

	if err := sndb.NewBlock(blockNumber2, blockHash, blockHash2); nil != err {
		t.Error("newBlock 2 err", err)
		return
	}

	stakingDB := staking.NewStakingDB()

	iter := stakingDB.IteratorCandidatePowerByBlockHash(blockHash2, 0)
	if err := iter.Error(); nil != err {
		t.Error("Get iter err", err)
		return
	}
	defer iter.Release()

	queue := make(staking.CandidateQueue, 0)

	for iter.Valid(); iter.Next(); {
		addrSuffix := iter.Value()
		can, err := stakingDB.GetCandidateStoreWithSuffix(blockHash2, addrSuffix)
		if nil != err {
			t.Errorf("Failed to Iterator Candidate info, err: %v", err)
			return
		}

		val := fmt.Sprint(can.ProgramVersion) + "_" + can.Shares.String() + "_" + fmt.Sprint(can.StakingBlockNum) + "_" + fmt.Sprint(can.StakingTxIndex)
		t.Log("Val:", val)

		queue = append(queue, can)
	}

	arrJson, _ := json.Marshal(queue)
	t.Log("CandidateList:", string(arrJson))
	t.Log("Candidate queue length:", len(queue))
}

func TestStakingPlugin_CalcDelegateIncome(t *testing.T) {
	del := staking.NewDelegation()
	del.ReleasedHes = new(big.Int).Mul(new(big.Int).SetInt64(100), new(big.Int).SetInt64(params.HSK))
	del.DelegateEpoch = 1
	per := make([]*reward.DelegateRewardPer, 0)
	per = append(per, &reward.DelegateRewardPer{
		Epoch:    1,
		Delegate: new(big.Int).SetUint64(10),
		Reward:   new(big.Int).SetUint64(100),
	})
	per = append(per, &reward.DelegateRewardPer{
		Epoch:    2,
		Delegate: new(big.Int).SetUint64(10),
		Reward:   new(big.Int).SetUint64(200),
	})
	expectedCumulativeIncome := per[1].CalDelegateReward(del.ReleasedHes)
	calcDelegateIncome(3, del, per)
	assert.True(t, del.CumulativeIncome.Cmp(expectedCumulativeIncome) == 0)

	del = staking.NewDelegation()
	del.Released = new(big.Int).Mul(new(big.Int).SetInt64(100), new(big.Int).SetInt64(params.HSK))
	del.ReleasedHes = new(big.Int).Mul(new(big.Int).SetInt64(100), new(big.Int).SetInt64(params.HSK))
	del.DelegateEpoch = 2
	per = make([]*reward.DelegateRewardPer, 0)
	per = append(per, &reward.DelegateRewardPer{
		Epoch:    2,
		Delegate: new(big.Int).SetUint64(10),
		Reward:   new(big.Int).SetUint64(100),
	})
	per = append(per, &reward.DelegateRewardPer{
		Epoch:    3,
		Delegate: new(big.Int).SetUint64(10),
		Reward:   new(big.Int).SetUint64(100),
	})

	expectedCumulativeIncome = per[0].CalDelegateReward(del.Released)
	expectedCumulativeIncome = expectedCumulativeIncome.Add(expectedCumulativeIncome, per[1].CalDelegateReward(new(big.Int).Add(del.Released, del.ReleasedHes)))
	calcDelegateIncome(4, del, per)
	assert.True(t, del.CumulativeIncome.Cmp(expectedCumulativeIncome) == 0)
}

func TestStakingPlugin_RandSeedShuffle(t *testing.T) {
	dataList := make([]int, 0)
	for i := 0; i < 6; i++ {
		dataList = append(dataList, i)
	}
	dataListCp := make([]int, len(dataList))
	copy(dataListCp, dataList)

	dataListCp2 := make([]int, len(dataList))
	copy(dataListCp2, dataList)

	dataListCp3 := make([]int, len(dataList))
	copy(dataListCp3, dataList)

	rd := mrand.New(mrand.NewSource(110))
	rd.Shuffle(len(dataList), func(i, j int) {
		dataList[i], dataList[j] = dataList[j], dataList[i]
	})

	mrand.Seed(110)
	mrand.Shuffle(len(dataListCp), func(i, j int) {
		dataListCp[i], dataListCp[j] = dataListCp[j], dataListCp[i]
	})
	for i := 0; i < len(dataList); i++ {
		assert.True(t, dataList[i] == dataListCp[i])
	}

	// Reset Seed
	rd.Seed(110)
	mrand.Seed(119)
	mrand.Shuffle(len(dataListCp2), func(i, j int) {
		dataListCp2[i], dataListCp2[j] = dataListCp2[j], dataListCp2[i]
	})
	for i := 0; i < len(dataList); i++ {
		assert.True(t, dataList[i] != dataListCp2[i])
	}

	rd.Shuffle(len(dataListCp3), func(i, j int) {
		dataListCp3[i], dataListCp3[j] = dataListCp3[j], dataListCp3[i]
	})
	for i := 0; i < len(dataList); i++ {
		assert.True(t, dataList[i] == dataListCp3[i])
	}
}

func TestStakingPlugin_HistoryValidatorList(t *testing.T) {
	state := mock.NewMockStateDB()
	newPlugins()
	build_gov_data(state)
	diskDB := memorydb.New()
	StakingInstance().SetChainDB(diskDB, diskDB)
	StakingInstance().EnableValidatorsHistory()
	// Set to the latest version.
	gov.AddActiveVersion(params.CodeVersion(), 0, state)
	sndb := snapshotdb.Instance()
	defer func() {
		sndb.Clear()
	}()

	if err := sndb.NewBlock(blockNumber, common.BytesToHash(crypto.Keccak256([]byte("genesis"))), blockHash); nil != err {
		t.Error("newBlock err", err)
		return
	}
	queue := make(staking.ValidatorQueue, 0)
	for i := 0; i < int(xcom.MaxValidators()); i++ {
		privateKey, err := crypto.GenerateKey()
		if nil != err {
			t.Fatalf("Failed to generate random NodeId private key: %v", err)
		}
		nodeId := discover.PubkeyID(&privateKey.PublicKey)
		nodeAddr := crypto.PubkeyToNodeAddress(privateKey.PublicKey)
		var blsKey bls.SecretKey
		blsKey.SetByCSPRNG()
		var blsKeyHex bls.PublicKeyHex
		b, _ := blsKey.GetPublicKey().MarshalText()
		if err := blsKeyHex.UnmarshalText(b); nil != err {
			log.Error("Failed to blsKeyHex.UnmarshalText", "err", err)
			return
		}
		val := &staking.Validator{
			NodeAddress:    nodeAddr,
			NodeId:         nodeId,
			BlsPubKey:      blsKeyHex,
			ProgramVersion: xutil.CalcVersion(initProgramVersion),
		}
		queue = append(queue, val)
	}

	start := uint64(1)
	end := xutil.EpochSize() * xutil.ConsensusSize()

	newVerifierArr := &staking.ValidatorArray{
		Start: start,
		End:   end,
	}
	newVerifierArr.Arr = queue
	err := setVerifierList(blockHash, newVerifierArr)
	if nil != err {
		t.Errorf("Failed to Set Genesis VerfierList, err: %v", err)
		return
	}

	newValidatorArr := &staking.ValidatorArray{
		Start: start,
		End:   xutil.ConsensusSize(),
	}
	newValidatorArr.Arr = queue[:int(xcom.MaxConsensusVals())]
	err = setRoundValList(blockHash, newValidatorArr)
	if nil != err {
		t.Errorf("Failed to Set Genesis current round validatorList, err: %v", err)
		return
	}
	newValidatorArr2 := &staking.ValidatorArray{
		Start: newValidatorArr.End + 1,
		End:   newValidatorArr.End + xutil.ConsensusSize(),
	}
	newValidatorArr2.Arr = queue[:int(xcom.MaxConsensusVals())]
	err = setRoundValList(blockHash, newValidatorArr2)
	if nil != err {
		t.Errorf("Failed to Set Genesis current round validatorList, err: %v", err)
		return
	}
	if err := sndb.Commit(blockHash); nil != err {
		t.Error("Commit 1 err", err)
		return
	}

	// Write data to DB
	header := &types.Header{
		ParentHash: blockHash,
		Number:     big.NewInt(int64(xutil.ConsensusSize())),
		Nonce:      types.EncodeNonce(crypto.Keccak256([]byte(string("history")))),
		Extra:      make([]byte, 97),
	}
	if err := sndb.NewBlock(blockNumber2, blockHash, blockHash2); nil != err {
		t.Error("newBlock 2 err", err)
		return
	}
	if err := StakingInstance().BeginBlock(blockHash2, header, state); err != nil {
		t.Fatal(err)
	}
	nilBytes := make([]byte, 32)
	if bytes.Equal(header.Extra[:32], nilBytes) {
		t.Fatal()
	}
	list, err := StakingInstance().GetValidatorHistoryList(newValidatorArr2.Start)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(list); i++ {
		if list[i].NodeId != newValidatorArr2.Arr[i].NodeId {
			t.Fatal("Data mismatch")
		}
		if list[i].BlsPubKey != newValidatorArr2.Arr[i].BlsPubKey {
			t.Fatal("Data mismatch")
		}
	}
	// Second round of writing data.
	newValidatorArr3 := &staking.ValidatorArray{
		Start: newValidatorArr2.End + 1,
		End:   newValidatorArr2.End + xutil.ConsensusSize(),
	}
	newValidatorArr3.Arr = queue[1:int(xcom.MaxConsensusVals()+1)]
	err = setRoundValList(blockHash2, newValidatorArr3)
	if nil != err {
		t.Errorf("Failed to Set Genesis current round validatorList, err: %v", err)
		return
	}
	if err := sndb.Commit(blockHash2); nil != err {
		t.Error("Commit 1 err", err)
		return
	}
	header = &types.Header{
		ParentHash: blockHash2,
		Number:     big.NewInt(int64(newValidatorArr2.End)),
		Nonce:      types.EncodeNonce(crypto.Keccak256([]byte(string("history")))),
		Extra:      make([]byte, 97),
	}
	if err := StakingInstance().BeginBlock(blockHash3, header, state); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(header.Extra[:32], nilBytes) {
		t.Fatal()
	}
	list2, err := StakingInstance().GetValidatorHistoryList(newValidatorArr3.Start)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(list2); i++ {
		if list2[i].NodeId != newValidatorArr3.Arr[i].NodeId {
			t.Fatal("Data mismatch")
		}
		if list2[i].BlsPubKey != newValidatorArr3.Arr[i].BlsPubKey {
			t.Fatal("Data mismatch")
		}
	}
	if list2[0].NodeId == list[0].NodeId {
		t.Fatal("Data duplication")
	}
	if list2[0].BlsPubKey == list[0].BlsPubKey {
		t.Fatal("Data duplication")
	}
}
