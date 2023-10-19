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
	"context"
	"github.com/PlatONnetwork/PlatON-Go/common"
	"github.com/PlatONnetwork/PlatON-Go/common/json"
	"github.com/PlatONnetwork/PlatON-Go/core/snapshotdb"
	"github.com/PlatONnetwork/PlatON-Go/core/state"
	"github.com/PlatONnetwork/PlatON-Go/core/types"
	"github.com/PlatONnetwork/PlatON-Go/rpc"
	"github.com/PlatONnetwork/PlatON-Go/x/staking"
	"github.com/PlatONnetwork/PlatON-Go/x/xutil"
)

type BackendAPI interface {
	StateAndHeaderByNumber(ctx context.Context, blockNr rpc.BlockNumber) (*state.StateDB, *types.Header, error)
}

// Provides an API interface to obtain data related to the economic model
type PublicPPOSAPI struct {
	snapshotDB snapshotdb.DB
	bkApi      BackendAPI
}

func NewPublicPPOSAPI(api BackendAPI) *PublicPPOSAPI {
	return &PublicPPOSAPI{snapshotDB: snapshotdb.Instance(), bkApi: api}
}

// Get node list of zero-out blocks
func (p *PublicPPOSAPI) GetWaitSlashingNodeList() string {
	list, err := slash.getWaitSlashingNodeList(0, common.ZeroHash)
	if nil != err || len(list) == 0 {
		return ""
	}
	enVal, err := json.Marshal(list)
	if err != nil {
		return ""
	}
	return string(enVal)
}

func (p *PublicPPOSAPI) GetValidatorByBlockNumber(ctx context.Context, blockNumber uint64) string {
	list, err := stk.GetValidatorHistoryList(blockNumber)
	if nil != err || len(list) == 0 {
		return ""
	}
	enVal, err := json.Marshal(list)
	return string(enVal)
}

// Get the list of consensus nodes for the current consensus cycle.
func (p *PublicPPOSAPI) GetConsensusNodeList(ctx context.Context) (staking.ValidatorExQueue, error) {
	_, header, err := p.bkApi.StateAndHeaderByNumber(ctx, rpc.LatestBlockNumber)
	if err != nil {
		return nil, err
	}
	blockHash := common.ZeroHash
	if !xutil.IsWorker(header.Extra) {
		blockHash = header.CacheHash()
	}
	return StakingInstance().GetValidatorList(blockHash, header.Number.Uint64(), CurrentRound, QueryStartNotIrr)
}

// Get the nodes in the current settlement cycle.
func (p *PublicPPOSAPI) GetValidatorList(ctx context.Context) (staking.ValidatorExQueue, error) {
	_, header, err := p.bkApi.StateAndHeaderByNumber(ctx, rpc.LatestBlockNumber)
	if err != nil {
		return nil, err
	}
	blockHash := common.ZeroHash
	if !xutil.IsWorker(header.Extra) {
		blockHash = header.CacheHash()
	}
	return StakingInstance().GetVerifierList(blockHash, header.Number.Uint64(), QueryStartNotIrr)
}

// Get all staking nodes.
func (p *PublicPPOSAPI) GetCandidateList(ctx context.Context) (staking.CandidateHexQueue, error) {
	_, header, err := p.bkApi.StateAndHeaderByNumber(ctx, rpc.LatestBlockNumber)
	if err != nil {
		return nil, err
	}
	blockHash := common.ZeroHash
	if !xutil.IsWorker(header.Extra) {
		blockHash = header.CacheHash()
	}
	return StakingInstance().GetCandidateList(blockHash, header.Number.Uint64())
}
