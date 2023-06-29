package api

import (
	"context"

	"github.com/PlatONnetwork/AppChain-Go/core/types"
	"github.com/PlatONnetwork/AppChain-Go/eth/filters"
)

type FilterAPI interface {
	GetLogs(ctx context.Context, crit filters.FilterCriteria) ([]*types.Log, error)
}
