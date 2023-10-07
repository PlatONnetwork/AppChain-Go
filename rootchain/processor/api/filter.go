package api

import (
	"context"

	"github.com/PlatONnetwork/PlatON-Go/core/types"
	"github.com/PlatONnetwork/PlatON-Go/eth/filters"
)

type FilterAPI interface {
	GetLogs(ctx context.Context, crit filters.FilterCriteria) ([]*types.Log, error)
}
