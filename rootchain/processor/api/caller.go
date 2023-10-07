package api

import (
	"context"

	"github.com/PlatONnetwork/PlatON-Go/common/hexutil"
	"github.com/PlatONnetwork/PlatON-Go/internal/ethapi"
	"github.com/PlatONnetwork/PlatON-Go/rpc"
)

type Caller interface {
	Call(ctx context.Context, args ethapi.CallArgs, blockNrOrHash rpc.BlockNumberOrHash, overrides *ethapi.StateOverride) (hexutil.Bytes, error)
}
