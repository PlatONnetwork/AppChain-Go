package api

import (
	"context"

	"github.com/PlatONnetwork/AppChain-Go/common/hexutil"
	"github.com/PlatONnetwork/AppChain-Go/internal/ethapi"
	"github.com/PlatONnetwork/AppChain-Go/rpc"
)

type Caller interface {
	Call(ctx context.Context, args ethapi.CallArgs, blockNrOrHash rpc.BlockNumberOrHash, overrides *ethapi.StateOverride) (hexutil.Bytes, error)
}
