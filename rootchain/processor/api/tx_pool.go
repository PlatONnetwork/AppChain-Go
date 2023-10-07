package api

import (
	"context"

	"github.com/PlatONnetwork/PlatON-Go/core/types"
)

type TxPoolAPI interface {
	SendTx(ctx context.Context, signedTx *types.Transaction) error
}
