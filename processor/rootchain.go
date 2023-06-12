package processor

import (
	"context"
	"encoding/hex"
	"math/big"
	"strings"

	"github.com/PlatONnetwork/PlatON-Go/accounts/abi/bind"
	"github.com/PlatONnetwork/PlatON-Go/common"
	"github.com/PlatONnetwork/PlatON-Go/core/types"
	"github.com/PlatONnetwork/PlatON-Go/ethclient"
	"github.com/PlatONnetwork/PlatON-Go/innerbindings/rootchain"
	"github.com/PlatONnetwork/PlatON-Go/log"
	"github.com/PlatONnetwork/PlatON-Go/manager"
)

type RootchainConnector struct {
	managerAccount *manager.ManagerAccount
	platonClient   *ethclient.Client
	caller         *rootchain.RootchainCaller
	transactor     *rootchain.RootchainTransactor

	chainId *big.Int
}

func NewRootchainConnector(managerAccount *manager.ManagerAccount, platonAddr string, contractAddr common.Address) (*RootchainConnector, error) {
	client, err := ethclient.Dial(platonAddr)
	if err != nil {
		return nil, err
	}
	client.SetNameSpace("platon")
	caller, err := rootchain.NewRootchainCaller(contractAddr, client)
	if err != nil {
		return nil, err
	}
	transactor, err := rootchain.NewRootchainTransactor(contractAddr, client)
	if err != nil {
		return nil, err
	}

	chainId, err := client.ChainID(context.Background())
	if err != nil {
		return nil, err
	}

	return &RootchainConnector{
		managerAccount: managerAccount,
		platonClient:   client,
		caller:         caller,
		transactor:     transactor,
		chainId:        chainId,
	}, nil
}

func (c *RootchainConnector) CurrentHeaderBlock(blockInterval uint64) (uint64, error) {
	currentHeaderBlock, err := c.caller.CurrentHeaderBlock(nil)
	if err != nil {
		log.Error("Cannot fetch current header block from rootchain contract", "err", err)
		return 0, err
	}

	return currentHeaderBlock.Uint64() / blockInterval, nil
}

func (c *RootchainConnector) GetHeaderInfo(number, blockInterval uint64) (
	root common.Hash,
	start uint64,
	end uint64,
	createdAt uint64,
	proposer common.Address,
	err error,
) {
	checkpointBigInt := big.NewInt(0).Mul(big.NewInt(0).SetUint64(number), big.NewInt(0).SetUint64(blockInterval))

	headerBlock, err := c.caller.HeaderBlocks(nil, checkpointBigInt)
	if err != nil {
		return root, start, end, createdAt, proposer, err
	}

	return headerBlock.Root,
		headerBlock.Start.Uint64(),
		headerBlock.End.Uint64(),
		headerBlock.CreatedAt.Uint64(),
		headerBlock.Proposer,
		nil
}

func (c *RootchainConnector) GetLatestChildBlock() (uint64, error) {
	latestChildBlock, err := c.caller.GetLastChildBlock(nil)
	if err != nil {
		log.Error("Could not fetch current child block from rootchain contract", "err", err)
		return 0, err
	}

	return latestChildBlock.Uint64(), nil
}

func (c *RootchainConnector) SendCheckpoint(signedData []byte, signedValidators []*big.Int, signature []byte) error {
	s := make([]string, 0)
	for _, id := range signedValidators {
		s = append(s, id.String())
	}
	log.Debug("Sending new checkpoint",
		"signedValidators", strings.Join(s, ","),
		"signature", hex.EncodeToString(signature),
	)

	_, err := c.transactor.SubmitCheckpoint(&bind.TransactOpts{
		From: c.managerAccount.Address(),
		Signer: func(s types.Signer, a common.Address, t *types.Transaction) (*types.Transaction, error) {
			return c.managerAccount.Sign(t, c.chainId)
		},
	}, signedData, signedValidators, signature)
	return err
}
