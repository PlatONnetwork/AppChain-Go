package processor

import (
	"context"
	"encoding/hex"
	"math/big"
	"strings"

	"github.com/PlatONnetwork/AppChain-Go/accounts/abi"
	"github.com/PlatONnetwork/AppChain-Go/common"
	"github.com/PlatONnetwork/AppChain-Go/innerbindings/helper"
	"github.com/PlatONnetwork/AppChain-Go/log"
	"github.com/PlatONnetwork/AppChain-Go/manager"
	ethereum "github.com/ethereum/go-ethereum"
	ecom "github.com/ethereum/go-ethereum/common"
	etypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
)

type RootchainConnector struct {
	managerAccount *manager.ManagerAccount
	platonClient   *ethclient.Client
	contractAddr   ecom.Address

	chainId *big.Int
}

func NewRootchainConnector(managerAccount *manager.ManagerAccount, platonAddr string, contractAddr common.Address) (*RootchainConnector, error) {
	client, err := ethclient.Dial(platonAddr)
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
		contractAddr:   toEthAddress(contractAddr),
		chainId:        chainId,
	}, nil
}

func (c *RootchainConnector) CurrentHeaderBlock(blockInterval uint64) (uint64, error) {
	data, err := helper.RootChainAbi.Pack("currentHeaderBlock")
	if err != nil {
		return 0, err
	}

	out, err := c.platonClient.CallContract(context.Background(), ethereum.CallMsg{
		To:   &c.contractAddr,
		Data: data,
	}, nil)
	if err != nil {
		log.Error("Cannot fetch current header block from rootchain contract", "err", err)
		return 0, err
	}

	res, err := helper.RootChainAbi.Unpack("currentHeaderBlock", out)
	if err != nil {
		return 0, err
	}
	currentHeaderBlock := *abi.ConvertType(res[0], new(*big.Int)).(**big.Int)

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
	data, err := helper.RootChainAbi.Pack("headerBlocks", checkpointBigInt)
	if err != nil {
		return root, start, end, createdAt, proposer, err
	}

	out, err := c.platonClient.CallContract(context.Background(), ethereum.CallMsg{
		To:   &c.contractAddr,
		Data: data,
	}, nil)
	if err != nil {
		log.Error("Cannot fetch current header block from rootchain contract", "err", err)
		return root, start, end, createdAt, proposer, err
	}

	res, err := helper.RootChainAbi.Unpack("headerBlocks", out)
	if err != nil {
		return root, start, end, createdAt, proposer, err
	}

	headerBlock := new(struct {
		Root      [32]byte
		Start     *big.Int
		End       *big.Int
		CreatedAt *big.Int
		Proposer  common.Address
	})

	headerBlock.Root = res[0].([32]byte)
	headerBlock.Start = res[1].(*big.Int)
	headerBlock.End = res[2].(*big.Int)
	headerBlock.CreatedAt = res[3].(*big.Int)
	headerBlock.Proposer = res[4].(common.Address)

	return headerBlock.Root,
		headerBlock.Start.Uint64(),
		headerBlock.End.Uint64(),
		headerBlock.CreatedAt.Uint64(),
		headerBlock.Proposer,
		nil
}

func (c *RootchainConnector) GetLatestChildBlock() (uint64, error) {
	data, err := helper.RootChainAbi.Pack("getLastChildBlock")
	if err != nil {
		return 0, err
	}

	out, err := c.platonClient.CallContract(context.Background(), ethereum.CallMsg{
		To:   &c.contractAddr,
		Data: data,
	}, nil)
	if err != nil {
		log.Error("Could not fetch current child block from rootchain contract", "err", err)
		return 0, err
	}

	res, err := helper.RootChainAbi.Unpack("getLastChildBlock", out)
	if err != nil {
		return 0, err
	}
	latestChildBlock := *abi.ConvertType(res[0], new(*big.Int)).(**big.Int)

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

	data, err := helper.RootChainAbi.Pack("submitCheckpoint", signedData, signedValidators, signature)
	if err != nil {
		return err
	}

	nonce, err := c.platonClient.PendingNonceAt(context.Background(), toEthAddress(c.managerAccount.Address()))
	if err != nil {
		return err
	}

	gasPrice, err := c.platonClient.SuggestGasPrice(context.Background())
	if err != nil {
		return err
	}

	msg := ethereum.CallMsg{
		From:     toEthAddress(c.managerAccount.Address()),
		To:       &c.contractAddr,
		GasPrice: gasPrice,
		Data:     data,
	}
	gasLimit, err := c.platonClient.EstimateGas(context.Background(), msg)
	if err != nil {
		return err
	}

	rawTx := etypes.NewTransaction(nonce, c.contractAddr, big.NewInt(0), gasLimit, gasPrice, data)
	signedTx, err := c.managerAccount.SignEthTx(rawTx, c.chainId)
	if err != nil {
		return err
	}
	return c.platonClient.SendTransaction(context.Background(), signedTx)
}

func toEthAddress(addr common.Address) ecom.Address {
	return ecom.BytesToAddress(addr.Bytes())
}
