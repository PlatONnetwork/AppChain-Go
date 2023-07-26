package processor

import (
	"context"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/PlatONnetwork/AppChain-Go/accounts/abi"
	"github.com/PlatONnetwork/AppChain-Go/common"
	"github.com/PlatONnetwork/AppChain-Go/common/hexutil"
	cvm "github.com/PlatONnetwork/AppChain-Go/common/vm"
	"github.com/PlatONnetwork/AppChain-Go/consensus"
	"github.com/PlatONnetwork/AppChain-Go/core/cbfttypes"
	"github.com/PlatONnetwork/AppChain-Go/core/types"
	"github.com/PlatONnetwork/AppChain-Go/core/vm"
	"github.com/PlatONnetwork/AppChain-Go/core/vm/solidity"
	"github.com/PlatONnetwork/AppChain-Go/core/vm/solidity/checkpoint"
	"github.com/PlatONnetwork/AppChain-Go/crypto"
	"github.com/PlatONnetwork/AppChain-Go/eth/filters"
	"github.com/PlatONnetwork/AppChain-Go/event"
	"github.com/PlatONnetwork/AppChain-Go/innerbindings/helper"
	"github.com/PlatONnetwork/AppChain-Go/innerbindings/rootchain"
	"github.com/PlatONnetwork/AppChain-Go/internal/ethapi"
	"github.com/PlatONnetwork/AppChain-Go/log"
	"github.com/PlatONnetwork/AppChain-Go/processor/api"
	"github.com/PlatONnetwork/AppChain-Go/rpc"
	"github.com/PlatONnetwork/AppChain-Go/x/plugin"
	"github.com/PlatONnetwork/AppChain-Go/x/staking"
	"github.com/PlatONnetwork/AppChain-Go/x/xutil"
	lru "github.com/hashicorp/golang-lru"
	"github.com/xsleonard/go-merkle"
	"golang.org/x/crypto/sha3"
)

const defaultBlockInterval = 10000

type CheckpointProcessor struct {
	chain ChainReader

	chainId            *big.Int
	bft                consensus.Bft
	txPoolAPI          api.TxPoolAPI
	filterAPI          api.FilterAPI
	caller             api.Caller
	rootchainConnector *RootchainConnector
	managerAccount     TxSigner

	checkpointABI *abi.ABI
	rootchainABI  *abi.ABI

	newHeaderBlockSubscription event.Subscription
	newHeaderBlockCh           chan *types.Log
	bftResultSub               *event.TypeMuxSubscription
	newChildBlockCh            chan *types.Block

	fromBlockNumber uint64

	exitCh chan struct{}

	rootHashCache *lru.ARCCache
}

func NewCheckpointProcessor(
	chain ChainReader,
	chainId *big.Int,
	bft consensus.Bft,
	txPoolAPI api.TxPoolAPI,
	filterAPI api.FilterAPI,
	caller api.Caller,
	rootchainConnector *RootchainConnector,
	magnerAccount TxSigner,
	subscriber NewHeaderBlockSubscriber,
	bftResultSub *event.TypeMuxSubscription,
) (*CheckpointProcessor, error) {
	p := &CheckpointProcessor{
		chain:              chain,
		chainId:            chainId,
		bft:                bft,
		txPoolAPI:          txPoolAPI,
		filterAPI:          filterAPI,
		caller:             caller,
		rootchainConnector: rootchainConnector,
		managerAccount:     magnerAccount,
		newHeaderBlockCh:   make(chan *types.Log, 16),
		bftResultSub:       bftResultSub,
		newChildBlockCh:    make(chan *types.Block, 64),
		fromBlockNumber:    chain.CurrentHeader().Number.Uint64(),
		checkpointABI:      vm.CheckpointABI(),
		rootchainABI:       helper.RootChainAbi,
		exitCh:             make(chan struct{}),
	}

	p.newHeaderBlockSubscription = subscriber.SubscribeEvents(p.newHeaderBlockCh)

	var err error
	p.rootHashCache, err = lru.NewARC(10)
	if err != nil {
		return nil, err
	}

	go p.loop()
	go p.processBlock()

	return p, nil
}

func (p *CheckpointProcessor) Stop() {
	close(p.exitCh)
}

func (p *CheckpointProcessor) loop() {
	defer p.bftResultSub.Unsubscribe()

	for {
		select {
		case result := <-p.bftResultSub.Chan():
			if result == nil {
				continue
			}
			cbftRsult, ok := result.Data.(cbfttypes.CbftResult)
			if !ok {
				log.Error("Receive bft result type error")
				continue
			}
			block := cbftRsult.Block
			if block == nil {
				log.Error("Cbft result error: block is nil")
				continue
			}
			p.newChildBlockCh <- block
		case <-p.exitCh:
			log.Info("Checkpoint loop stopping...")
			return
		}
	}
}

func (p *CheckpointProcessor) processBlock() {
	defer p.newHeaderBlockSubscription.Unsubscribe()

	for {
		select {
		case err := <-p.newHeaderBlockSubscription.Err():
			log.Error("New header block subscription fail", "err", err)
			return
		case log := <-p.newHeaderBlockCh:
			if log == nil {
				continue
			}
			p.handleNewHeaderBlock(log)
		case block := <-p.newChildBlockCh:
			p.handleBlock(block)
		case <-p.exitCh:
			log.Info("Checkpoint processBlock stopping...")
			return
		}
	}
}

func (p *CheckpointProcessor) handleNewHeaderBlock(evlog *types.Log) {
	newHeaderBlock := new(rootchain.RootchainNewHeaderBlock)
	if err := helper.UnpackLog(helper.RootChainAbi, newHeaderBlock, helper.NewHeaderBlock, evlog); err != nil {
		log.Error("Unpack new header block log error", "err", err)
		return
	}
	log.Info("Checkpoint committed",
		"proposer", newHeaderBlock.Proposer,
		"headerBlockId", newHeaderBlock.HeaderBlockId,
		"reward", newHeaderBlock.Reward,
		"Start", newHeaderBlock.Start,
		"end", newHeaderBlock.End,
		"root", hex.EncodeToString(newHeaderBlock.Root[:]),
	)
}

func (p *CheckpointProcessor) handleBlock(block *types.Block) {
	p.sendCheckpointToAppChain(block)
	p.sendCheckpointToRootChain(block)
}

func (p *CheckpointProcessor) sendCheckpointToAppChain(block *types.Block) {
	validator, err := p.bft.IsCurrentValidator()
	isValidator := validator != nil && err == nil
	if isValidator {
		expectedCheckpointState, err := p.nextExpectedCheckpoint(block.NumberU64())
		if err != nil {
			log.Error("Calculate next expected checkpoint error", "err", err)
			return
		}

		start := expectedCheckpointState.newStart
		end := expectedCheckpointState.newEnd

		if end > block.NumberU64() {
			log.Debug("Waiting for blocks", "number", block.NumberU64(), "end", end)
			return
		}

		shouldPropose, err := p.shouldPropose(block.Number(), big.NewInt(0).SetUint64(uint64(validator.ValidatorId)))
		if err != nil {
			log.Error("Cannot check should propose", "number", block.Number(), "validatorId", validator.ValidatorId, "err", err)
			return
		}

		if !shouldPropose {
			log.Info("Checkpoint already propose", "number", block.NumberU64())
			return
		}

		if err := p.createAndSendCheckpointToAppChain(block, start, end); err != nil {
			log.Error("Sending checkpoint to appchain error", "err", err)
			return
		}
	} else {
		log.Info("I'm not the validator. skipping newheader", "headerNumber", block.Number())
	}
}

func (p *CheckpointProcessor) sendCheckpointToRootChain(block *types.Block) {
	aggEv, err := p.getCheckpointSigAggEvent(block)
	if err != nil || aggEv == nil {
		return
	}

	isProposer := p.bft.IsCurrentProposer()

	startBlock := aggEv.Start.Uint64()
	endBlock := aggEv.End.Uint64()

	shouldSend, err := p.shouldSendCheckpoint(startBlock, endBlock)
	if err != nil {
		return
	}

	if isProposer && shouldSend {
		if err := p.createAndSendCheckpointToRootchain(aggEv, startBlock, endBlock); err != nil {
			log.Error("Sending checkpoint to rootchain error", "err", err)
			return
		}
	}
	log.Info("I am not the current proposer or checkpoint already sent. Ignoring.", "number", block.Number())
}

func (p *CheckpointProcessor) createAndSendCheckpointToAppChain(block *types.Block, start, end uint64) error {
	log.Debug("Initiating checkpoint to appchain", "start", start, "end", end)

	if end == 0 || start > end {
		log.Info("Waiting for blocks or invalid start end formation", "start", start, "end", end)
		return nil
	}

	root, err := p.rootHash(start, end)
	if err != nil {
		return err
	}
	log.Info("Root hash calculated", "rootHash", root)

	endBlockHeader := p.chain.GetHeaderByNumber(end)
	verifiers, err := plugin.StakingInstance().GetVerifierListFilterInitNode(endBlockHeader.Hash(), endBlockHeader.Number.Uint64(), false)
	//verifiers = sortVerifierList(verifiers)
	if err != nil {
		log.Info("Failed to get verifier list", "hash", endBlockHeader.Hash(), "number", endBlockHeader.Number, "err", err)
		return err
	}
	accountRootHash, err := p.accountHash(verifiers)
	if err != nil {
		return err
	}

	proposer := p.bft.CurrentProposer()

	log.Info("Creating and sign new checkpoint", "proposer", proposer.Address.String(), "start", start, "end", end, "root", root, "accountRoot", accountRootHash)

	validators, err := plugin.StakingInstance().GetValidator(block.NumberU64())
	if err != nil {
		return err
	}

	current := validators.ValidatorIdList()
	rewards := make([]*big.Int, len(verifiers))
	for i, v := range verifiers {
		rewards[i] = v.ValidatorId
	}
	// TODO: slashing

	hashes := make([][32]byte, 2)
	hashes[0] = root
	hashes[1] = accountRootHash

	cp := &Checkpoint{
		Proposer: common.Address(proposer.Address),
		Hashes:   hashes,
		Start:    big.NewInt(0).SetUint64(start),
		End:      big.NewInt(0).SetUint64(end),
		Current:  convertToBigInt(current),
		Rewards:  rewards,
		ChainId:  p.chainId,
		Slashing: make([]*big.Int, 0),
	}

	tcp := solidity.ICheckpointToCheckpoint((*checkpoint.ICheckpointSigAggregatorCheckpoint)(cp))
	signature, err := p.bft.BlsSign(crypto.Keccak256(tcp.Pack()))
	if err != nil {
		log.Error("BLS sign error", "err", err)
		return err
	}
	me, err := p.bft.IsCurrentValidator()
	if err != nil {
		log.Error("Get current valiator error", "err", err)
		return err
	}
	log.Info("Sending new checkpoint proposal",
		"proposer", cp.Proposer,
		"start", start,
		"end", end,
		"root", root,
		"accountRoot", accountRootHash,
		"validatorId", me.ValidatorId,
		"signature", hex.EncodeToString(signature))
	return p.submitProposalSignature(cp, me.ValidatorId, signature)
}

func (p *CheckpointProcessor) createAndSendCheckpointToRootchain(aggEv *checkpoint.CheckpointCheckpointSigAggregated, start, end uint64) error {
	pending, err := p.getPendingCheckpoint()
	if err != nil {
		return err
	}

	if pending != nil && (pending.Checkpoint.Start.Uint64() != start || pending.Checkpoint.End.Uint64() != end) {
		log.Error("Mismatch pending checkpoint start end formation",
			"pending.start", pending.Checkpoint.Start,
			"pending.end", pending.Checkpoint.End,
			"start", start,
			"end", end,
		)
		return nil
	}

	shouldSend, err := p.shouldSendCheckpoint(start, end)
	if err != nil {
		return err
	}

	if shouldSend {
		tcp := solidity.ICheckpointToCheckpoint(&pending.Checkpoint)
		s := make([]string, 0)
		for _, id := range aggEv.SignedValidators {
			s = append(s, id.String())
		}
		log.Info("Sending new checkpoint to rootchain",
			"proposer", tcp.Proposer,
			"start", tcp.Start,
			"end", tcp.End,
			"rootHash", hex.EncodeToString(tcp.Hashes[0][:]),
			"accountHash", hex.EncodeToString(tcp.Hashes[1][:]),
			"signedValidators", strings.Join(s, ","),
			"signature", hex.EncodeToString(aggEv.Signature),
		)
		if err := p.rootchainConnector.SendCheckpoint(tcp.Pack(), aggEv.SignedValidators, aggEv.Signature); err != nil {
			log.Error("Failed to submit checkpoint to rootchain", "checkpoint", tcp.String(), "err", err)
			return err
		}
	}
	return nil
}

func (p *CheckpointProcessor) submitProposalSignature(proposal *Checkpoint, validatorId uint32, signature []byte) error {
	cp := (*checkpoint.ICheckpointSigAggregatorCheckpoint)(proposal)
	vid := big.NewInt(int64(validatorId))
	data, err := p.checkpointABI.Pack("propose", cp, vid, signature)
	if err != nil {
		return err
	}

	tx := types.NewTransaction(
		p.managerAccount.Nonce(),
		cvm.CheckpointSigAggAddr,
		big.NewInt(0),
		50000,
		big.NewInt(0),
		data,
	)
	signedTx, err := p.managerAccount.Sign(tx, p.chainId)
	if err != nil {
		return err
	}
	return p.txPoolAPI.SendTx(context.Background(), signedTx)
}

func (p *CheckpointProcessor) nextExpectedCheckpoint(latestChildBlock uint64) (*ContractCheckpoint, error) {
	currentHeaderBlock, err := p.rootchainConnector.CurrentHeaderBlock(defaultBlockInterval)
	if err != nil {
		return nil, err
	}

	currentHeaderBlockNumber := big.NewInt(0).SetUint64(currentHeaderBlock)

	_, currentStart, currentEnd, _, _, err := p.rootchainConnector.GetHeaderInfo(currentHeaderBlockNumber.Uint64(), defaultBlockInterval)
	if err != nil {
		log.Error("Failed to fetching header info from rootchain contract", "currentHeaderBlockNumber", currentHeaderBlockNumber, "err", err)
		return nil, err
	}

	var start, end uint64
	start = currentEnd

	if start > 0 {
		start = start + 1
	}

	epochBlocks := xutil.CalcBlocksEachEpoch()
	end = epochBlocks + start - 1
	if start == 0 {
		end = end + 1
	}

	if latestChildBlock >= end {
		log.Debug("Calculating checkpoint eligibility",
			"latest", latestChildBlock,
			"start", start,
			"end", end,
			"epochBlocks", epochBlocks,
		)
	}

	return NewContractCheckpoint(start, end, &HeaderBlock{
		start:  currentStart,
		end:    currentEnd,
		number: currentHeaderBlockNumber,
	}), nil
}

func (p *CheckpointProcessor) getCheckpointSigAggEvent(block *types.Block) (*checkpoint.CheckpointCheckpointSigAggregated, error) {
	event := p.checkpointABI.Events["CheckpointSigAggregated"]

	logs, err := p.filterAPI.GetLogs(context.Background(), filters.FilterCriteria{
		FromBlock: new(big.Int).SetUint64(p.fromBlockNumber),
		ToBlock:   block.Number(),
		Addresses: []common.Address{cvm.CheckpointSigAggAddr},
		Topics:    [][]common.Hash{{event.ID}},
	})
	if err != nil {
		log.Error("Failed to filter log", "number", block.Number(), "hash", block.Hash(), "err", err)
		return nil, err
	}
	p.fromBlockNumber = block.NumberU64() + 1

	if len(logs) == 0 {
		return nil, nil
	}
	// Get the latest one
	evlog := logs[len(logs)-1]

	aggEv := new(checkpoint.CheckpointCheckpointSigAggregated)
	if err := helper.UnpackLog(p.checkpointABI, aggEv, event.Name, evlog); err != nil {
		log.Error("Unpack checkpoint sig aggregated log error", "err", err)
		return nil, err
	}
	return aggEv, nil
}

func (p *CheckpointProcessor) shouldSendCheckpoint(start, end uint64) (bool, error) {
	currentChildBlock, err := p.rootchainConnector.GetLatestChildBlock()
	if err != nil {
		return false, err
	}
	log.Debug("Fetched current child block", "currentChildBlock", currentChildBlock)

	shouldSend := false
	if ((currentChildBlock + 1) == start) || (start == 0 && currentChildBlock == 0) {
		log.Debug("Checkpoint valid", "startBlock", start)
		shouldSend = true
	} else if currentChildBlock > start {
		log.Info("Start block does not match, checkpoint already sent", "commitedLatestBlock", currentChildBlock, "startBlock", start)
	} else if currentChildBlock > end {
		log.Info("Checkpoint already sent", "commitedLatestBlock", currentChildBlock, "startBlock", start)
	} else {
		log.Info("No need to send checkpoint")
	}
	return shouldSend, nil
}

func (p *CheckpointProcessor) getPendingCheckpoint() (*PendingCheckpoint, error) {
	blockNr := rpc.BlockNumber(rpc.PendingBlockNumber)

	const method = "pendingCheckpoint"

	data, err := p.checkpointABI.Pack(method)
	if err != nil {
		return nil, err
	}

	msgData := (hexutil.Bytes)(data)
	toAddress := cvm.CheckpointSigAggAddr
	gas := (hexutil.Uint64)(uint64(math.MaxUint64 / 2))

	result, err := p.caller.Call(context.Background(), ethapi.CallArgs{
		To:   &toAddress,
		Data: &msgData,
		Gas:  &gas,
	}, rpc.BlockNumberOrHash{BlockNumber: &blockNr}, nil)
	if err != nil {
		return nil, err
	}

	if len(result) > 0 {
		pending := new(checkpoint.ICheckpointSigAggregatorPendingCheckpoint)
		out, err := p.checkpointABI.Unpack("pendingCheckpoint", result)
		if err != nil {
			return nil, err
		}
		abi.ConvertType(out[0], &pending)
		log.Debug("Get pending checkpoint", "proposer", pending.Checkpoint.Proposer,
			"start", pending.Checkpoint.Start, "end", pending.Checkpoint.End,
			"blockNum", pending.BlockNum)
		return (*PendingCheckpoint)(pending), nil
	}
	return nil, nil
}

func (p *CheckpointProcessor) shouldPropose(number, validatorId *big.Int) (bool, error) {
	blockNr := rpc.BlockNumber(rpc.PendingBlockNumber)

	const method = "shouldPropose"

	data, err := p.checkpointABI.Pack(method, number, validatorId)
	if err != nil {
		return false, err
	}

	msgData := (hexutil.Bytes)(data)
	toAddress := cvm.CheckpointSigAggAddr
	gas := (hexutil.Uint64)(uint64(math.MaxUint64 / 2))

	result, err := p.caller.Call(context.Background(), ethapi.CallArgs{
		To:   &toAddress,
		Data: &msgData,
		Gas:  &gas,
	}, rpc.BlockNumberOrHash{BlockNumber: &blockNr}, nil)
	if err != nil {
		return false, err
	}

	out, err := p.checkpointABI.Unpack("shouldPropose", result)
	if err != nil {
		return false, err
	}

	should := *abi.ConvertType(out[0], new(bool)).(*bool)
	log.Debug("Should propose", "number", number, "validatorId", validatorId, "should", should)
	return should, nil
}

func (p *CheckpointProcessor) rootHash(start, end uint64) (common.Hash, error) {
	key := getRootHashKey(start, end)

	if root, known := p.rootHashCache.Get(key); known {
		return common.BytesToHash(root.([]byte)), nil
	}

	length := end - start + 1
	currentHeaderNumber := p.chain.CurrentHeader().Number.Uint64()

	if start > end || end > currentHeaderNumber {
		return common.ZeroHash, fmt.Errorf("invalid start end block(start: %d, end: %d, current: %d)", start, end, currentHeaderNumber)
	}

	blockHeaders := make([]*types.Header, end-start+1)
	wg := new(sync.WaitGroup)
	concurrent := make(chan bool, 20)

	for i := start; i <= end; i++ {
		wg.Add(1)
		concurrent <- true

		go func(number uint64) {
			blockHeaders[number-start] = p.chain.GetHeaderByNumber(number)

			<-concurrent
			wg.Done()
		}(i)
	}
	wg.Wait()
	close(concurrent)

	headers := make([][32]byte, nextPowerOfTwo(length))

	for i := 0; i < len(blockHeaders); i++ {
		blockHeader := blockHeaders[i]
		header := crypto.Keccak256(appendBytes32(
			blockHeader.Number.Bytes(),
			new(big.Int).SetUint64(blockHeader.Time).Bytes(),
			blockHeader.TxHash.Bytes(),
			blockHeader.ReceiptHash.Bytes(),
		))

		var arr [32]byte
		copy(arr[:], header)
		headers[i] = arr
	}

	tree := merkle.NewTreeWithOpts(merkle.TreeOptions{EnableHashSorting: false, DisableHashLeaves: true})
	if err := tree.Generate(convert(headers), sha3.NewLegacyKeccak256()); err != nil {
		return common.ZeroHash, err
	}

	p.rootHashCache.Add(key, tree.Root().Hash)

	return common.BytesToHash(tree.Root().Hash), nil
}

func (p *CheckpointProcessor) accountHash(verifiers staking.ValidatorExQueue) (common.Hash, error) {
	accounts := make([][32]byte, nextPowerOfTwo(uint64(len(verifiers))))

	for i := 0; i < len(verifiers); i++ {
		verifier := verifiers[i]
		account := crypto.Keccak256(appendBytes32(
			verifier.ValidatorId.Bytes(),
			verifier.Shares.ToInt().Bytes(),
		))

		var arr [32]byte
		copy(arr[:], account)
		accounts[i] = arr
	}

	tree := merkle.NewTreeWithOpts(merkle.TreeOptions{EnableHashSorting: false, DisableHashLeaves: true})
	if err := tree.Generate(convert(accounts), sha3.NewLegacyKeccak256()); err != nil {
		return common.ZeroHash, err
	}
	return common.BytesToHash(tree.Root().Hash), nil
}

func getRootHashKey(start, end uint64) string {
	return strconv.FormatUint(start, 10) + "-" + strconv.FormatUint(end, 10)
}

func sortVerifierList(verifiers staking.ValidatorExQueue) staking.ValidatorExQueue {
	sort.Slice(verifiers, func(i, j int) bool {
		return verifiers[i].ValidatorId.Cmp(verifiers[j].ValidatorId) < 0
	})
	return verifiers
}

func convertToBigInt(l []uint32) []*big.Int {
	bl := make([]*big.Int, len(l))
	for i, v := range l {
		bl[i] = big.NewInt(int64(v))
	}
	return bl
}
