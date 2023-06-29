// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package innerstake

import (
	"errors"
	"math/big"
	"strings"

	hskchain "github.com/PlatONnetwork/AppChain-Go"
	"github.com/PlatONnetwork/AppChain-Go/accounts/abi"
	"github.com/PlatONnetwork/AppChain-Go/accounts/abi/bind"
	"github.com/PlatONnetwork/AppChain-Go/common"
	"github.com/PlatONnetwork/AppChain-Go/core/types"
	"github.com/PlatONnetwork/AppChain-Go/event"
)

// Reference imports to suppress errors if they are not otherwise used.
var (
	_ = errors.New
	_ = big.NewInt
	_ = strings.NewReader
	_ = hskchain.NotFound
	_ = bind.Bind
	_ = common.Big1
	_ = types.BloomLookup
	_ = event.NewSubscription
)

// InnerstakeMetaData contains all meta data concerning the Innerstake contract.
var InnerstakeMetaData = &bind.MetaData{
	ABI: "[{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"start\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"end\",\"type\":\"uint256\"}],\"name\":\"StakeStateSync\",\"type\":\"event\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"blockNumber\",\"type\":\"uint256\"},{\"internalType\":\"bytes[]\",\"name\":\"events\",\"type\":\"bytes[]\"}],\"name\":\"stakeStateSync\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"blockNumber\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]",
	Bin: "0x608060405234801561001057600080fd5b506101e4806100206000396000f3fe608060405234801561001057600080fd5b50600436106100365760003560e01c806357e871e71461003b578063bb02fc8914610059575b600080fd5b610043610075565b6040516100509190610159565b60405180910390f35b610073600480360381019061006e91906100ea565b61007a565b005b600090565b505050565b60008083601f84011261009557610094610183565b5b8235905067ffffffffffffffff8111156100b2576100b161017e565b5b6020830191508360208202830111156100ce576100cd610188565b5b9250929050565b6000813590506100e481610197565b92915050565b60008060006040848603121561010357610102610192565b5b6000610111868287016100d5565b935050602084013567ffffffffffffffff8111156101325761013161018d565b5b61013e8682870161007f565b92509250509250925092565b61015381610174565b82525050565b600060208201905061016e600083018461014a565b92915050565b6000819050919050565b600080fd5b600080fd5b600080fd5b600080fd5b600080fd5b6101a081610174565b81146101ab57600080fd5b5056fea26469706673582212200871f561d136d8f36794a3f85785e3a534b89181ffd88d9151b146e13e3f22a364736f6c63430008070033",
}

// InnerstakeABI is the input ABI used to generate the binding from.
// Deprecated: Use InnerstakeMetaData.ABI instead.
var InnerstakeABI = InnerstakeMetaData.ABI

// InnerstakeBin is the compiled bytecode used for deploying new contracts.
// Deprecated: Use InnerstakeMetaData.Bin instead.
var InnerstakeBin = InnerstakeMetaData.Bin

// DeployInnerstake deploys a new hskchain contract, binding an instance of Innerstake to it.
func DeployInnerstake(auth *bind.TransactOpts, backend bind.ContractBackend) (common.Address, *types.Transaction, *Innerstake, error) {
	parsed, err := InnerstakeMetaData.GetAbi()
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	if parsed == nil {
		return common.Address{}, nil, nil, errors.New("GetABI returned nil")
	}

	address, tx, contract, err := bind.DeployContract(auth, *parsed, common.FromHex(InnerstakeBin), backend)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &Innerstake{InnerstakeCaller: InnerstakeCaller{contract: contract}, InnerstakeTransactor: InnerstakeTransactor{contract: contract}, InnerstakeFilterer: InnerstakeFilterer{contract: contract}}, nil
}

// Innerstake is an auto generated Go binding around an hskchain contract.
type Innerstake struct {
	InnerstakeCaller     // Read-only binding to the contract
	InnerstakeTransactor // Write-only binding to the contract
	InnerstakeFilterer   // Log filterer for contract events
}

// InnerstakeCaller is an auto generated read-only Go binding around an hskchain contract.
type InnerstakeCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// InnerstakeTransactor is an auto generated write-only Go binding around an hskchain contract.
type InnerstakeTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// InnerstakeFilterer is an auto generated log filtering Go binding around an hskchain contract events.
type InnerstakeFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// InnerstakeSession is an auto generated Go binding around an hskchain contract,
// with pre-set call and transact options.
type InnerstakeSession struct {
	Contract     *Innerstake       // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// InnerstakeCallerSession is an auto generated read-only Go binding around an hskchain contract,
// with pre-set call options.
type InnerstakeCallerSession struct {
	Contract *InnerstakeCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts     // Call options to use throughout this session
}

// InnerstakeTransactorSession is an auto generated write-only Go binding around an hskchain contract,
// with pre-set transact options.
type InnerstakeTransactorSession struct {
	Contract     *InnerstakeTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts     // Transaction auth options to use throughout this session
}

// InnerstakeRaw is an auto generated low-level Go binding around an hskchain contract.
type InnerstakeRaw struct {
	Contract *Innerstake // Generic contract binding to access the raw methods on
}

// InnerstakeCallerRaw is an auto generated low-level read-only Go binding around an hskchain contract.
type InnerstakeCallerRaw struct {
	Contract *InnerstakeCaller // Generic read-only contract binding to access the raw methods on
}

// InnerstakeTransactorRaw is an auto generated low-level write-only Go binding around an hskchain contract.
type InnerstakeTransactorRaw struct {
	Contract *InnerstakeTransactor // Generic write-only contract binding to access the raw methods on
}

// NewInnerstake creates a new instance of Innerstake, bound to a specific deployed contract.
func NewInnerstake(address common.Address, backend bind.ContractBackend) (*Innerstake, error) {
	contract, err := bindInnerstake(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &Innerstake{InnerstakeCaller: InnerstakeCaller{contract: contract}, InnerstakeTransactor: InnerstakeTransactor{contract: contract}, InnerstakeFilterer: InnerstakeFilterer{contract: contract}}, nil
}

// NewInnerstakeCaller creates a new read-only instance of Innerstake, bound to a specific deployed contract.
func NewInnerstakeCaller(address common.Address, caller bind.ContractCaller) (*InnerstakeCaller, error) {
	contract, err := bindInnerstake(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &InnerstakeCaller{contract: contract}, nil
}

// NewInnerstakeTransactor creates a new write-only instance of Innerstake, bound to a specific deployed contract.
func NewInnerstakeTransactor(address common.Address, transactor bind.ContractTransactor) (*InnerstakeTransactor, error) {
	contract, err := bindInnerstake(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &InnerstakeTransactor{contract: contract}, nil
}

// NewInnerstakeFilterer creates a new log filterer instance of Innerstake, bound to a specific deployed contract.
func NewInnerstakeFilterer(address common.Address, filterer bind.ContractFilterer) (*InnerstakeFilterer, error) {
	contract, err := bindInnerstake(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &InnerstakeFilterer{contract: contract}, nil
}

// bindInnerstake binds a generic wrapper to an already deployed contract.
func bindInnerstake(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(InnerstakeABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Innerstake *InnerstakeRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Innerstake.Contract.InnerstakeCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Innerstake *InnerstakeRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Innerstake.Contract.InnerstakeTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Innerstake *InnerstakeRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Innerstake.Contract.InnerstakeTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Innerstake *InnerstakeCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Innerstake.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Innerstake *InnerstakeTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Innerstake.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Innerstake *InnerstakeTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Innerstake.Contract.contract.Transact(opts, method, params...)
}

// BlockNumber is a paid mutator transaction binding the contract method 0x57e871e7.
//
// Solidity: function blockNumber() returns(uint256)
func (_Innerstake *InnerstakeTransactor) BlockNumber(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Innerstake.contract.Transact(opts, "blockNumber")
}

// BlockNumber is a paid mutator transaction binding the contract method 0x57e871e7.
//
// Solidity: function blockNumber() returns(uint256)
func (_Innerstake *InnerstakeSession) BlockNumber() (*types.Transaction, error) {
	return _Innerstake.Contract.BlockNumber(&_Innerstake.TransactOpts)
}

// BlockNumber is a paid mutator transaction binding the contract method 0x57e871e7.
//
// Solidity: function blockNumber() returns(uint256)
func (_Innerstake *InnerstakeTransactorSession) BlockNumber() (*types.Transaction, error) {
	return _Innerstake.Contract.BlockNumber(&_Innerstake.TransactOpts)
}

// StakeStateSync is a paid mutator transaction binding the contract method 0xbb02fc89.
//
// Solidity: function stakeStateSync(uint256 blockNumber, bytes[] events) returns()
func (_Innerstake *InnerstakeTransactor) StakeStateSync(opts *bind.TransactOpts, blockNumber *big.Int, events [][]byte) (*types.Transaction, error) {
	return _Innerstake.contract.Transact(opts, "stakeStateSync", blockNumber, events)
}

// StakeStateSync is a paid mutator transaction binding the contract method 0xbb02fc89.
//
// Solidity: function stakeStateSync(uint256 blockNumber, bytes[] events) returns()
func (_Innerstake *InnerstakeSession) StakeStateSync(blockNumber *big.Int, events [][]byte) (*types.Transaction, error) {
	return _Innerstake.Contract.StakeStateSync(&_Innerstake.TransactOpts, blockNumber, events)
}

// StakeStateSync is a paid mutator transaction binding the contract method 0xbb02fc89.
//
// Solidity: function stakeStateSync(uint256 blockNumber, bytes[] events) returns()
func (_Innerstake *InnerstakeTransactorSession) StakeStateSync(blockNumber *big.Int, events [][]byte) (*types.Transaction, error) {
	return _Innerstake.Contract.StakeStateSync(&_Innerstake.TransactOpts, blockNumber, events)
}

// InnerstakeStakeStateSyncIterator is returned from FilterStakeStateSync and is used to iterate over the raw logs and unpacked data for StakeStateSync events raised by the Innerstake contract.
type InnerstakeStakeStateSyncIterator struct {
	Event *InnerstakeStakeStateSync // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  hskchain.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *InnerstakeStakeStateSyncIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(InnerstakeStakeStateSync)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(InnerstakeStakeStateSync)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *InnerstakeStakeStateSyncIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *InnerstakeStakeStateSyncIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// InnerstakeStakeStateSync represents a StakeStateSync event raised by the Innerstake contract.
type InnerstakeStakeStateSync struct {
	Start *big.Int
	End   *big.Int
	Raw   types.Log // Blockchain specific contextual infos
}

// FilterStakeStateSync is a free log retrieval operation binding the contract event 0xe3a67652e61a483ab89390b9621d7359a9cbe27a29d64d0636424886803fdaba.
//
// Solidity: event StakeStateSync(uint256 start, uint256 end)
func (_Innerstake *InnerstakeFilterer) FilterStakeStateSync(opts *bind.FilterOpts) (*InnerstakeStakeStateSyncIterator, error) {

	logs, sub, err := _Innerstake.contract.FilterLogs(opts, "StakeStateSync")
	if err != nil {
		return nil, err
	}
	return &InnerstakeStakeStateSyncIterator{contract: _Innerstake.contract, event: "StakeStateSync", logs: logs, sub: sub}, nil
}

// WatchStakeStateSync is a free log subscription operation binding the contract event 0xe3a67652e61a483ab89390b9621d7359a9cbe27a29d64d0636424886803fdaba.
//
// Solidity: event StakeStateSync(uint256 start, uint256 end)
func (_Innerstake *InnerstakeFilterer) WatchStakeStateSync(opts *bind.WatchOpts, sink chan<- *InnerstakeStakeStateSync) (event.Subscription, error) {

	logs, sub, err := _Innerstake.contract.WatchLogs(opts, "StakeStateSync")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(InnerstakeStakeStateSync)
				if err := _Innerstake.contract.UnpackLog(event, "StakeStateSync", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseStakeStateSync is a log parse operation binding the contract event 0xe3a67652e61a483ab89390b9621d7359a9cbe27a29d64d0636424886803fdaba.
//
// Solidity: event StakeStateSync(uint256 start, uint256 end)
func (_Innerstake *InnerstakeFilterer) ParseStakeStateSync(log types.Log) (*InnerstakeStakeStateSync, error) {
	event := new(InnerstakeStakeStateSync)
	if err := _Innerstake.contract.UnpackLog(event, "StakeStateSync", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

