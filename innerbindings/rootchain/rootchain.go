// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package rootchain

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

// RootchainMetaData contains all meta data concerning the Rootchain contract.
var RootchainMetaData = &bind.MetaData{
	ABI: "[{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"proposer\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"headerBlockId\",\"type\":\"uint256\"},{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"reward\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"start\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"end\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"bytes32\",\"name\":\"root\",\"type\":\"bytes32\"}],\"name\":\"NewHeaderBlock\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"previousOwner\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"newOwner\",\"type\":\"address\"}],\"name\":\"OwnershipTransferred\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"proposer\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"headerBlockId\",\"type\":\"uint256\"}],\"name\":\"ResetHeaderBlock\",\"type\":\"event\"},{\"constant\":true,\"inputs\":[],\"name\":\"CHAINID\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"VOTE_TYPE\",\"outputs\":[{\"internalType\":\"uint8\",\"name\":\"\",\"type\":\"uint8\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"_nextHeaderBlock\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"headerBlocks\",\"outputs\":[{\"internalType\":\"bytes32\",\"name\":\"root\",\"type\":\"bytes32\"},{\"internalType\":\"uint256\",\"name\":\"start\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"end\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"createdAt\",\"type\":\"uint256\"},{\"internalType\":\"address\",\"name\":\"proposer\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"heimdallId\",\"outputs\":[{\"internalType\":\"bytes32\",\"name\":\"\",\"type\":\"bytes32\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"isOwner\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"networkId\",\"outputs\":[{\"internalType\":\"bytes\",\"name\":\"\",\"type\":\"bytes\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"owner\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[],\"name\":\"renounceOwnership\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"internalType\":\"address\",\"name\":\"newOwner\",\"type\":\"address\"}],\"name\":\"transferOwnership\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"data\",\"type\":\"bytes\"},{\"internalType\":\"bytes\",\"name\":\"sigs\",\"type\":\"bytes\"}],\"name\":\"submitHeaderBlock\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"data\",\"type\":\"bytes\"},{\"internalType\":\"uint256[]\",\"name\":\"validatorIds\",\"type\":\"uint256[]\"},{\"internalType\":\"bytes\",\"name\":\"signatures\",\"type\":\"bytes\"}],\"name\":\"submitCheckpoint\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"numDeposits\",\"type\":\"uint256\"}],\"name\":\"updateDepositId\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"depositId\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"getLastChildBlock\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[],\"name\":\"slash\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"currentHeaderBlock\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"_value\",\"type\":\"uint256\"}],\"name\":\"setNextHeaderBlock\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"internalType\":\"string\",\"name\":\"_heimdallId\",\"type\":\"string\"}],\"name\":\"setHeimdallId\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]",
}

// RootchainABI is the input ABI used to generate the binding from.
// Deprecated: Use RootchainMetaData.ABI instead.
var RootchainABI = RootchainMetaData.ABI

// Rootchain is an auto generated Go binding around an hskchain contract.
type Rootchain struct {
	RootchainCaller     // Read-only binding to the contract
	RootchainTransactor // Write-only binding to the contract
	RootchainFilterer   // Log filterer for contract events
}

// RootchainCaller is an auto generated read-only Go binding around an hskchain contract.
type RootchainCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// RootchainTransactor is an auto generated write-only Go binding around an hskchain contract.
type RootchainTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// RootchainFilterer is an auto generated log filtering Go binding around an hskchain contract events.
type RootchainFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// RootchainSession is an auto generated Go binding around an hskchain contract,
// with pre-set call and transact options.
type RootchainSession struct {
	Contract     *Rootchain        // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// RootchainCallerSession is an auto generated read-only Go binding around an hskchain contract,
// with pre-set call options.
type RootchainCallerSession struct {
	Contract *RootchainCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts    // Call options to use throughout this session
}

// RootchainTransactorSession is an auto generated write-only Go binding around an hskchain contract,
// with pre-set transact options.
type RootchainTransactorSession struct {
	Contract     *RootchainTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts    // Transaction auth options to use throughout this session
}

// RootchainRaw is an auto generated low-level Go binding around an hskchain contract.
type RootchainRaw struct {
	Contract *Rootchain // Generic contract binding to access the raw methods on
}

// RootchainCallerRaw is an auto generated low-level read-only Go binding around an hskchain contract.
type RootchainCallerRaw struct {
	Contract *RootchainCaller // Generic read-only contract binding to access the raw methods on
}

// RootchainTransactorRaw is an auto generated low-level write-only Go binding around an hskchain contract.
type RootchainTransactorRaw struct {
	Contract *RootchainTransactor // Generic write-only contract binding to access the raw methods on
}

// NewRootchain creates a new instance of Rootchain, bound to a specific deployed contract.
func NewRootchain(address common.Address, backend bind.ContractBackend) (*Rootchain, error) {
	contract, err := bindRootchain(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &Rootchain{RootchainCaller: RootchainCaller{contract: contract}, RootchainTransactor: RootchainTransactor{contract: contract}, RootchainFilterer: RootchainFilterer{contract: contract}}, nil
}

// NewRootchainCaller creates a new read-only instance of Rootchain, bound to a specific deployed contract.
func NewRootchainCaller(address common.Address, caller bind.ContractCaller) (*RootchainCaller, error) {
	contract, err := bindRootchain(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &RootchainCaller{contract: contract}, nil
}

// NewRootchainTransactor creates a new write-only instance of Rootchain, bound to a specific deployed contract.
func NewRootchainTransactor(address common.Address, transactor bind.ContractTransactor) (*RootchainTransactor, error) {
	contract, err := bindRootchain(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &RootchainTransactor{contract: contract}, nil
}

// NewRootchainFilterer creates a new log filterer instance of Rootchain, bound to a specific deployed contract.
func NewRootchainFilterer(address common.Address, filterer bind.ContractFilterer) (*RootchainFilterer, error) {
	contract, err := bindRootchain(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &RootchainFilterer{contract: contract}, nil
}

// bindRootchain binds a generic wrapper to an already deployed contract.
func bindRootchain(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(RootchainABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Rootchain *RootchainRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Rootchain.Contract.RootchainCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Rootchain *RootchainRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Rootchain.Contract.RootchainTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Rootchain *RootchainRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Rootchain.Contract.RootchainTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Rootchain *RootchainCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Rootchain.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Rootchain *RootchainTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Rootchain.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Rootchain *RootchainTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Rootchain.Contract.contract.Transact(opts, method, params...)
}

// CHAINID is a free data retrieval call binding the contract method 0xcc79f97b.
//
// Solidity: function CHAINID() view returns(uint256)
func (_Rootchain *RootchainCaller) CHAINID(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _Rootchain.contract.Call(opts, &out, "CHAINID")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// CHAINID is a free data retrieval call binding the contract method 0xcc79f97b.
//
// Solidity: function CHAINID() view returns(uint256)
func (_Rootchain *RootchainSession) CHAINID() (*big.Int, error) {
	return _Rootchain.Contract.CHAINID(&_Rootchain.CallOpts)
}

// CHAINID is a free data retrieval call binding the contract method 0xcc79f97b.
//
// Solidity: function CHAINID() view returns(uint256)
func (_Rootchain *RootchainCallerSession) CHAINID() (*big.Int, error) {
	return _Rootchain.Contract.CHAINID(&_Rootchain.CallOpts)
}

// VOTETYPE is a free data retrieval call binding the contract method 0xd5b844eb.
//
// Solidity: function VOTE_TYPE() view returns(uint8)
func (_Rootchain *RootchainCaller) VOTETYPE(opts *bind.CallOpts) (uint8, error) {
	var out []interface{}
	err := _Rootchain.contract.Call(opts, &out, "VOTE_TYPE")

	if err != nil {
		return *new(uint8), err
	}

	out0 := *abi.ConvertType(out[0], new(uint8)).(*uint8)

	return out0, err

}

// VOTETYPE is a free data retrieval call binding the contract method 0xd5b844eb.
//
// Solidity: function VOTE_TYPE() view returns(uint8)
func (_Rootchain *RootchainSession) VOTETYPE() (uint8, error) {
	return _Rootchain.Contract.VOTETYPE(&_Rootchain.CallOpts)
}

// VOTETYPE is a free data retrieval call binding the contract method 0xd5b844eb.
//
// Solidity: function VOTE_TYPE() view returns(uint8)
func (_Rootchain *RootchainCallerSession) VOTETYPE() (uint8, error) {
	return _Rootchain.Contract.VOTETYPE(&_Rootchain.CallOpts)
}

// NextHeaderBlock is a free data retrieval call binding the contract method 0x8d978d88.
//
// Solidity: function _nextHeaderBlock() view returns(uint256)
func (_Rootchain *RootchainCaller) NextHeaderBlock(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _Rootchain.contract.Call(opts, &out, "_nextHeaderBlock")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// NextHeaderBlock is a free data retrieval call binding the contract method 0x8d978d88.
//
// Solidity: function _nextHeaderBlock() view returns(uint256)
func (_Rootchain *RootchainSession) NextHeaderBlock() (*big.Int, error) {
	return _Rootchain.Contract.NextHeaderBlock(&_Rootchain.CallOpts)
}

// NextHeaderBlock is a free data retrieval call binding the contract method 0x8d978d88.
//
// Solidity: function _nextHeaderBlock() view returns(uint256)
func (_Rootchain *RootchainCallerSession) NextHeaderBlock() (*big.Int, error) {
	return _Rootchain.Contract.NextHeaderBlock(&_Rootchain.CallOpts)
}

// CurrentHeaderBlock is a free data retrieval call binding the contract method 0xec7e4855.
//
// Solidity: function currentHeaderBlock() view returns(uint256)
func (_Rootchain *RootchainCaller) CurrentHeaderBlock(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _Rootchain.contract.Call(opts, &out, "currentHeaderBlock")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// CurrentHeaderBlock is a free data retrieval call binding the contract method 0xec7e4855.
//
// Solidity: function currentHeaderBlock() view returns(uint256)
func (_Rootchain *RootchainSession) CurrentHeaderBlock() (*big.Int, error) {
	return _Rootchain.Contract.CurrentHeaderBlock(&_Rootchain.CallOpts)
}

// CurrentHeaderBlock is a free data retrieval call binding the contract method 0xec7e4855.
//
// Solidity: function currentHeaderBlock() view returns(uint256)
func (_Rootchain *RootchainCallerSession) CurrentHeaderBlock() (*big.Int, error) {
	return _Rootchain.Contract.CurrentHeaderBlock(&_Rootchain.CallOpts)
}

// GetLastChildBlock is a free data retrieval call binding the contract method 0xb87e1b66.
//
// Solidity: function getLastChildBlock() view returns(uint256)
func (_Rootchain *RootchainCaller) GetLastChildBlock(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _Rootchain.contract.Call(opts, &out, "getLastChildBlock")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// GetLastChildBlock is a free data retrieval call binding the contract method 0xb87e1b66.
//
// Solidity: function getLastChildBlock() view returns(uint256)
func (_Rootchain *RootchainSession) GetLastChildBlock() (*big.Int, error) {
	return _Rootchain.Contract.GetLastChildBlock(&_Rootchain.CallOpts)
}

// GetLastChildBlock is a free data retrieval call binding the contract method 0xb87e1b66.
//
// Solidity: function getLastChildBlock() view returns(uint256)
func (_Rootchain *RootchainCallerSession) GetLastChildBlock() (*big.Int, error) {
	return _Rootchain.Contract.GetLastChildBlock(&_Rootchain.CallOpts)
}

// HeaderBlocks is a free data retrieval call binding the contract method 0x41539d4a.
//
// Solidity: function headerBlocks(uint256 ) view returns(bytes32 root, uint256 start, uint256 end, uint256 createdAt, address proposer)
func (_Rootchain *RootchainCaller) HeaderBlocks(opts *bind.CallOpts, arg0 *big.Int) (struct {
	Root      [32]byte
	Start     *big.Int
	End       *big.Int
	CreatedAt *big.Int
	Proposer  common.Address
}, error) {
	var out []interface{}
	err := _Rootchain.contract.Call(opts, &out, "headerBlocks", arg0)

	outstruct := new(struct {
		Root      [32]byte
		Start     *big.Int
		End       *big.Int
		CreatedAt *big.Int
		Proposer  common.Address
	})

	outstruct.Root = out[0].([32]byte)
	outstruct.Start = out[1].(*big.Int)
	outstruct.End = out[2].(*big.Int)
	outstruct.CreatedAt = out[3].(*big.Int)
	outstruct.Proposer = out[4].(common.Address)

	return *outstruct, err

}

// HeaderBlocks is a free data retrieval call binding the contract method 0x41539d4a.
//
// Solidity: function headerBlocks(uint256 ) view returns(bytes32 root, uint256 start, uint256 end, uint256 createdAt, address proposer)
func (_Rootchain *RootchainSession) HeaderBlocks(arg0 *big.Int) (struct {
	Root      [32]byte
	Start     *big.Int
	End       *big.Int
	CreatedAt *big.Int
	Proposer  common.Address
}, error) {
	return _Rootchain.Contract.HeaderBlocks(&_Rootchain.CallOpts, arg0)
}

// HeaderBlocks is a free data retrieval call binding the contract method 0x41539d4a.
//
// Solidity: function headerBlocks(uint256 ) view returns(bytes32 root, uint256 start, uint256 end, uint256 createdAt, address proposer)
func (_Rootchain *RootchainCallerSession) HeaderBlocks(arg0 *big.Int) (struct {
	Root      [32]byte
	Start     *big.Int
	End       *big.Int
	CreatedAt *big.Int
	Proposer  common.Address
}, error) {
	return _Rootchain.Contract.HeaderBlocks(&_Rootchain.CallOpts, arg0)
}

// HeimdallId is a free data retrieval call binding the contract method 0xfbc3dd36.
//
// Solidity: function heimdallId() view returns(bytes32)
func (_Rootchain *RootchainCaller) HeimdallId(opts *bind.CallOpts) ([32]byte, error) {
	var out []interface{}
	err := _Rootchain.contract.Call(opts, &out, "heimdallId")

	if err != nil {
		return *new([32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)

	return out0, err

}

// HeimdallId is a free data retrieval call binding the contract method 0xfbc3dd36.
//
// Solidity: function heimdallId() view returns(bytes32)
func (_Rootchain *RootchainSession) HeimdallId() ([32]byte, error) {
	return _Rootchain.Contract.HeimdallId(&_Rootchain.CallOpts)
}

// HeimdallId is a free data retrieval call binding the contract method 0xfbc3dd36.
//
// Solidity: function heimdallId() view returns(bytes32)
func (_Rootchain *RootchainCallerSession) HeimdallId() ([32]byte, error) {
	return _Rootchain.Contract.HeimdallId(&_Rootchain.CallOpts)
}

// IsOwner is a free data retrieval call binding the contract method 0x8f32d59b.
//
// Solidity: function isOwner() view returns(bool)
func (_Rootchain *RootchainCaller) IsOwner(opts *bind.CallOpts) (bool, error) {
	var out []interface{}
	err := _Rootchain.contract.Call(opts, &out, "isOwner")

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// IsOwner is a free data retrieval call binding the contract method 0x8f32d59b.
//
// Solidity: function isOwner() view returns(bool)
func (_Rootchain *RootchainSession) IsOwner() (bool, error) {
	return _Rootchain.Contract.IsOwner(&_Rootchain.CallOpts)
}

// IsOwner is a free data retrieval call binding the contract method 0x8f32d59b.
//
// Solidity: function isOwner() view returns(bool)
func (_Rootchain *RootchainCallerSession) IsOwner() (bool, error) {
	return _Rootchain.Contract.IsOwner(&_Rootchain.CallOpts)
}

// NetworkId is a free data retrieval call binding the contract method 0x9025e64c.
//
// Solidity: function networkId() view returns(bytes)
func (_Rootchain *RootchainCaller) NetworkId(opts *bind.CallOpts) ([]byte, error) {
	var out []interface{}
	err := _Rootchain.contract.Call(opts, &out, "networkId")

	if err != nil {
		return *new([]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([]byte)).(*[]byte)

	return out0, err

}

// NetworkId is a free data retrieval call binding the contract method 0x9025e64c.
//
// Solidity: function networkId() view returns(bytes)
func (_Rootchain *RootchainSession) NetworkId() ([]byte, error) {
	return _Rootchain.Contract.NetworkId(&_Rootchain.CallOpts)
}

// NetworkId is a free data retrieval call binding the contract method 0x9025e64c.
//
// Solidity: function networkId() view returns(bytes)
func (_Rootchain *RootchainCallerSession) NetworkId() ([]byte, error) {
	return _Rootchain.Contract.NetworkId(&_Rootchain.CallOpts)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_Rootchain *RootchainCaller) Owner(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _Rootchain.contract.Call(opts, &out, "owner")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_Rootchain *RootchainSession) Owner() (common.Address, error) {
	return _Rootchain.Contract.Owner(&_Rootchain.CallOpts)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_Rootchain *RootchainCallerSession) Owner() (common.Address, error) {
	return _Rootchain.Contract.Owner(&_Rootchain.CallOpts)
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0x715018a6.
//
// Solidity: function renounceOwnership() returns()
func (_Rootchain *RootchainTransactor) RenounceOwnership(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Rootchain.contract.Transact(opts, "renounceOwnership")
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0x715018a6.
//
// Solidity: function renounceOwnership() returns()
func (_Rootchain *RootchainSession) RenounceOwnership() (*types.Transaction, error) {
	return _Rootchain.Contract.RenounceOwnership(&_Rootchain.TransactOpts)
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0x715018a6.
//
// Solidity: function renounceOwnership() returns()
func (_Rootchain *RootchainTransactorSession) RenounceOwnership() (*types.Transaction, error) {
	return _Rootchain.Contract.RenounceOwnership(&_Rootchain.TransactOpts)
}

// SetHeimdallId is a paid mutator transaction binding the contract method 0xea0688b3.
//
// Solidity: function setHeimdallId(string _heimdallId) returns()
func (_Rootchain *RootchainTransactor) SetHeimdallId(opts *bind.TransactOpts, _heimdallId string) (*types.Transaction, error) {
	return _Rootchain.contract.Transact(opts, "setHeimdallId", _heimdallId)
}

// SetHeimdallId is a paid mutator transaction binding the contract method 0xea0688b3.
//
// Solidity: function setHeimdallId(string _heimdallId) returns()
func (_Rootchain *RootchainSession) SetHeimdallId(_heimdallId string) (*types.Transaction, error) {
	return _Rootchain.Contract.SetHeimdallId(&_Rootchain.TransactOpts, _heimdallId)
}

// SetHeimdallId is a paid mutator transaction binding the contract method 0xea0688b3.
//
// Solidity: function setHeimdallId(string _heimdallId) returns()
func (_Rootchain *RootchainTransactorSession) SetHeimdallId(_heimdallId string) (*types.Transaction, error) {
	return _Rootchain.Contract.SetHeimdallId(&_Rootchain.TransactOpts, _heimdallId)
}

// SetNextHeaderBlock is a paid mutator transaction binding the contract method 0xcf24a0ea.
//
// Solidity: function setNextHeaderBlock(uint256 _value) returns()
func (_Rootchain *RootchainTransactor) SetNextHeaderBlock(opts *bind.TransactOpts, _value *big.Int) (*types.Transaction, error) {
	return _Rootchain.contract.Transact(opts, "setNextHeaderBlock", _value)
}

// SetNextHeaderBlock is a paid mutator transaction binding the contract method 0xcf24a0ea.
//
// Solidity: function setNextHeaderBlock(uint256 _value) returns()
func (_Rootchain *RootchainSession) SetNextHeaderBlock(_value *big.Int) (*types.Transaction, error) {
	return _Rootchain.Contract.SetNextHeaderBlock(&_Rootchain.TransactOpts, _value)
}

// SetNextHeaderBlock is a paid mutator transaction binding the contract method 0xcf24a0ea.
//
// Solidity: function setNextHeaderBlock(uint256 _value) returns()
func (_Rootchain *RootchainTransactorSession) SetNextHeaderBlock(_value *big.Int) (*types.Transaction, error) {
	return _Rootchain.Contract.SetNextHeaderBlock(&_Rootchain.TransactOpts, _value)
}

// Slash is a paid mutator transaction binding the contract method 0x2da25de3.
//
// Solidity: function slash() returns()
func (_Rootchain *RootchainTransactor) Slash(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Rootchain.contract.Transact(opts, "slash")
}

// Slash is a paid mutator transaction binding the contract method 0x2da25de3.
//
// Solidity: function slash() returns()
func (_Rootchain *RootchainSession) Slash() (*types.Transaction, error) {
	return _Rootchain.Contract.Slash(&_Rootchain.TransactOpts)
}

// Slash is a paid mutator transaction binding the contract method 0x2da25de3.
//
// Solidity: function slash() returns()
func (_Rootchain *RootchainTransactorSession) Slash() (*types.Transaction, error) {
	return _Rootchain.Contract.Slash(&_Rootchain.TransactOpts)
}

// SubmitCheckpoint is a paid mutator transaction binding the contract method 0x19338670.
//
// Solidity: function submitCheckpoint(bytes data, uint256[] validatorIds, bytes signatures) returns()
func (_Rootchain *RootchainTransactor) SubmitCheckpoint(opts *bind.TransactOpts, data []byte, validatorIds []*big.Int, signatures []byte) (*types.Transaction, error) {
	return _Rootchain.contract.Transact(opts, "submitCheckpoint", data, validatorIds, signatures)
}

// SubmitCheckpoint is a paid mutator transaction binding the contract method 0x19338670.
//
// Solidity: function submitCheckpoint(bytes data, uint256[] validatorIds, bytes signatures) returns()
func (_Rootchain *RootchainSession) SubmitCheckpoint(data []byte, validatorIds []*big.Int, signatures []byte) (*types.Transaction, error) {
	return _Rootchain.Contract.SubmitCheckpoint(&_Rootchain.TransactOpts, data, validatorIds, signatures)
}

// SubmitCheckpoint is a paid mutator transaction binding the contract method 0x19338670.
//
// Solidity: function submitCheckpoint(bytes data, uint256[] validatorIds, bytes signatures) returns()
func (_Rootchain *RootchainTransactorSession) SubmitCheckpoint(data []byte, validatorIds []*big.Int, signatures []byte) (*types.Transaction, error) {
	return _Rootchain.Contract.SubmitCheckpoint(&_Rootchain.TransactOpts, data, validatorIds, signatures)
}

// SubmitHeaderBlock is a paid mutator transaction binding the contract method 0x6a791f11.
//
// Solidity: function submitHeaderBlock(bytes data, bytes sigs) returns()
func (_Rootchain *RootchainTransactor) SubmitHeaderBlock(opts *bind.TransactOpts, data []byte, sigs []byte) (*types.Transaction, error) {
	return _Rootchain.contract.Transact(opts, "submitHeaderBlock", data, sigs)
}

// SubmitHeaderBlock is a paid mutator transaction binding the contract method 0x6a791f11.
//
// Solidity: function submitHeaderBlock(bytes data, bytes sigs) returns()
func (_Rootchain *RootchainSession) SubmitHeaderBlock(data []byte, sigs []byte) (*types.Transaction, error) {
	return _Rootchain.Contract.SubmitHeaderBlock(&_Rootchain.TransactOpts, data, sigs)
}

// SubmitHeaderBlock is a paid mutator transaction binding the contract method 0x6a791f11.
//
// Solidity: function submitHeaderBlock(bytes data, bytes sigs) returns()
func (_Rootchain *RootchainTransactorSession) SubmitHeaderBlock(data []byte, sigs []byte) (*types.Transaction, error) {
	return _Rootchain.Contract.SubmitHeaderBlock(&_Rootchain.TransactOpts, data, sigs)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_Rootchain *RootchainTransactor) TransferOwnership(opts *bind.TransactOpts, newOwner common.Address) (*types.Transaction, error) {
	return _Rootchain.contract.Transact(opts, "transferOwnership", newOwner)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_Rootchain *RootchainSession) TransferOwnership(newOwner common.Address) (*types.Transaction, error) {
	return _Rootchain.Contract.TransferOwnership(&_Rootchain.TransactOpts, newOwner)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_Rootchain *RootchainTransactorSession) TransferOwnership(newOwner common.Address) (*types.Transaction, error) {
	return _Rootchain.Contract.TransferOwnership(&_Rootchain.TransactOpts, newOwner)
}

// UpdateDepositId is a paid mutator transaction binding the contract method 0x5391f483.
//
// Solidity: function updateDepositId(uint256 numDeposits) returns(uint256 depositId)
func (_Rootchain *RootchainTransactor) UpdateDepositId(opts *bind.TransactOpts, numDeposits *big.Int) (*types.Transaction, error) {
	return _Rootchain.contract.Transact(opts, "updateDepositId", numDeposits)
}

// UpdateDepositId is a paid mutator transaction binding the contract method 0x5391f483.
//
// Solidity: function updateDepositId(uint256 numDeposits) returns(uint256 depositId)
func (_Rootchain *RootchainSession) UpdateDepositId(numDeposits *big.Int) (*types.Transaction, error) {
	return _Rootchain.Contract.UpdateDepositId(&_Rootchain.TransactOpts, numDeposits)
}

// UpdateDepositId is a paid mutator transaction binding the contract method 0x5391f483.
//
// Solidity: function updateDepositId(uint256 numDeposits) returns(uint256 depositId)
func (_Rootchain *RootchainTransactorSession) UpdateDepositId(numDeposits *big.Int) (*types.Transaction, error) {
	return _Rootchain.Contract.UpdateDepositId(&_Rootchain.TransactOpts, numDeposits)
}

// RootchainNewHeaderBlockIterator is returned from FilterNewHeaderBlock and is used to iterate over the raw logs and unpacked data for NewHeaderBlock events raised by the Rootchain contract.
type RootchainNewHeaderBlockIterator struct {
	Event *RootchainNewHeaderBlock // Event containing the contract specifics and raw log

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
func (it *RootchainNewHeaderBlockIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(RootchainNewHeaderBlock)
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
		it.Event = new(RootchainNewHeaderBlock)
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
func (it *RootchainNewHeaderBlockIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *RootchainNewHeaderBlockIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// RootchainNewHeaderBlock represents a NewHeaderBlock event raised by the Rootchain contract.
type RootchainNewHeaderBlock struct {
	Proposer      common.Address
	HeaderBlockId *big.Int
	Reward        *big.Int
	Start         *big.Int
	End           *big.Int
	Root          [32]byte
	Raw           types.Log // Blockchain specific contextual infos
}

// FilterNewHeaderBlock is a free log retrieval operation binding the contract event 0xba5de06d22af2685c6c7765f60067f7d2b08c2d29f53cdf14d67f6d1c9bfb527.
//
// Solidity: event NewHeaderBlock(address indexed proposer, uint256 indexed headerBlockId, uint256 indexed reward, uint256 start, uint256 end, bytes32 root)
func (_Rootchain *RootchainFilterer) FilterNewHeaderBlock(opts *bind.FilterOpts, proposer []common.Address, headerBlockId []*big.Int, reward []*big.Int) (*RootchainNewHeaderBlockIterator, error) {

	var proposerRule []interface{}
	for _, proposerItem := range proposer {
		proposerRule = append(proposerRule, proposerItem)
	}
	var headerBlockIdRule []interface{}
	for _, headerBlockIdItem := range headerBlockId {
		headerBlockIdRule = append(headerBlockIdRule, headerBlockIdItem)
	}
	var rewardRule []interface{}
	for _, rewardItem := range reward {
		rewardRule = append(rewardRule, rewardItem)
	}

	logs, sub, err := _Rootchain.contract.FilterLogs(opts, "NewHeaderBlock", proposerRule, headerBlockIdRule, rewardRule)
	if err != nil {
		return nil, err
	}
	return &RootchainNewHeaderBlockIterator{contract: _Rootchain.contract, event: "NewHeaderBlock", logs: logs, sub: sub}, nil
}

// WatchNewHeaderBlock is a free log subscription operation binding the contract event 0xba5de06d22af2685c6c7765f60067f7d2b08c2d29f53cdf14d67f6d1c9bfb527.
//
// Solidity: event NewHeaderBlock(address indexed proposer, uint256 indexed headerBlockId, uint256 indexed reward, uint256 start, uint256 end, bytes32 root)
func (_Rootchain *RootchainFilterer) WatchNewHeaderBlock(opts *bind.WatchOpts, sink chan<- *RootchainNewHeaderBlock, proposer []common.Address, headerBlockId []*big.Int, reward []*big.Int) (event.Subscription, error) {

	var proposerRule []interface{}
	for _, proposerItem := range proposer {
		proposerRule = append(proposerRule, proposerItem)
	}
	var headerBlockIdRule []interface{}
	for _, headerBlockIdItem := range headerBlockId {
		headerBlockIdRule = append(headerBlockIdRule, headerBlockIdItem)
	}
	var rewardRule []interface{}
	for _, rewardItem := range reward {
		rewardRule = append(rewardRule, rewardItem)
	}

	logs, sub, err := _Rootchain.contract.WatchLogs(opts, "NewHeaderBlock", proposerRule, headerBlockIdRule, rewardRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(RootchainNewHeaderBlock)
				if err := _Rootchain.contract.UnpackLog(event, "NewHeaderBlock", log); err != nil {
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

// ParseNewHeaderBlock is a log parse operation binding the contract event 0xba5de06d22af2685c6c7765f60067f7d2b08c2d29f53cdf14d67f6d1c9bfb527.
//
// Solidity: event NewHeaderBlock(address indexed proposer, uint256 indexed headerBlockId, uint256 indexed reward, uint256 start, uint256 end, bytes32 root)
func (_Rootchain *RootchainFilterer) ParseNewHeaderBlock(log types.Log) (*RootchainNewHeaderBlock, error) {
	event := new(RootchainNewHeaderBlock)
	if err := _Rootchain.contract.UnpackLog(event, "NewHeaderBlock", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// RootchainOwnershipTransferredIterator is returned from FilterOwnershipTransferred and is used to iterate over the raw logs and unpacked data for OwnershipTransferred events raised by the Rootchain contract.
type RootchainOwnershipTransferredIterator struct {
	Event *RootchainOwnershipTransferred // Event containing the contract specifics and raw log

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
func (it *RootchainOwnershipTransferredIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(RootchainOwnershipTransferred)
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
		it.Event = new(RootchainOwnershipTransferred)
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
func (it *RootchainOwnershipTransferredIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *RootchainOwnershipTransferredIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// RootchainOwnershipTransferred represents a OwnershipTransferred event raised by the Rootchain contract.
type RootchainOwnershipTransferred struct {
	PreviousOwner common.Address
	NewOwner      common.Address
	Raw           types.Log // Blockchain specific contextual infos
}

// FilterOwnershipTransferred is a free log retrieval operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
//
// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
func (_Rootchain *RootchainFilterer) FilterOwnershipTransferred(opts *bind.FilterOpts, previousOwner []common.Address, newOwner []common.Address) (*RootchainOwnershipTransferredIterator, error) {

	var previousOwnerRule []interface{}
	for _, previousOwnerItem := range previousOwner {
		previousOwnerRule = append(previousOwnerRule, previousOwnerItem)
	}
	var newOwnerRule []interface{}
	for _, newOwnerItem := range newOwner {
		newOwnerRule = append(newOwnerRule, newOwnerItem)
	}

	logs, sub, err := _Rootchain.contract.FilterLogs(opts, "OwnershipTransferred", previousOwnerRule, newOwnerRule)
	if err != nil {
		return nil, err
	}
	return &RootchainOwnershipTransferredIterator{contract: _Rootchain.contract, event: "OwnershipTransferred", logs: logs, sub: sub}, nil
}

// WatchOwnershipTransferred is a free log subscription operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
//
// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
func (_Rootchain *RootchainFilterer) WatchOwnershipTransferred(opts *bind.WatchOpts, sink chan<- *RootchainOwnershipTransferred, previousOwner []common.Address, newOwner []common.Address) (event.Subscription, error) {

	var previousOwnerRule []interface{}
	for _, previousOwnerItem := range previousOwner {
		previousOwnerRule = append(previousOwnerRule, previousOwnerItem)
	}
	var newOwnerRule []interface{}
	for _, newOwnerItem := range newOwner {
		newOwnerRule = append(newOwnerRule, newOwnerItem)
	}

	logs, sub, err := _Rootchain.contract.WatchLogs(opts, "OwnershipTransferred", previousOwnerRule, newOwnerRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(RootchainOwnershipTransferred)
				if err := _Rootchain.contract.UnpackLog(event, "OwnershipTransferred", log); err != nil {
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

// ParseOwnershipTransferred is a log parse operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
//
// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
func (_Rootchain *RootchainFilterer) ParseOwnershipTransferred(log types.Log) (*RootchainOwnershipTransferred, error) {
	event := new(RootchainOwnershipTransferred)
	if err := _Rootchain.contract.UnpackLog(event, "OwnershipTransferred", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// RootchainResetHeaderBlockIterator is returned from FilterResetHeaderBlock and is used to iterate over the raw logs and unpacked data for ResetHeaderBlock events raised by the Rootchain contract.
type RootchainResetHeaderBlockIterator struct {
	Event *RootchainResetHeaderBlock // Event containing the contract specifics and raw log

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
func (it *RootchainResetHeaderBlockIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(RootchainResetHeaderBlock)
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
		it.Event = new(RootchainResetHeaderBlock)
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
func (it *RootchainResetHeaderBlockIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *RootchainResetHeaderBlockIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// RootchainResetHeaderBlock represents a ResetHeaderBlock event raised by the Rootchain contract.
type RootchainResetHeaderBlock struct {
	Proposer      common.Address
	HeaderBlockId *big.Int
	Raw           types.Log // Blockchain specific contextual infos
}

// FilterResetHeaderBlock is a free log retrieval operation binding the contract event 0xca1d8316287f938830e225956a7bb10fd5a1a1506dd2eb3a476751a488117205.
//
// Solidity: event ResetHeaderBlock(address indexed proposer, uint256 indexed headerBlockId)
func (_Rootchain *RootchainFilterer) FilterResetHeaderBlock(opts *bind.FilterOpts, proposer []common.Address, headerBlockId []*big.Int) (*RootchainResetHeaderBlockIterator, error) {

	var proposerRule []interface{}
	for _, proposerItem := range proposer {
		proposerRule = append(proposerRule, proposerItem)
	}
	var headerBlockIdRule []interface{}
	for _, headerBlockIdItem := range headerBlockId {
		headerBlockIdRule = append(headerBlockIdRule, headerBlockIdItem)
	}

	logs, sub, err := _Rootchain.contract.FilterLogs(opts, "ResetHeaderBlock", proposerRule, headerBlockIdRule)
	if err != nil {
		return nil, err
	}
	return &RootchainResetHeaderBlockIterator{contract: _Rootchain.contract, event: "ResetHeaderBlock", logs: logs, sub: sub}, nil
}

// WatchResetHeaderBlock is a free log subscription operation binding the contract event 0xca1d8316287f938830e225956a7bb10fd5a1a1506dd2eb3a476751a488117205.
//
// Solidity: event ResetHeaderBlock(address indexed proposer, uint256 indexed headerBlockId)
func (_Rootchain *RootchainFilterer) WatchResetHeaderBlock(opts *bind.WatchOpts, sink chan<- *RootchainResetHeaderBlock, proposer []common.Address, headerBlockId []*big.Int) (event.Subscription, error) {

	var proposerRule []interface{}
	for _, proposerItem := range proposer {
		proposerRule = append(proposerRule, proposerItem)
	}
	var headerBlockIdRule []interface{}
	for _, headerBlockIdItem := range headerBlockId {
		headerBlockIdRule = append(headerBlockIdRule, headerBlockIdItem)
	}

	logs, sub, err := _Rootchain.contract.WatchLogs(opts, "ResetHeaderBlock", proposerRule, headerBlockIdRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(RootchainResetHeaderBlock)
				if err := _Rootchain.contract.UnpackLog(event, "ResetHeaderBlock", log); err != nil {
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

// ParseResetHeaderBlock is a log parse operation binding the contract event 0xca1d8316287f938830e225956a7bb10fd5a1a1506dd2eb3a476751a488117205.
//
// Solidity: event ResetHeaderBlock(address indexed proposer, uint256 indexed headerBlockId)
func (_Rootchain *RootchainFilterer) ParseResetHeaderBlock(log types.Log) (*RootchainResetHeaderBlock, error) {
	event := new(RootchainResetHeaderBlock)
	if err := _Rootchain.contract.UnpackLog(event, "ResetHeaderBlock", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}
