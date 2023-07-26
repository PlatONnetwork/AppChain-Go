// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package stakinginfo

import (
	"errors"
	"math/big"
	"strings"

	appchain "github.com/PlatONnetwork/AppChain-Go"
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
	_ = appchain.NotFound
	_ = bind.Bind
	_ = common.Big1
	_ = types.BloomLookup
	_ = event.NewSubscription
)

// StakinginfoMetaData contains all meta data concerning the Stakinginfo contract.
var StakinginfoMetaData = &bind.MetaData{
	ABI: "[{\"inputs\":[{\"internalType\":\"address\",\"name\":\"_registry\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"user\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"fee\",\"type\":\"uint256\"}],\"name\":\"ClaimFee\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"validatorId\",\"type\":\"uint256\"},{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"},{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"totalAmount\",\"type\":\"uint256\"}],\"name\":\"ClaimRewards\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"newValidatorId\",\"type\":\"uint256\"},{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"oldValidatorId\",\"type\":\"uint256\"},{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"}],\"name\":\"ConfirmAuction\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"validatorId\",\"type\":\"uint256\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"user\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"rewards\",\"type\":\"uint256\"}],\"name\":\"DelegatorClaimedRewards\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"validatorId\",\"type\":\"uint256\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"user\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"totalStaked\",\"type\":\"uint256\"}],\"name\":\"DelegatorRestaked\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"validatorId\",\"type\":\"uint256\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"user\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"}],\"name\":\"DelegatorUnstaked\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"newDynasty\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"oldDynasty\",\"type\":\"uint256\"}],\"name\":\"DynastyValueChange\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"validatorId\",\"type\":\"uint256\"},{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"exitEpoch\",\"type\":\"uint256\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"signer\",\"type\":\"address\"}],\"name\":\"Jailed\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"previousOwner\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"newOwner\",\"type\":\"address\"}],\"name\":\"OwnershipTransferred\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"newProposerBonus\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"oldProposerBonus\",\"type\":\"uint256\"}],\"name\":\"ProposerBonusChange\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"validatorId\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"total\",\"type\":\"uint256\"}],\"name\":\"Restaked\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"newReward\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"oldReward\",\"type\":\"uint256\"}],\"name\":\"RewardUpdate\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"validatorId\",\"type\":\"uint256\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"user\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"tokens\",\"type\":\"uint256\"}],\"name\":\"ShareBurned\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"validatorId\",\"type\":\"uint256\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"user\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"tokens\",\"type\":\"uint256\"}],\"name\":\"ShareMinted\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"validatorId\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"nonce\",\"type\":\"uint256\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"oldSigner\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"newSigner\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"bytes\",\"name\":\"signerPubkey\",\"type\":\"bytes\"}],\"name\":\"SignerChange\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"epoch\",\"type\":\"uint256\"},{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"}],\"name\":\"Slashed\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"validatorId\",\"type\":\"uint256\"},{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"nonce\",\"type\":\"uint256\"},{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"newAmount\",\"type\":\"uint256\"}],\"name\":\"StakeUpdate\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"signer\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"address\",\"name\":\"owner\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"validatorId\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"nonce\",\"type\":\"uint256\"},{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"activationEpoch\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"total\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"bytes\",\"name\":\"pubkeys\",\"type\":\"bytes\"}],\"name\":\"Staked\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"validatorId\",\"type\":\"uint256\"},{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"},{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"auctionAmount\",\"type\":\"uint256\"}],\"name\":\"StartAuction\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"newThreshold\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"oldThreshold\",\"type\":\"uint256\"}],\"name\":\"ThresholdChange\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"user\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"fee\",\"type\":\"uint256\"}],\"name\":\"TopUpFee\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"validatorId\",\"type\":\"uint256\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"signer\",\"type\":\"address\"}],\"name\":\"UnJailed\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"user\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"validatorId\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"nonce\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"deactivationEpoch\",\"type\":\"uint256\"},{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"}],\"name\":\"UnstakeInit\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"user\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"validatorId\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"total\",\"type\":\"uint256\"}],\"name\":\"Unstaked\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"validatorId\",\"type\":\"uint256\"},{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"newCommissionRate\",\"type\":\"uint256\"},{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"oldCommissionRate\",\"type\":\"uint256\"}],\"name\":\"UpdateCommissionRate\",\"type\":\"event\"},{\"constant\":true,\"inputs\":[],\"name\":\"isOwner\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"owner\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"registry\",\"outputs\":[{\"internalType\":\"contractRegistry\",\"name\":\"\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[],\"name\":\"renounceOwnership\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"internalType\":\"address\",\"name\":\"newOwner\",\"type\":\"address\"}],\"name\":\"transferOwnership\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"validatorNonce\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"internalType\":\"uint256[]\",\"name\":\"validatorIds\",\"type\":\"uint256[]\"},{\"internalType\":\"uint256[]\",\"name\":\"nonces\",\"type\":\"uint256[]\"}],\"name\":\"updateNonce\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"internalType\":\"address\",\"name\":\"signer\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"owner\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"validatorId\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"activationEpoch\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"total\",\"type\":\"uint256\"},{\"internalType\":\"bytes\",\"name\":\"pubkeys\",\"type\":\"bytes\"}],\"name\":\"logStaked\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"internalType\":\"address\",\"name\":\"user\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"validatorId\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"total\",\"type\":\"uint256\"}],\"name\":\"logUnstaked\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"internalType\":\"address\",\"name\":\"user\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"validatorId\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"deactivationEpoch\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"}],\"name\":\"logUnstakeInit\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"validatorId\",\"type\":\"uint256\"},{\"internalType\":\"address\",\"name\":\"oldSigner\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"newSigner\",\"type\":\"address\"},{\"internalType\":\"bytes\",\"name\":\"signerPubkey\",\"type\":\"bytes\"}],\"name\":\"logSignerChange\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"validatorId\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"total\",\"type\":\"uint256\"}],\"name\":\"logRestaked\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"validatorId\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"exitEpoch\",\"type\":\"uint256\"},{\"internalType\":\"address\",\"name\":\"signer\",\"type\":\"address\"}],\"name\":\"logJailed\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"validatorId\",\"type\":\"uint256\"},{\"internalType\":\"address\",\"name\":\"signer\",\"type\":\"address\"}],\"name\":\"logUnjailed\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"epoch\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"}],\"name\":\"logSlashed\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"newThreshold\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"oldThreshold\",\"type\":\"uint256\"}],\"name\":\"logThresholdChange\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"newDynasty\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"oldDynasty\",\"type\":\"uint256\"}],\"name\":\"logDynastyValueChange\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"newProposerBonus\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"oldProposerBonus\",\"type\":\"uint256\"}],\"name\":\"logProposerBonusChange\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"newReward\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"oldReward\",\"type\":\"uint256\"}],\"name\":\"logRewardUpdate\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"validatorId\",\"type\":\"uint256\"}],\"name\":\"logStakeUpdate\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"validatorId\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"totalAmount\",\"type\":\"uint256\"}],\"name\":\"logClaimRewards\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"validatorId\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"auctionAmount\",\"type\":\"uint256\"}],\"name\":\"logStartAuction\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"newValidatorId\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"oldValidatorId\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"}],\"name\":\"logConfirmAuction\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"internalType\":\"address\",\"name\":\"user\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"fee\",\"type\":\"uint256\"}],\"name\":\"logTopUpFee\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"internalType\":\"address\",\"name\":\"user\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"fee\",\"type\":\"uint256\"}],\"name\":\"logClaimFee\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"validatorId\",\"type\":\"uint256\"}],\"name\":\"getStakerDetails\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"reward\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"activationEpoch\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"deactivationEpoch\",\"type\":\"uint256\"},{\"internalType\":\"address\",\"name\":\"signer\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"_status\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"validatorId\",\"type\":\"uint256\"}],\"name\":\"totalValidatorStake\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"validatorStake\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"getAccountStateRoot\",\"outputs\":[{\"internalType\":\"bytes32\",\"name\":\"accountStateRoot\",\"type\":\"bytes32\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"validatorId\",\"type\":\"uint256\"}],\"name\":\"getValidatorContractAddress\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"ValidatorContract\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"validatorId\",\"type\":\"uint256\"},{\"internalType\":\"address\",\"name\":\"user\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"tokens\",\"type\":\"uint256\"}],\"name\":\"logShareMinted\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"validatorId\",\"type\":\"uint256\"},{\"internalType\":\"address\",\"name\":\"user\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"tokens\",\"type\":\"uint256\"}],\"name\":\"logShareBurned\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"validatorId\",\"type\":\"uint256\"},{\"internalType\":\"address\",\"name\":\"user\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"rewards\",\"type\":\"uint256\"}],\"name\":\"logDelegatorClaimRewards\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"validatorId\",\"type\":\"uint256\"},{\"internalType\":\"address\",\"name\":\"user\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"totalStaked\",\"type\":\"uint256\"}],\"name\":\"logDelegatorRestaked\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"validatorId\",\"type\":\"uint256\"},{\"internalType\":\"address\",\"name\":\"user\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"}],\"name\":\"logDelegatorUnstaked\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"validatorId\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"newCommissionRate\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"oldCommissionRate\",\"type\":\"uint256\"}],\"name\":\"logUpdateCommissionRate\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]",
}

// StakinginfoABI is the input ABI used to generate the binding from.
// Deprecated: Use StakinginfoMetaData.ABI instead.
var StakinginfoABI = StakinginfoMetaData.ABI

// Stakinginfo is an auto generated Go binding around an Ethereum contract.
type Stakinginfo struct {
	StakinginfoCaller     // Read-only binding to the contract
	StakinginfoTransactor // Write-only binding to the contract
	StakinginfoFilterer   // Log filterer for contract events
}

// StakinginfoCaller is an auto generated read-only Go binding around an Ethereum contract.
type StakinginfoCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// StakinginfoTransactor is an auto generated write-only Go binding around an Ethereum contract.
type StakinginfoTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// StakinginfoFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type StakinginfoFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// StakinginfoSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type StakinginfoSession struct {
	Contract     *Stakinginfo      // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// StakinginfoCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type StakinginfoCallerSession struct {
	Contract *StakinginfoCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts      // Call options to use throughout this session
}

// StakinginfoTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type StakinginfoTransactorSession struct {
	Contract     *StakinginfoTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts      // Transaction auth options to use throughout this session
}

// StakinginfoRaw is an auto generated low-level Go binding around an Ethereum contract.
type StakinginfoRaw struct {
	Contract *Stakinginfo // Generic contract binding to access the raw methods on
}

// StakinginfoCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type StakinginfoCallerRaw struct {
	Contract *StakinginfoCaller // Generic read-only contract binding to access the raw methods on
}

// StakinginfoTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type StakinginfoTransactorRaw struct {
	Contract *StakinginfoTransactor // Generic write-only contract binding to access the raw methods on
}

// NewStakinginfo creates a new instance of Stakinginfo, bound to a specific deployed contract.
func NewStakinginfo(address common.Address, backend bind.ContractBackend) (*Stakinginfo, error) {
	contract, err := bindStakinginfo(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &Stakinginfo{StakinginfoCaller: StakinginfoCaller{contract: contract}, StakinginfoTransactor: StakinginfoTransactor{contract: contract}, StakinginfoFilterer: StakinginfoFilterer{contract: contract}}, nil
}

// NewStakinginfoCaller creates a new read-only instance of Stakinginfo, bound to a specific deployed contract.
func NewStakinginfoCaller(address common.Address, caller bind.ContractCaller) (*StakinginfoCaller, error) {
	contract, err := bindStakinginfo(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &StakinginfoCaller{contract: contract}, nil
}

// NewStakinginfoTransactor creates a new write-only instance of Stakinginfo, bound to a specific deployed contract.
func NewStakinginfoTransactor(address common.Address, transactor bind.ContractTransactor) (*StakinginfoTransactor, error) {
	contract, err := bindStakinginfo(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &StakinginfoTransactor{contract: contract}, nil
}

// NewStakinginfoFilterer creates a new log filterer instance of Stakinginfo, bound to a specific deployed contract.
func NewStakinginfoFilterer(address common.Address, filterer bind.ContractFilterer) (*StakinginfoFilterer, error) {
	contract, err := bindStakinginfo(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &StakinginfoFilterer{contract: contract}, nil
}

// bindStakinginfo binds a generic wrapper to an already deployed contract.
func bindStakinginfo(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(StakinginfoABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Stakinginfo *StakinginfoRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Stakinginfo.Contract.StakinginfoCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Stakinginfo *StakinginfoRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Stakinginfo.Contract.StakinginfoTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Stakinginfo *StakinginfoRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Stakinginfo.Contract.StakinginfoTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Stakinginfo *StakinginfoCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Stakinginfo.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Stakinginfo *StakinginfoTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Stakinginfo.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Stakinginfo *StakinginfoTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Stakinginfo.Contract.contract.Transact(opts, method, params...)
}

// GetAccountStateRoot is a free data retrieval call binding the contract method 0x4b6b87ce.
//
// Solidity: function getAccountStateRoot() view returns(bytes32 accountStateRoot)
func (_Stakinginfo *StakinginfoCaller) GetAccountStateRoot(opts *bind.CallOpts) ([32]byte, error) {
	var out []interface{}
	err := _Stakinginfo.contract.Call(opts, &out, "getAccountStateRoot")

	if err != nil {
		return *new([32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)

	return out0, err

}

// GetAccountStateRoot is a free data retrieval call binding the contract method 0x4b6b87ce.
//
// Solidity: function getAccountStateRoot() view returns(bytes32 accountStateRoot)
func (_Stakinginfo *StakinginfoSession) GetAccountStateRoot() ([32]byte, error) {
	return _Stakinginfo.Contract.GetAccountStateRoot(&_Stakinginfo.CallOpts)
}

// GetAccountStateRoot is a free data retrieval call binding the contract method 0x4b6b87ce.
//
// Solidity: function getAccountStateRoot() view returns(bytes32 accountStateRoot)
func (_Stakinginfo *StakinginfoCallerSession) GetAccountStateRoot() ([32]byte, error) {
	return _Stakinginfo.Contract.GetAccountStateRoot(&_Stakinginfo.CallOpts)
}

// GetStakerDetails is a free data retrieval call binding the contract method 0x78daaf69.
//
// Solidity: function getStakerDetails(uint256 validatorId) view returns(uint256 amount, uint256 reward, uint256 activationEpoch, uint256 deactivationEpoch, address signer, uint256 _status)
func (_Stakinginfo *StakinginfoCaller) GetStakerDetails(opts *bind.CallOpts, validatorId *big.Int) (struct {
	Amount            *big.Int
	Reward            *big.Int
	ActivationEpoch   *big.Int
	DeactivationEpoch *big.Int
	Signer            common.Address
	Status            *big.Int
}, error) {
	var out []interface{}
	err := _Stakinginfo.contract.Call(opts, &out, "getStakerDetails", validatorId)

	outstruct := new(struct {
		Amount            *big.Int
		Reward            *big.Int
		ActivationEpoch   *big.Int
		DeactivationEpoch *big.Int
		Signer            common.Address
		Status            *big.Int
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.Amount = *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)
	outstruct.Reward = *abi.ConvertType(out[1], new(*big.Int)).(**big.Int)
	outstruct.ActivationEpoch = *abi.ConvertType(out[2], new(*big.Int)).(**big.Int)
	outstruct.DeactivationEpoch = *abi.ConvertType(out[3], new(*big.Int)).(**big.Int)
	outstruct.Signer = *abi.ConvertType(out[4], new(common.Address)).(*common.Address)
	outstruct.Status = *abi.ConvertType(out[5], new(*big.Int)).(**big.Int)

	return *outstruct, err

}

// GetStakerDetails is a free data retrieval call binding the contract method 0x78daaf69.
//
// Solidity: function getStakerDetails(uint256 validatorId) view returns(uint256 amount, uint256 reward, uint256 activationEpoch, uint256 deactivationEpoch, address signer, uint256 _status)
func (_Stakinginfo *StakinginfoSession) GetStakerDetails(validatorId *big.Int) (struct {
	Amount            *big.Int
	Reward            *big.Int
	ActivationEpoch   *big.Int
	DeactivationEpoch *big.Int
	Signer            common.Address
	Status            *big.Int
}, error) {
	return _Stakinginfo.Contract.GetStakerDetails(&_Stakinginfo.CallOpts, validatorId)
}

// GetStakerDetails is a free data retrieval call binding the contract method 0x78daaf69.
//
// Solidity: function getStakerDetails(uint256 validatorId) view returns(uint256 amount, uint256 reward, uint256 activationEpoch, uint256 deactivationEpoch, address signer, uint256 _status)
func (_Stakinginfo *StakinginfoCallerSession) GetStakerDetails(validatorId *big.Int) (struct {
	Amount            *big.Int
	Reward            *big.Int
	ActivationEpoch   *big.Int
	DeactivationEpoch *big.Int
	Signer            common.Address
	Status            *big.Int
}, error) {
	return _Stakinginfo.Contract.GetStakerDetails(&_Stakinginfo.CallOpts, validatorId)
}

// GetValidatorContractAddress is a free data retrieval call binding the contract method 0x178d46aa.
//
// Solidity: function getValidatorContractAddress(uint256 validatorId) view returns(address ValidatorContract)
func (_Stakinginfo *StakinginfoCaller) GetValidatorContractAddress(opts *bind.CallOpts, validatorId *big.Int) (common.Address, error) {
	var out []interface{}
	err := _Stakinginfo.contract.Call(opts, &out, "getValidatorContractAddress", validatorId)

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// GetValidatorContractAddress is a free data retrieval call binding the contract method 0x178d46aa.
//
// Solidity: function getValidatorContractAddress(uint256 validatorId) view returns(address ValidatorContract)
func (_Stakinginfo *StakinginfoSession) GetValidatorContractAddress(validatorId *big.Int) (common.Address, error) {
	return _Stakinginfo.Contract.GetValidatorContractAddress(&_Stakinginfo.CallOpts, validatorId)
}

// GetValidatorContractAddress is a free data retrieval call binding the contract method 0x178d46aa.
//
// Solidity: function getValidatorContractAddress(uint256 validatorId) view returns(address ValidatorContract)
func (_Stakinginfo *StakinginfoCallerSession) GetValidatorContractAddress(validatorId *big.Int) (common.Address, error) {
	return _Stakinginfo.Contract.GetValidatorContractAddress(&_Stakinginfo.CallOpts, validatorId)
}

// IsOwner is a free data retrieval call binding the contract method 0x8f32d59b.
//
// Solidity: function isOwner() view returns(bool)
func (_Stakinginfo *StakinginfoCaller) IsOwner(opts *bind.CallOpts) (bool, error) {
	var out []interface{}
	err := _Stakinginfo.contract.Call(opts, &out, "isOwner")

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// IsOwner is a free data retrieval call binding the contract method 0x8f32d59b.
//
// Solidity: function isOwner() view returns(bool)
func (_Stakinginfo *StakinginfoSession) IsOwner() (bool, error) {
	return _Stakinginfo.Contract.IsOwner(&_Stakinginfo.CallOpts)
}

// IsOwner is a free data retrieval call binding the contract method 0x8f32d59b.
//
// Solidity: function isOwner() view returns(bool)
func (_Stakinginfo *StakinginfoCallerSession) IsOwner() (bool, error) {
	return _Stakinginfo.Contract.IsOwner(&_Stakinginfo.CallOpts)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_Stakinginfo *StakinginfoCaller) Owner(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _Stakinginfo.contract.Call(opts, &out, "owner")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_Stakinginfo *StakinginfoSession) Owner() (common.Address, error) {
	return _Stakinginfo.Contract.Owner(&_Stakinginfo.CallOpts)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_Stakinginfo *StakinginfoCallerSession) Owner() (common.Address, error) {
	return _Stakinginfo.Contract.Owner(&_Stakinginfo.CallOpts)
}

// Registry is a free data retrieval call binding the contract method 0x7b103999.
//
// Solidity: function registry() view returns(address)
func (_Stakinginfo *StakinginfoCaller) Registry(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _Stakinginfo.contract.Call(opts, &out, "registry")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// Registry is a free data retrieval call binding the contract method 0x7b103999.
//
// Solidity: function registry() view returns(address)
func (_Stakinginfo *StakinginfoSession) Registry() (common.Address, error) {
	return _Stakinginfo.Contract.Registry(&_Stakinginfo.CallOpts)
}

// Registry is a free data retrieval call binding the contract method 0x7b103999.
//
// Solidity: function registry() view returns(address)
func (_Stakinginfo *StakinginfoCallerSession) Registry() (common.Address, error) {
	return _Stakinginfo.Contract.Registry(&_Stakinginfo.CallOpts)
}

// TotalValidatorStake is a free data retrieval call binding the contract method 0xca7d34b6.
//
// Solidity: function totalValidatorStake(uint256 validatorId) view returns(uint256 validatorStake)
func (_Stakinginfo *StakinginfoCaller) TotalValidatorStake(opts *bind.CallOpts, validatorId *big.Int) (*big.Int, error) {
	var out []interface{}
	err := _Stakinginfo.contract.Call(opts, &out, "totalValidatorStake", validatorId)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// TotalValidatorStake is a free data retrieval call binding the contract method 0xca7d34b6.
//
// Solidity: function totalValidatorStake(uint256 validatorId) view returns(uint256 validatorStake)
func (_Stakinginfo *StakinginfoSession) TotalValidatorStake(validatorId *big.Int) (*big.Int, error) {
	return _Stakinginfo.Contract.TotalValidatorStake(&_Stakinginfo.CallOpts, validatorId)
}

// TotalValidatorStake is a free data retrieval call binding the contract method 0xca7d34b6.
//
// Solidity: function totalValidatorStake(uint256 validatorId) view returns(uint256 validatorStake)
func (_Stakinginfo *StakinginfoCallerSession) TotalValidatorStake(validatorId *big.Int) (*big.Int, error) {
	return _Stakinginfo.Contract.TotalValidatorStake(&_Stakinginfo.CallOpts, validatorId)
}

// ValidatorNonce is a free data retrieval call binding the contract method 0xebde9f93.
//
// Solidity: function validatorNonce(uint256 ) view returns(uint256)
func (_Stakinginfo *StakinginfoCaller) ValidatorNonce(opts *bind.CallOpts, arg0 *big.Int) (*big.Int, error) {
	var out []interface{}
	err := _Stakinginfo.contract.Call(opts, &out, "validatorNonce", arg0)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// ValidatorNonce is a free data retrieval call binding the contract method 0xebde9f93.
//
// Solidity: function validatorNonce(uint256 ) view returns(uint256)
func (_Stakinginfo *StakinginfoSession) ValidatorNonce(arg0 *big.Int) (*big.Int, error) {
	return _Stakinginfo.Contract.ValidatorNonce(&_Stakinginfo.CallOpts, arg0)
}

// ValidatorNonce is a free data retrieval call binding the contract method 0xebde9f93.
//
// Solidity: function validatorNonce(uint256 ) view returns(uint256)
func (_Stakinginfo *StakinginfoCallerSession) ValidatorNonce(arg0 *big.Int) (*big.Int, error) {
	return _Stakinginfo.Contract.ValidatorNonce(&_Stakinginfo.CallOpts, arg0)
}

// LogClaimFee is a paid mutator transaction binding the contract method 0x122b6481.
//
// Solidity: function logClaimFee(address user, uint256 fee) returns()
func (_Stakinginfo *StakinginfoTransactor) LogClaimFee(opts *bind.TransactOpts, user common.Address, fee *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.contract.Transact(opts, "logClaimFee", user, fee)
}

// LogClaimFee is a paid mutator transaction binding the contract method 0x122b6481.
//
// Solidity: function logClaimFee(address user, uint256 fee) returns()
func (_Stakinginfo *StakinginfoSession) LogClaimFee(user common.Address, fee *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.Contract.LogClaimFee(&_Stakinginfo.TransactOpts, user, fee)
}

// LogClaimFee is a paid mutator transaction binding the contract method 0x122b6481.
//
// Solidity: function logClaimFee(address user, uint256 fee) returns()
func (_Stakinginfo *StakinginfoTransactorSession) LogClaimFee(user common.Address, fee *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.Contract.LogClaimFee(&_Stakinginfo.TransactOpts, user, fee)
}

// LogClaimRewards is a paid mutator transaction binding the contract method 0xb685b26a.
//
// Solidity: function logClaimRewards(uint256 validatorId, uint256 amount, uint256 totalAmount) returns()
func (_Stakinginfo *StakinginfoTransactor) LogClaimRewards(opts *bind.TransactOpts, validatorId *big.Int, amount *big.Int, totalAmount *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.contract.Transact(opts, "logClaimRewards", validatorId, amount, totalAmount)
}

// LogClaimRewards is a paid mutator transaction binding the contract method 0xb685b26a.
//
// Solidity: function logClaimRewards(uint256 validatorId, uint256 amount, uint256 totalAmount) returns()
func (_Stakinginfo *StakinginfoSession) LogClaimRewards(validatorId *big.Int, amount *big.Int, totalAmount *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.Contract.LogClaimRewards(&_Stakinginfo.TransactOpts, validatorId, amount, totalAmount)
}

// LogClaimRewards is a paid mutator transaction binding the contract method 0xb685b26a.
//
// Solidity: function logClaimRewards(uint256 validatorId, uint256 amount, uint256 totalAmount) returns()
func (_Stakinginfo *StakinginfoTransactorSession) LogClaimRewards(validatorId *big.Int, amount *big.Int, totalAmount *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.Contract.LogClaimRewards(&_Stakinginfo.TransactOpts, validatorId, amount, totalAmount)
}

// LogConfirmAuction is a paid mutator transaction binding the contract method 0xe12ab1af.
//
// Solidity: function logConfirmAuction(uint256 newValidatorId, uint256 oldValidatorId, uint256 amount) returns()
func (_Stakinginfo *StakinginfoTransactor) LogConfirmAuction(opts *bind.TransactOpts, newValidatorId *big.Int, oldValidatorId *big.Int, amount *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.contract.Transact(opts, "logConfirmAuction", newValidatorId, oldValidatorId, amount)
}

// LogConfirmAuction is a paid mutator transaction binding the contract method 0xe12ab1af.
//
// Solidity: function logConfirmAuction(uint256 newValidatorId, uint256 oldValidatorId, uint256 amount) returns()
func (_Stakinginfo *StakinginfoSession) LogConfirmAuction(newValidatorId *big.Int, oldValidatorId *big.Int, amount *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.Contract.LogConfirmAuction(&_Stakinginfo.TransactOpts, newValidatorId, oldValidatorId, amount)
}

// LogConfirmAuction is a paid mutator transaction binding the contract method 0xe12ab1af.
//
// Solidity: function logConfirmAuction(uint256 newValidatorId, uint256 oldValidatorId, uint256 amount) returns()
func (_Stakinginfo *StakinginfoTransactorSession) LogConfirmAuction(newValidatorId *big.Int, oldValidatorId *big.Int, amount *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.Contract.LogConfirmAuction(&_Stakinginfo.TransactOpts, newValidatorId, oldValidatorId, amount)
}

// LogDelegatorClaimRewards is a paid mutator transaction binding the contract method 0xb7721d2d.
//
// Solidity: function logDelegatorClaimRewards(uint256 validatorId, address user, uint256 rewards) returns()
func (_Stakinginfo *StakinginfoTransactor) LogDelegatorClaimRewards(opts *bind.TransactOpts, validatorId *big.Int, user common.Address, rewards *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.contract.Transact(opts, "logDelegatorClaimRewards", validatorId, user, rewards)
}

// LogDelegatorClaimRewards is a paid mutator transaction binding the contract method 0xb7721d2d.
//
// Solidity: function logDelegatorClaimRewards(uint256 validatorId, address user, uint256 rewards) returns()
func (_Stakinginfo *StakinginfoSession) LogDelegatorClaimRewards(validatorId *big.Int, user common.Address, rewards *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.Contract.LogDelegatorClaimRewards(&_Stakinginfo.TransactOpts, validatorId, user, rewards)
}

// LogDelegatorClaimRewards is a paid mutator transaction binding the contract method 0xb7721d2d.
//
// Solidity: function logDelegatorClaimRewards(uint256 validatorId, address user, uint256 rewards) returns()
func (_Stakinginfo *StakinginfoTransactorSession) LogDelegatorClaimRewards(validatorId *big.Int, user common.Address, rewards *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.Contract.LogDelegatorClaimRewards(&_Stakinginfo.TransactOpts, validatorId, user, rewards)
}

// LogDelegatorRestaked is a paid mutator transaction binding the contract method 0x7f88a957.
//
// Solidity: function logDelegatorRestaked(uint256 validatorId, address user, uint256 totalStaked) returns()
func (_Stakinginfo *StakinginfoTransactor) LogDelegatorRestaked(opts *bind.TransactOpts, validatorId *big.Int, user common.Address, totalStaked *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.contract.Transact(opts, "logDelegatorRestaked", validatorId, user, totalStaked)
}

// LogDelegatorRestaked is a paid mutator transaction binding the contract method 0x7f88a957.
//
// Solidity: function logDelegatorRestaked(uint256 validatorId, address user, uint256 totalStaked) returns()
func (_Stakinginfo *StakinginfoSession) LogDelegatorRestaked(validatorId *big.Int, user common.Address, totalStaked *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.Contract.LogDelegatorRestaked(&_Stakinginfo.TransactOpts, validatorId, user, totalStaked)
}

// LogDelegatorRestaked is a paid mutator transaction binding the contract method 0x7f88a957.
//
// Solidity: function logDelegatorRestaked(uint256 validatorId, address user, uint256 totalStaked) returns()
func (_Stakinginfo *StakinginfoTransactorSession) LogDelegatorRestaked(validatorId *big.Int, user common.Address, totalStaked *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.Contract.LogDelegatorRestaked(&_Stakinginfo.TransactOpts, validatorId, user, totalStaked)
}

// LogDelegatorUnstaked is a paid mutator transaction binding the contract method 0x605be9be.
//
// Solidity: function logDelegatorUnstaked(uint256 validatorId, address user, uint256 amount) returns()
func (_Stakinginfo *StakinginfoTransactor) LogDelegatorUnstaked(opts *bind.TransactOpts, validatorId *big.Int, user common.Address, amount *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.contract.Transact(opts, "logDelegatorUnstaked", validatorId, user, amount)
}

// LogDelegatorUnstaked is a paid mutator transaction binding the contract method 0x605be9be.
//
// Solidity: function logDelegatorUnstaked(uint256 validatorId, address user, uint256 amount) returns()
func (_Stakinginfo *StakinginfoSession) LogDelegatorUnstaked(validatorId *big.Int, user common.Address, amount *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.Contract.LogDelegatorUnstaked(&_Stakinginfo.TransactOpts, validatorId, user, amount)
}

// LogDelegatorUnstaked is a paid mutator transaction binding the contract method 0x605be9be.
//
// Solidity: function logDelegatorUnstaked(uint256 validatorId, address user, uint256 amount) returns()
func (_Stakinginfo *StakinginfoTransactorSession) LogDelegatorUnstaked(validatorId *big.Int, user common.Address, amount *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.Contract.LogDelegatorUnstaked(&_Stakinginfo.TransactOpts, validatorId, user, amount)
}

// LogDynastyValueChange is a paid mutator transaction binding the contract method 0xa0e300a6.
//
// Solidity: function logDynastyValueChange(uint256 newDynasty, uint256 oldDynasty) returns()
func (_Stakinginfo *StakinginfoTransactor) LogDynastyValueChange(opts *bind.TransactOpts, newDynasty *big.Int, oldDynasty *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.contract.Transact(opts, "logDynastyValueChange", newDynasty, oldDynasty)
}

// LogDynastyValueChange is a paid mutator transaction binding the contract method 0xa0e300a6.
//
// Solidity: function logDynastyValueChange(uint256 newDynasty, uint256 oldDynasty) returns()
func (_Stakinginfo *StakinginfoSession) LogDynastyValueChange(newDynasty *big.Int, oldDynasty *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.Contract.LogDynastyValueChange(&_Stakinginfo.TransactOpts, newDynasty, oldDynasty)
}

// LogDynastyValueChange is a paid mutator transaction binding the contract method 0xa0e300a6.
//
// Solidity: function logDynastyValueChange(uint256 newDynasty, uint256 oldDynasty) returns()
func (_Stakinginfo *StakinginfoTransactorSession) LogDynastyValueChange(newDynasty *big.Int, oldDynasty *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.Contract.LogDynastyValueChange(&_Stakinginfo.TransactOpts, newDynasty, oldDynasty)
}

// LogJailed is a paid mutator transaction binding the contract method 0x81dc101b.
//
// Solidity: function logJailed(uint256 validatorId, uint256 exitEpoch, address signer) returns()
func (_Stakinginfo *StakinginfoTransactor) LogJailed(opts *bind.TransactOpts, validatorId *big.Int, exitEpoch *big.Int, signer common.Address) (*types.Transaction, error) {
	return _Stakinginfo.contract.Transact(opts, "logJailed", validatorId, exitEpoch, signer)
}

// LogJailed is a paid mutator transaction binding the contract method 0x81dc101b.
//
// Solidity: function logJailed(uint256 validatorId, uint256 exitEpoch, address signer) returns()
func (_Stakinginfo *StakinginfoSession) LogJailed(validatorId *big.Int, exitEpoch *big.Int, signer common.Address) (*types.Transaction, error) {
	return _Stakinginfo.Contract.LogJailed(&_Stakinginfo.TransactOpts, validatorId, exitEpoch, signer)
}

// LogJailed is a paid mutator transaction binding the contract method 0x81dc101b.
//
// Solidity: function logJailed(uint256 validatorId, uint256 exitEpoch, address signer) returns()
func (_Stakinginfo *StakinginfoTransactorSession) LogJailed(validatorId *big.Int, exitEpoch *big.Int, signer common.Address) (*types.Transaction, error) {
	return _Stakinginfo.Contract.LogJailed(&_Stakinginfo.TransactOpts, validatorId, exitEpoch, signer)
}

// LogProposerBonusChange is a paid mutator transaction binding the contract method 0xa3b1d8cb.
//
// Solidity: function logProposerBonusChange(uint256 newProposerBonus, uint256 oldProposerBonus) returns()
func (_Stakinginfo *StakinginfoTransactor) LogProposerBonusChange(opts *bind.TransactOpts, newProposerBonus *big.Int, oldProposerBonus *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.contract.Transact(opts, "logProposerBonusChange", newProposerBonus, oldProposerBonus)
}

// LogProposerBonusChange is a paid mutator transaction binding the contract method 0xa3b1d8cb.
//
// Solidity: function logProposerBonusChange(uint256 newProposerBonus, uint256 oldProposerBonus) returns()
func (_Stakinginfo *StakinginfoSession) LogProposerBonusChange(newProposerBonus *big.Int, oldProposerBonus *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.Contract.LogProposerBonusChange(&_Stakinginfo.TransactOpts, newProposerBonus, oldProposerBonus)
}

// LogProposerBonusChange is a paid mutator transaction binding the contract method 0xa3b1d8cb.
//
// Solidity: function logProposerBonusChange(uint256 newProposerBonus, uint256 oldProposerBonus) returns()
func (_Stakinginfo *StakinginfoTransactorSession) LogProposerBonusChange(newProposerBonus *big.Int, oldProposerBonus *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.Contract.LogProposerBonusChange(&_Stakinginfo.TransactOpts, newProposerBonus, oldProposerBonus)
}

// LogRestaked is a paid mutator transaction binding the contract method 0x5616a7cc.
//
// Solidity: function logRestaked(uint256 validatorId, uint256 amount, uint256 total) returns()
func (_Stakinginfo *StakinginfoTransactor) LogRestaked(opts *bind.TransactOpts, validatorId *big.Int, amount *big.Int, total *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.contract.Transact(opts, "logRestaked", validatorId, amount, total)
}

// LogRestaked is a paid mutator transaction binding the contract method 0x5616a7cc.
//
// Solidity: function logRestaked(uint256 validatorId, uint256 amount, uint256 total) returns()
func (_Stakinginfo *StakinginfoSession) LogRestaked(validatorId *big.Int, amount *big.Int, total *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.Contract.LogRestaked(&_Stakinginfo.TransactOpts, validatorId, amount, total)
}

// LogRestaked is a paid mutator transaction binding the contract method 0x5616a7cc.
//
// Solidity: function logRestaked(uint256 validatorId, uint256 amount, uint256 total) returns()
func (_Stakinginfo *StakinginfoTransactorSession) LogRestaked(validatorId *big.Int, amount *big.Int, total *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.Contract.LogRestaked(&_Stakinginfo.TransactOpts, validatorId, amount, total)
}

// LogRewardUpdate is a paid mutator transaction binding the contract method 0xb6fa74c4.
//
// Solidity: function logRewardUpdate(uint256 newReward, uint256 oldReward) returns()
func (_Stakinginfo *StakinginfoTransactor) LogRewardUpdate(opts *bind.TransactOpts, newReward *big.Int, oldReward *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.contract.Transact(opts, "logRewardUpdate", newReward, oldReward)
}

// LogRewardUpdate is a paid mutator transaction binding the contract method 0xb6fa74c4.
//
// Solidity: function logRewardUpdate(uint256 newReward, uint256 oldReward) returns()
func (_Stakinginfo *StakinginfoSession) LogRewardUpdate(newReward *big.Int, oldReward *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.Contract.LogRewardUpdate(&_Stakinginfo.TransactOpts, newReward, oldReward)
}

// LogRewardUpdate is a paid mutator transaction binding the contract method 0xb6fa74c4.
//
// Solidity: function logRewardUpdate(uint256 newReward, uint256 oldReward) returns()
func (_Stakinginfo *StakinginfoTransactorSession) LogRewardUpdate(newReward *big.Int, oldReward *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.Contract.LogRewardUpdate(&_Stakinginfo.TransactOpts, newReward, oldReward)
}

// LogShareBurned is a paid mutator transaction binding the contract method 0xf1382b53.
//
// Solidity: function logShareBurned(uint256 validatorId, address user, uint256 amount, uint256 tokens) returns()
func (_Stakinginfo *StakinginfoTransactor) LogShareBurned(opts *bind.TransactOpts, validatorId *big.Int, user common.Address, amount *big.Int, tokens *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.contract.Transact(opts, "logShareBurned", validatorId, user, amount, tokens)
}

// LogShareBurned is a paid mutator transaction binding the contract method 0xf1382b53.
//
// Solidity: function logShareBurned(uint256 validatorId, address user, uint256 amount, uint256 tokens) returns()
func (_Stakinginfo *StakinginfoSession) LogShareBurned(validatorId *big.Int, user common.Address, amount *big.Int, tokens *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.Contract.LogShareBurned(&_Stakinginfo.TransactOpts, validatorId, user, amount, tokens)
}

// LogShareBurned is a paid mutator transaction binding the contract method 0xf1382b53.
//
// Solidity: function logShareBurned(uint256 validatorId, address user, uint256 amount, uint256 tokens) returns()
func (_Stakinginfo *StakinginfoTransactorSession) LogShareBurned(validatorId *big.Int, user common.Address, amount *big.Int, tokens *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.Contract.LogShareBurned(&_Stakinginfo.TransactOpts, validatorId, user, amount, tokens)
}

// LogShareMinted is a paid mutator transaction binding the contract method 0xc69d0573.
//
// Solidity: function logShareMinted(uint256 validatorId, address user, uint256 amount, uint256 tokens) returns()
func (_Stakinginfo *StakinginfoTransactor) LogShareMinted(opts *bind.TransactOpts, validatorId *big.Int, user common.Address, amount *big.Int, tokens *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.contract.Transact(opts, "logShareMinted", validatorId, user, amount, tokens)
}

// LogShareMinted is a paid mutator transaction binding the contract method 0xc69d0573.
//
// Solidity: function logShareMinted(uint256 validatorId, address user, uint256 amount, uint256 tokens) returns()
func (_Stakinginfo *StakinginfoSession) LogShareMinted(validatorId *big.Int, user common.Address, amount *big.Int, tokens *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.Contract.LogShareMinted(&_Stakinginfo.TransactOpts, validatorId, user, amount, tokens)
}

// LogShareMinted is a paid mutator transaction binding the contract method 0xc69d0573.
//
// Solidity: function logShareMinted(uint256 validatorId, address user, uint256 amount, uint256 tokens) returns()
func (_Stakinginfo *StakinginfoTransactorSession) LogShareMinted(validatorId *big.Int, user common.Address, amount *big.Int, tokens *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.Contract.LogShareMinted(&_Stakinginfo.TransactOpts, validatorId, user, amount, tokens)
}

// LogSignerChange is a paid mutator transaction binding the contract method 0xb80fbce5.
//
// Solidity: function logSignerChange(uint256 validatorId, address oldSigner, address newSigner, bytes signerPubkey) returns()
func (_Stakinginfo *StakinginfoTransactor) LogSignerChange(opts *bind.TransactOpts, validatorId *big.Int, oldSigner common.Address, newSigner common.Address, signerPubkey []byte) (*types.Transaction, error) {
	return _Stakinginfo.contract.Transact(opts, "logSignerChange", validatorId, oldSigner, newSigner, signerPubkey)
}

// LogSignerChange is a paid mutator transaction binding the contract method 0xb80fbce5.
//
// Solidity: function logSignerChange(uint256 validatorId, address oldSigner, address newSigner, bytes signerPubkey) returns()
func (_Stakinginfo *StakinginfoSession) LogSignerChange(validatorId *big.Int, oldSigner common.Address, newSigner common.Address, signerPubkey []byte) (*types.Transaction, error) {
	return _Stakinginfo.Contract.LogSignerChange(&_Stakinginfo.TransactOpts, validatorId, oldSigner, newSigner, signerPubkey)
}

// LogSignerChange is a paid mutator transaction binding the contract method 0xb80fbce5.
//
// Solidity: function logSignerChange(uint256 validatorId, address oldSigner, address newSigner, bytes signerPubkey) returns()
func (_Stakinginfo *StakinginfoTransactorSession) LogSignerChange(validatorId *big.Int, oldSigner common.Address, newSigner common.Address, signerPubkey []byte) (*types.Transaction, error) {
	return _Stakinginfo.Contract.LogSignerChange(&_Stakinginfo.TransactOpts, validatorId, oldSigner, newSigner, signerPubkey)
}

// LogSlashed is a paid mutator transaction binding the contract method 0xfb77c94e.
//
// Solidity: function logSlashed(uint256 epoch, uint256 amount) returns()
func (_Stakinginfo *StakinginfoTransactor) LogSlashed(opts *bind.TransactOpts, epoch *big.Int, amount *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.contract.Transact(opts, "logSlashed", epoch, amount)
}

// LogSlashed is a paid mutator transaction binding the contract method 0xfb77c94e.
//
// Solidity: function logSlashed(uint256 epoch, uint256 amount) returns()
func (_Stakinginfo *StakinginfoSession) LogSlashed(epoch *big.Int, amount *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.Contract.LogSlashed(&_Stakinginfo.TransactOpts, epoch, amount)
}

// LogSlashed is a paid mutator transaction binding the contract method 0xfb77c94e.
//
// Solidity: function logSlashed(uint256 epoch, uint256 amount) returns()
func (_Stakinginfo *StakinginfoTransactorSession) LogSlashed(epoch *big.Int, amount *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.Contract.LogSlashed(&_Stakinginfo.TransactOpts, epoch, amount)
}

// LogStakeUpdate is a paid mutator transaction binding the contract method 0x532e19a9.
//
// Solidity: function logStakeUpdate(uint256 validatorId) returns()
func (_Stakinginfo *StakinginfoTransactor) LogStakeUpdate(opts *bind.TransactOpts, validatorId *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.contract.Transact(opts, "logStakeUpdate", validatorId)
}

// LogStakeUpdate is a paid mutator transaction binding the contract method 0x532e19a9.
//
// Solidity: function logStakeUpdate(uint256 validatorId) returns()
func (_Stakinginfo *StakinginfoSession) LogStakeUpdate(validatorId *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.Contract.LogStakeUpdate(&_Stakinginfo.TransactOpts, validatorId)
}

// LogStakeUpdate is a paid mutator transaction binding the contract method 0x532e19a9.
//
// Solidity: function logStakeUpdate(uint256 validatorId) returns()
func (_Stakinginfo *StakinginfoTransactorSession) LogStakeUpdate(validatorId *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.Contract.LogStakeUpdate(&_Stakinginfo.TransactOpts, validatorId)
}

// LogStaked is a paid mutator transaction binding the contract method 0x46f74082.
//
// Solidity: function logStaked(address signer, address owner, uint256 validatorId, uint256 activationEpoch, uint256 amount, uint256 total, bytes pubkeys) returns()
func (_Stakinginfo *StakinginfoTransactor) LogStaked(opts *bind.TransactOpts, signer common.Address, owner common.Address, validatorId *big.Int, activationEpoch *big.Int, amount *big.Int, total *big.Int, pubkeys []byte) (*types.Transaction, error) {
	return _Stakinginfo.contract.Transact(opts, "logStaked", signer, owner, validatorId, activationEpoch, amount, total, pubkeys)
}

// LogStaked is a paid mutator transaction binding the contract method 0x46f74082.
//
// Solidity: function logStaked(address signer, address owner, uint256 validatorId, uint256 activationEpoch, uint256 amount, uint256 total, bytes pubkeys) returns()
func (_Stakinginfo *StakinginfoSession) LogStaked(signer common.Address, owner common.Address, validatorId *big.Int, activationEpoch *big.Int, amount *big.Int, total *big.Int, pubkeys []byte) (*types.Transaction, error) {
	return _Stakinginfo.Contract.LogStaked(&_Stakinginfo.TransactOpts, signer, owner, validatorId, activationEpoch, amount, total, pubkeys)
}

// LogStaked is a paid mutator transaction binding the contract method 0x46f74082.
//
// Solidity: function logStaked(address signer, address owner, uint256 validatorId, uint256 activationEpoch, uint256 amount, uint256 total, bytes pubkeys) returns()
func (_Stakinginfo *StakinginfoTransactorSession) LogStaked(signer common.Address, owner common.Address, validatorId *big.Int, activationEpoch *big.Int, amount *big.Int, total *big.Int, pubkeys []byte) (*types.Transaction, error) {
	return _Stakinginfo.Contract.LogStaked(&_Stakinginfo.TransactOpts, signer, owner, validatorId, activationEpoch, amount, total, pubkeys)
}

// LogStartAuction is a paid mutator transaction binding the contract method 0x0934a6df.
//
// Solidity: function logStartAuction(uint256 validatorId, uint256 amount, uint256 auctionAmount) returns()
func (_Stakinginfo *StakinginfoTransactor) LogStartAuction(opts *bind.TransactOpts, validatorId *big.Int, amount *big.Int, auctionAmount *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.contract.Transact(opts, "logStartAuction", validatorId, amount, auctionAmount)
}

// LogStartAuction is a paid mutator transaction binding the contract method 0x0934a6df.
//
// Solidity: function logStartAuction(uint256 validatorId, uint256 amount, uint256 auctionAmount) returns()
func (_Stakinginfo *StakinginfoSession) LogStartAuction(validatorId *big.Int, amount *big.Int, auctionAmount *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.Contract.LogStartAuction(&_Stakinginfo.TransactOpts, validatorId, amount, auctionAmount)
}

// LogStartAuction is a paid mutator transaction binding the contract method 0x0934a6df.
//
// Solidity: function logStartAuction(uint256 validatorId, uint256 amount, uint256 auctionAmount) returns()
func (_Stakinginfo *StakinginfoTransactorSession) LogStartAuction(validatorId *big.Int, amount *big.Int, auctionAmount *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.Contract.LogStartAuction(&_Stakinginfo.TransactOpts, validatorId, amount, auctionAmount)
}

// LogThresholdChange is a paid mutator transaction binding the contract method 0xf1980a50.
//
// Solidity: function logThresholdChange(uint256 newThreshold, uint256 oldThreshold) returns()
func (_Stakinginfo *StakinginfoTransactor) LogThresholdChange(opts *bind.TransactOpts, newThreshold *big.Int, oldThreshold *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.contract.Transact(opts, "logThresholdChange", newThreshold, oldThreshold)
}

// LogThresholdChange is a paid mutator transaction binding the contract method 0xf1980a50.
//
// Solidity: function logThresholdChange(uint256 newThreshold, uint256 oldThreshold) returns()
func (_Stakinginfo *StakinginfoSession) LogThresholdChange(newThreshold *big.Int, oldThreshold *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.Contract.LogThresholdChange(&_Stakinginfo.TransactOpts, newThreshold, oldThreshold)
}

// LogThresholdChange is a paid mutator transaction binding the contract method 0xf1980a50.
//
// Solidity: function logThresholdChange(uint256 newThreshold, uint256 oldThreshold) returns()
func (_Stakinginfo *StakinginfoTransactorSession) LogThresholdChange(newThreshold *big.Int, oldThreshold *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.Contract.LogThresholdChange(&_Stakinginfo.TransactOpts, newThreshold, oldThreshold)
}

// LogTopUpFee is a paid mutator transaction binding the contract method 0xa449d795.
//
// Solidity: function logTopUpFee(address user, uint256 fee) returns()
func (_Stakinginfo *StakinginfoTransactor) LogTopUpFee(opts *bind.TransactOpts, user common.Address, fee *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.contract.Transact(opts, "logTopUpFee", user, fee)
}

// LogTopUpFee is a paid mutator transaction binding the contract method 0xa449d795.
//
// Solidity: function logTopUpFee(address user, uint256 fee) returns()
func (_Stakinginfo *StakinginfoSession) LogTopUpFee(user common.Address, fee *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.Contract.LogTopUpFee(&_Stakinginfo.TransactOpts, user, fee)
}

// LogTopUpFee is a paid mutator transaction binding the contract method 0xa449d795.
//
// Solidity: function logTopUpFee(address user, uint256 fee) returns()
func (_Stakinginfo *StakinginfoTransactorSession) LogTopUpFee(user common.Address, fee *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.Contract.LogTopUpFee(&_Stakinginfo.TransactOpts, user, fee)
}

// LogUnjailed is a paid mutator transaction binding the contract method 0xf92ec5af.
//
// Solidity: function logUnjailed(uint256 validatorId, address signer) returns()
func (_Stakinginfo *StakinginfoTransactor) LogUnjailed(opts *bind.TransactOpts, validatorId *big.Int, signer common.Address) (*types.Transaction, error) {
	return _Stakinginfo.contract.Transact(opts, "logUnjailed", validatorId, signer)
}

// LogUnjailed is a paid mutator transaction binding the contract method 0xf92ec5af.
//
// Solidity: function logUnjailed(uint256 validatorId, address signer) returns()
func (_Stakinginfo *StakinginfoSession) LogUnjailed(validatorId *big.Int, signer common.Address) (*types.Transaction, error) {
	return _Stakinginfo.Contract.LogUnjailed(&_Stakinginfo.TransactOpts, validatorId, signer)
}

// LogUnjailed is a paid mutator transaction binding the contract method 0xf92ec5af.
//
// Solidity: function logUnjailed(uint256 validatorId, address signer) returns()
func (_Stakinginfo *StakinginfoTransactorSession) LogUnjailed(validatorId *big.Int, signer common.Address) (*types.Transaction, error) {
	return _Stakinginfo.Contract.LogUnjailed(&_Stakinginfo.TransactOpts, validatorId, signer)
}

// LogUnstakeInit is a paid mutator transaction binding the contract method 0x5e04d483.
//
// Solidity: function logUnstakeInit(address user, uint256 validatorId, uint256 deactivationEpoch, uint256 amount) returns()
func (_Stakinginfo *StakinginfoTransactor) LogUnstakeInit(opts *bind.TransactOpts, user common.Address, validatorId *big.Int, deactivationEpoch *big.Int, amount *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.contract.Transact(opts, "logUnstakeInit", user, validatorId, deactivationEpoch, amount)
}

// LogUnstakeInit is a paid mutator transaction binding the contract method 0x5e04d483.
//
// Solidity: function logUnstakeInit(address user, uint256 validatorId, uint256 deactivationEpoch, uint256 amount) returns()
func (_Stakinginfo *StakinginfoSession) LogUnstakeInit(user common.Address, validatorId *big.Int, deactivationEpoch *big.Int, amount *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.Contract.LogUnstakeInit(&_Stakinginfo.TransactOpts, user, validatorId, deactivationEpoch, amount)
}

// LogUnstakeInit is a paid mutator transaction binding the contract method 0x5e04d483.
//
// Solidity: function logUnstakeInit(address user, uint256 validatorId, uint256 deactivationEpoch, uint256 amount) returns()
func (_Stakinginfo *StakinginfoTransactorSession) LogUnstakeInit(user common.Address, validatorId *big.Int, deactivationEpoch *big.Int, amount *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.Contract.LogUnstakeInit(&_Stakinginfo.TransactOpts, user, validatorId, deactivationEpoch, amount)
}

// LogUnstaked is a paid mutator transaction binding the contract method 0xae2e26b1.
//
// Solidity: function logUnstaked(address user, uint256 validatorId, uint256 amount, uint256 total) returns()
func (_Stakinginfo *StakinginfoTransactor) LogUnstaked(opts *bind.TransactOpts, user common.Address, validatorId *big.Int, amount *big.Int, total *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.contract.Transact(opts, "logUnstaked", user, validatorId, amount, total)
}

// LogUnstaked is a paid mutator transaction binding the contract method 0xae2e26b1.
//
// Solidity: function logUnstaked(address user, uint256 validatorId, uint256 amount, uint256 total) returns()
func (_Stakinginfo *StakinginfoSession) LogUnstaked(user common.Address, validatorId *big.Int, amount *big.Int, total *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.Contract.LogUnstaked(&_Stakinginfo.TransactOpts, user, validatorId, amount, total)
}

// LogUnstaked is a paid mutator transaction binding the contract method 0xae2e26b1.
//
// Solidity: function logUnstaked(address user, uint256 validatorId, uint256 amount, uint256 total) returns()
func (_Stakinginfo *StakinginfoTransactorSession) LogUnstaked(user common.Address, validatorId *big.Int, amount *big.Int, total *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.Contract.LogUnstaked(&_Stakinginfo.TransactOpts, user, validatorId, amount, total)
}

// LogUpdateCommissionRate is a paid mutator transaction binding the contract method 0xc98cc002.
//
// Solidity: function logUpdateCommissionRate(uint256 validatorId, uint256 newCommissionRate, uint256 oldCommissionRate) returns()
func (_Stakinginfo *StakinginfoTransactor) LogUpdateCommissionRate(opts *bind.TransactOpts, validatorId *big.Int, newCommissionRate *big.Int, oldCommissionRate *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.contract.Transact(opts, "logUpdateCommissionRate", validatorId, newCommissionRate, oldCommissionRate)
}

// LogUpdateCommissionRate is a paid mutator transaction binding the contract method 0xc98cc002.
//
// Solidity: function logUpdateCommissionRate(uint256 validatorId, uint256 newCommissionRate, uint256 oldCommissionRate) returns()
func (_Stakinginfo *StakinginfoSession) LogUpdateCommissionRate(validatorId *big.Int, newCommissionRate *big.Int, oldCommissionRate *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.Contract.LogUpdateCommissionRate(&_Stakinginfo.TransactOpts, validatorId, newCommissionRate, oldCommissionRate)
}

// LogUpdateCommissionRate is a paid mutator transaction binding the contract method 0xc98cc002.
//
// Solidity: function logUpdateCommissionRate(uint256 validatorId, uint256 newCommissionRate, uint256 oldCommissionRate) returns()
func (_Stakinginfo *StakinginfoTransactorSession) LogUpdateCommissionRate(validatorId *big.Int, newCommissionRate *big.Int, oldCommissionRate *big.Int) (*types.Transaction, error) {
	return _Stakinginfo.Contract.LogUpdateCommissionRate(&_Stakinginfo.TransactOpts, validatorId, newCommissionRate, oldCommissionRate)
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0x715018a6.
//
// Solidity: function renounceOwnership() returns()
func (_Stakinginfo *StakinginfoTransactor) RenounceOwnership(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Stakinginfo.contract.Transact(opts, "renounceOwnership")
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0x715018a6.
//
// Solidity: function renounceOwnership() returns()
func (_Stakinginfo *StakinginfoSession) RenounceOwnership() (*types.Transaction, error) {
	return _Stakinginfo.Contract.RenounceOwnership(&_Stakinginfo.TransactOpts)
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0x715018a6.
//
// Solidity: function renounceOwnership() returns()
func (_Stakinginfo *StakinginfoTransactorSession) RenounceOwnership() (*types.Transaction, error) {
	return _Stakinginfo.Contract.RenounceOwnership(&_Stakinginfo.TransactOpts)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_Stakinginfo *StakinginfoTransactor) TransferOwnership(opts *bind.TransactOpts, newOwner common.Address) (*types.Transaction, error) {
	return _Stakinginfo.contract.Transact(opts, "transferOwnership", newOwner)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_Stakinginfo *StakinginfoSession) TransferOwnership(newOwner common.Address) (*types.Transaction, error) {
	return _Stakinginfo.Contract.TransferOwnership(&_Stakinginfo.TransactOpts, newOwner)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_Stakinginfo *StakinginfoTransactorSession) TransferOwnership(newOwner common.Address) (*types.Transaction, error) {
	return _Stakinginfo.Contract.TransferOwnership(&_Stakinginfo.TransactOpts, newOwner)
}

// UpdateNonce is a paid mutator transaction binding the contract method 0xeae3f749.
//
// Solidity: function updateNonce(uint256[] validatorIds, uint256[] nonces) returns()
func (_Stakinginfo *StakinginfoTransactor) UpdateNonce(opts *bind.TransactOpts, validatorIds []*big.Int, nonces []*big.Int) (*types.Transaction, error) {
	return _Stakinginfo.contract.Transact(opts, "updateNonce", validatorIds, nonces)
}

// UpdateNonce is a paid mutator transaction binding the contract method 0xeae3f749.
//
// Solidity: function updateNonce(uint256[] validatorIds, uint256[] nonces) returns()
func (_Stakinginfo *StakinginfoSession) UpdateNonce(validatorIds []*big.Int, nonces []*big.Int) (*types.Transaction, error) {
	return _Stakinginfo.Contract.UpdateNonce(&_Stakinginfo.TransactOpts, validatorIds, nonces)
}

// UpdateNonce is a paid mutator transaction binding the contract method 0xeae3f749.
//
// Solidity: function updateNonce(uint256[] validatorIds, uint256[] nonces) returns()
func (_Stakinginfo *StakinginfoTransactorSession) UpdateNonce(validatorIds []*big.Int, nonces []*big.Int) (*types.Transaction, error) {
	return _Stakinginfo.Contract.UpdateNonce(&_Stakinginfo.TransactOpts, validatorIds, nonces)
}

// StakinginfoClaimFeeIterator is returned from FilterClaimFee and is used to iterate over the raw logs and unpacked data for ClaimFee events raised by the Stakinginfo contract.
type StakinginfoClaimFeeIterator struct {
	Event *StakinginfoClaimFee // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  appchain.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *StakinginfoClaimFeeIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(StakinginfoClaimFee)
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
		it.Event = new(StakinginfoClaimFee)
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
func (it *StakinginfoClaimFeeIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *StakinginfoClaimFeeIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// StakinginfoClaimFee represents a ClaimFee event raised by the Stakinginfo contract.
type StakinginfoClaimFee struct {
	User common.Address
	Fee  *big.Int
	Raw  types.Log // Blockchain specific contextual infos
}

// FilterClaimFee is a free log retrieval operation binding the contract event 0xf40b9ca28516abde647ef8ed0e7b155e16347eb4d8dd6eb29989ed2c0c3d27e8.
//
// Solidity: event ClaimFee(address indexed user, uint256 indexed fee)
func (_Stakinginfo *StakinginfoFilterer) FilterClaimFee(opts *bind.FilterOpts, user []common.Address, fee []*big.Int) (*StakinginfoClaimFeeIterator, error) {

	var userRule []interface{}
	for _, userItem := range user {
		userRule = append(userRule, userItem)
	}
	var feeRule []interface{}
	for _, feeItem := range fee {
		feeRule = append(feeRule, feeItem)
	}

	logs, sub, err := _Stakinginfo.contract.FilterLogs(opts, "ClaimFee", userRule, feeRule)
	if err != nil {
		return nil, err
	}
	return &StakinginfoClaimFeeIterator{contract: _Stakinginfo.contract, event: "ClaimFee", logs: logs, sub: sub}, nil
}

// WatchClaimFee is a free log subscription operation binding the contract event 0xf40b9ca28516abde647ef8ed0e7b155e16347eb4d8dd6eb29989ed2c0c3d27e8.
//
// Solidity: event ClaimFee(address indexed user, uint256 indexed fee)
func (_Stakinginfo *StakinginfoFilterer) WatchClaimFee(opts *bind.WatchOpts, sink chan<- *StakinginfoClaimFee, user []common.Address, fee []*big.Int) (event.Subscription, error) {

	var userRule []interface{}
	for _, userItem := range user {
		userRule = append(userRule, userItem)
	}
	var feeRule []interface{}
	for _, feeItem := range fee {
		feeRule = append(feeRule, feeItem)
	}

	logs, sub, err := _Stakinginfo.contract.WatchLogs(opts, "ClaimFee", userRule, feeRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(StakinginfoClaimFee)
				if err := _Stakinginfo.contract.UnpackLog(event, "ClaimFee", log); err != nil {
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

// ParseClaimFee is a log parse operation binding the contract event 0xf40b9ca28516abde647ef8ed0e7b155e16347eb4d8dd6eb29989ed2c0c3d27e8.
//
// Solidity: event ClaimFee(address indexed user, uint256 indexed fee)
func (_Stakinginfo *StakinginfoFilterer) ParseClaimFee(log types.Log) (*StakinginfoClaimFee, error) {
	event := new(StakinginfoClaimFee)
	if err := _Stakinginfo.contract.UnpackLog(event, "ClaimFee", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// StakinginfoClaimRewardsIterator is returned from FilterClaimRewards and is used to iterate over the raw logs and unpacked data for ClaimRewards events raised by the Stakinginfo contract.
type StakinginfoClaimRewardsIterator struct {
	Event *StakinginfoClaimRewards // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  appchain.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *StakinginfoClaimRewardsIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(StakinginfoClaimRewards)
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
		it.Event = new(StakinginfoClaimRewards)
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
func (it *StakinginfoClaimRewardsIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *StakinginfoClaimRewardsIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// StakinginfoClaimRewards represents a ClaimRewards event raised by the Stakinginfo contract.
type StakinginfoClaimRewards struct {
	ValidatorId *big.Int
	Amount      *big.Int
	TotalAmount *big.Int
	Raw         types.Log // Blockchain specific contextual infos
}

// FilterClaimRewards is a free log retrieval operation binding the contract event 0x41e5e4590cfcde2f03ee9281c54d03acad8adffb83f8310d66b894532470ba35.
//
// Solidity: event ClaimRewards(uint256 indexed validatorId, uint256 indexed amount, uint256 indexed totalAmount)
func (_Stakinginfo *StakinginfoFilterer) FilterClaimRewards(opts *bind.FilterOpts, validatorId []*big.Int, amount []*big.Int, totalAmount []*big.Int) (*StakinginfoClaimRewardsIterator, error) {

	var validatorIdRule []interface{}
	for _, validatorIdItem := range validatorId {
		validatorIdRule = append(validatorIdRule, validatorIdItem)
	}
	var amountRule []interface{}
	for _, amountItem := range amount {
		amountRule = append(amountRule, amountItem)
	}
	var totalAmountRule []interface{}
	for _, totalAmountItem := range totalAmount {
		totalAmountRule = append(totalAmountRule, totalAmountItem)
	}

	logs, sub, err := _Stakinginfo.contract.FilterLogs(opts, "ClaimRewards", validatorIdRule, amountRule, totalAmountRule)
	if err != nil {
		return nil, err
	}
	return &StakinginfoClaimRewardsIterator{contract: _Stakinginfo.contract, event: "ClaimRewards", logs: logs, sub: sub}, nil
}

// WatchClaimRewards is a free log subscription operation binding the contract event 0x41e5e4590cfcde2f03ee9281c54d03acad8adffb83f8310d66b894532470ba35.
//
// Solidity: event ClaimRewards(uint256 indexed validatorId, uint256 indexed amount, uint256 indexed totalAmount)
func (_Stakinginfo *StakinginfoFilterer) WatchClaimRewards(opts *bind.WatchOpts, sink chan<- *StakinginfoClaimRewards, validatorId []*big.Int, amount []*big.Int, totalAmount []*big.Int) (event.Subscription, error) {

	var validatorIdRule []interface{}
	for _, validatorIdItem := range validatorId {
		validatorIdRule = append(validatorIdRule, validatorIdItem)
	}
	var amountRule []interface{}
	for _, amountItem := range amount {
		amountRule = append(amountRule, amountItem)
	}
	var totalAmountRule []interface{}
	for _, totalAmountItem := range totalAmount {
		totalAmountRule = append(totalAmountRule, totalAmountItem)
	}

	logs, sub, err := _Stakinginfo.contract.WatchLogs(opts, "ClaimRewards", validatorIdRule, amountRule, totalAmountRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(StakinginfoClaimRewards)
				if err := _Stakinginfo.contract.UnpackLog(event, "ClaimRewards", log); err != nil {
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

// ParseClaimRewards is a log parse operation binding the contract event 0x41e5e4590cfcde2f03ee9281c54d03acad8adffb83f8310d66b894532470ba35.
//
// Solidity: event ClaimRewards(uint256 indexed validatorId, uint256 indexed amount, uint256 indexed totalAmount)
func (_Stakinginfo *StakinginfoFilterer) ParseClaimRewards(log types.Log) (*StakinginfoClaimRewards, error) {
	event := new(StakinginfoClaimRewards)
	if err := _Stakinginfo.contract.UnpackLog(event, "ClaimRewards", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// StakinginfoConfirmAuctionIterator is returned from FilterConfirmAuction and is used to iterate over the raw logs and unpacked data for ConfirmAuction events raised by the Stakinginfo contract.
type StakinginfoConfirmAuctionIterator struct {
	Event *StakinginfoConfirmAuction // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  appchain.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *StakinginfoConfirmAuctionIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(StakinginfoConfirmAuction)
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
		it.Event = new(StakinginfoConfirmAuction)
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
func (it *StakinginfoConfirmAuctionIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *StakinginfoConfirmAuctionIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// StakinginfoConfirmAuction represents a ConfirmAuction event raised by the Stakinginfo contract.
type StakinginfoConfirmAuction struct {
	NewValidatorId *big.Int
	OldValidatorId *big.Int
	Amount         *big.Int
	Raw            types.Log // Blockchain specific contextual infos
}

// FilterConfirmAuction is a free log retrieval operation binding the contract event 0x1002381ecf76700f6f0ab4c90b9f523e39df7b0482b71ec63cf62cf854120470.
//
// Solidity: event ConfirmAuction(uint256 indexed newValidatorId, uint256 indexed oldValidatorId, uint256 indexed amount)
func (_Stakinginfo *StakinginfoFilterer) FilterConfirmAuction(opts *bind.FilterOpts, newValidatorId []*big.Int, oldValidatorId []*big.Int, amount []*big.Int) (*StakinginfoConfirmAuctionIterator, error) {

	var newValidatorIdRule []interface{}
	for _, newValidatorIdItem := range newValidatorId {
		newValidatorIdRule = append(newValidatorIdRule, newValidatorIdItem)
	}
	var oldValidatorIdRule []interface{}
	for _, oldValidatorIdItem := range oldValidatorId {
		oldValidatorIdRule = append(oldValidatorIdRule, oldValidatorIdItem)
	}
	var amountRule []interface{}
	for _, amountItem := range amount {
		amountRule = append(amountRule, amountItem)
	}

	logs, sub, err := _Stakinginfo.contract.FilterLogs(opts, "ConfirmAuction", newValidatorIdRule, oldValidatorIdRule, amountRule)
	if err != nil {
		return nil, err
	}
	return &StakinginfoConfirmAuctionIterator{contract: _Stakinginfo.contract, event: "ConfirmAuction", logs: logs, sub: sub}, nil
}

// WatchConfirmAuction is a free log subscription operation binding the contract event 0x1002381ecf76700f6f0ab4c90b9f523e39df7b0482b71ec63cf62cf854120470.
//
// Solidity: event ConfirmAuction(uint256 indexed newValidatorId, uint256 indexed oldValidatorId, uint256 indexed amount)
func (_Stakinginfo *StakinginfoFilterer) WatchConfirmAuction(opts *bind.WatchOpts, sink chan<- *StakinginfoConfirmAuction, newValidatorId []*big.Int, oldValidatorId []*big.Int, amount []*big.Int) (event.Subscription, error) {

	var newValidatorIdRule []interface{}
	for _, newValidatorIdItem := range newValidatorId {
		newValidatorIdRule = append(newValidatorIdRule, newValidatorIdItem)
	}
	var oldValidatorIdRule []interface{}
	for _, oldValidatorIdItem := range oldValidatorId {
		oldValidatorIdRule = append(oldValidatorIdRule, oldValidatorIdItem)
	}
	var amountRule []interface{}
	for _, amountItem := range amount {
		amountRule = append(amountRule, amountItem)
	}

	logs, sub, err := _Stakinginfo.contract.WatchLogs(opts, "ConfirmAuction", newValidatorIdRule, oldValidatorIdRule, amountRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(StakinginfoConfirmAuction)
				if err := _Stakinginfo.contract.UnpackLog(event, "ConfirmAuction", log); err != nil {
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

// ParseConfirmAuction is a log parse operation binding the contract event 0x1002381ecf76700f6f0ab4c90b9f523e39df7b0482b71ec63cf62cf854120470.
//
// Solidity: event ConfirmAuction(uint256 indexed newValidatorId, uint256 indexed oldValidatorId, uint256 indexed amount)
func (_Stakinginfo *StakinginfoFilterer) ParseConfirmAuction(log types.Log) (*StakinginfoConfirmAuction, error) {
	event := new(StakinginfoConfirmAuction)
	if err := _Stakinginfo.contract.UnpackLog(event, "ConfirmAuction", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// StakinginfoDelegatorClaimedRewardsIterator is returned from FilterDelegatorClaimedRewards and is used to iterate over the raw logs and unpacked data for DelegatorClaimedRewards events raised by the Stakinginfo contract.
type StakinginfoDelegatorClaimedRewardsIterator struct {
	Event *StakinginfoDelegatorClaimedRewards // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  appchain.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *StakinginfoDelegatorClaimedRewardsIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(StakinginfoDelegatorClaimedRewards)
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
		it.Event = new(StakinginfoDelegatorClaimedRewards)
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
func (it *StakinginfoDelegatorClaimedRewardsIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *StakinginfoDelegatorClaimedRewardsIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// StakinginfoDelegatorClaimedRewards represents a DelegatorClaimedRewards event raised by the Stakinginfo contract.
type StakinginfoDelegatorClaimedRewards struct {
	ValidatorId *big.Int
	User        common.Address
	Rewards     *big.Int
	Raw         types.Log // Blockchain specific contextual infos
}

// FilterDelegatorClaimedRewards is a free log retrieval operation binding the contract event 0x31d1715032654fde9867c0f095aecce1113049e30b9f4ecbaa6954ed6c63b8df.
//
// Solidity: event DelegatorClaimedRewards(uint256 indexed validatorId, address indexed user, uint256 indexed rewards)
func (_Stakinginfo *StakinginfoFilterer) FilterDelegatorClaimedRewards(opts *bind.FilterOpts, validatorId []*big.Int, user []common.Address, rewards []*big.Int) (*StakinginfoDelegatorClaimedRewardsIterator, error) {

	var validatorIdRule []interface{}
	for _, validatorIdItem := range validatorId {
		validatorIdRule = append(validatorIdRule, validatorIdItem)
	}
	var userRule []interface{}
	for _, userItem := range user {
		userRule = append(userRule, userItem)
	}
	var rewardsRule []interface{}
	for _, rewardsItem := range rewards {
		rewardsRule = append(rewardsRule, rewardsItem)
	}

	logs, sub, err := _Stakinginfo.contract.FilterLogs(opts, "DelegatorClaimedRewards", validatorIdRule, userRule, rewardsRule)
	if err != nil {
		return nil, err
	}
	return &StakinginfoDelegatorClaimedRewardsIterator{contract: _Stakinginfo.contract, event: "DelegatorClaimedRewards", logs: logs, sub: sub}, nil
}

// WatchDelegatorClaimedRewards is a free log subscription operation binding the contract event 0x31d1715032654fde9867c0f095aecce1113049e30b9f4ecbaa6954ed6c63b8df.
//
// Solidity: event DelegatorClaimedRewards(uint256 indexed validatorId, address indexed user, uint256 indexed rewards)
func (_Stakinginfo *StakinginfoFilterer) WatchDelegatorClaimedRewards(opts *bind.WatchOpts, sink chan<- *StakinginfoDelegatorClaimedRewards, validatorId []*big.Int, user []common.Address, rewards []*big.Int) (event.Subscription, error) {

	var validatorIdRule []interface{}
	for _, validatorIdItem := range validatorId {
		validatorIdRule = append(validatorIdRule, validatorIdItem)
	}
	var userRule []interface{}
	for _, userItem := range user {
		userRule = append(userRule, userItem)
	}
	var rewardsRule []interface{}
	for _, rewardsItem := range rewards {
		rewardsRule = append(rewardsRule, rewardsItem)
	}

	logs, sub, err := _Stakinginfo.contract.WatchLogs(opts, "DelegatorClaimedRewards", validatorIdRule, userRule, rewardsRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(StakinginfoDelegatorClaimedRewards)
				if err := _Stakinginfo.contract.UnpackLog(event, "DelegatorClaimedRewards", log); err != nil {
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

// ParseDelegatorClaimedRewards is a log parse operation binding the contract event 0x31d1715032654fde9867c0f095aecce1113049e30b9f4ecbaa6954ed6c63b8df.
//
// Solidity: event DelegatorClaimedRewards(uint256 indexed validatorId, address indexed user, uint256 indexed rewards)
func (_Stakinginfo *StakinginfoFilterer) ParseDelegatorClaimedRewards(log types.Log) (*StakinginfoDelegatorClaimedRewards, error) {
	event := new(StakinginfoDelegatorClaimedRewards)
	if err := _Stakinginfo.contract.UnpackLog(event, "DelegatorClaimedRewards", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// StakinginfoDelegatorRestakedIterator is returned from FilterDelegatorRestaked and is used to iterate over the raw logs and unpacked data for DelegatorRestaked events raised by the Stakinginfo contract.
type StakinginfoDelegatorRestakedIterator struct {
	Event *StakinginfoDelegatorRestaked // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  appchain.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *StakinginfoDelegatorRestakedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(StakinginfoDelegatorRestaked)
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
		it.Event = new(StakinginfoDelegatorRestaked)
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
func (it *StakinginfoDelegatorRestakedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *StakinginfoDelegatorRestakedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// StakinginfoDelegatorRestaked represents a DelegatorRestaked event raised by the Stakinginfo contract.
type StakinginfoDelegatorRestaked struct {
	ValidatorId *big.Int
	User        common.Address
	TotalStaked *big.Int
	Raw         types.Log // Blockchain specific contextual infos
}

// FilterDelegatorRestaked is a free log retrieval operation binding the contract event 0x0f9ccdda16b467e719059c85ebd8383fcb7f8ffa5576629fe3b842836e04dad1.
//
// Solidity: event DelegatorRestaked(uint256 indexed validatorId, address indexed user, uint256 indexed totalStaked)
func (_Stakinginfo *StakinginfoFilterer) FilterDelegatorRestaked(opts *bind.FilterOpts, validatorId []*big.Int, user []common.Address, totalStaked []*big.Int) (*StakinginfoDelegatorRestakedIterator, error) {

	var validatorIdRule []interface{}
	for _, validatorIdItem := range validatorId {
		validatorIdRule = append(validatorIdRule, validatorIdItem)
	}
	var userRule []interface{}
	for _, userItem := range user {
		userRule = append(userRule, userItem)
	}
	var totalStakedRule []interface{}
	for _, totalStakedItem := range totalStaked {
		totalStakedRule = append(totalStakedRule, totalStakedItem)
	}

	logs, sub, err := _Stakinginfo.contract.FilterLogs(opts, "DelegatorRestaked", validatorIdRule, userRule, totalStakedRule)
	if err != nil {
		return nil, err
	}
	return &StakinginfoDelegatorRestakedIterator{contract: _Stakinginfo.contract, event: "DelegatorRestaked", logs: logs, sub: sub}, nil
}

// WatchDelegatorRestaked is a free log subscription operation binding the contract event 0x0f9ccdda16b467e719059c85ebd8383fcb7f8ffa5576629fe3b842836e04dad1.
//
// Solidity: event DelegatorRestaked(uint256 indexed validatorId, address indexed user, uint256 indexed totalStaked)
func (_Stakinginfo *StakinginfoFilterer) WatchDelegatorRestaked(opts *bind.WatchOpts, sink chan<- *StakinginfoDelegatorRestaked, validatorId []*big.Int, user []common.Address, totalStaked []*big.Int) (event.Subscription, error) {

	var validatorIdRule []interface{}
	for _, validatorIdItem := range validatorId {
		validatorIdRule = append(validatorIdRule, validatorIdItem)
	}
	var userRule []interface{}
	for _, userItem := range user {
		userRule = append(userRule, userItem)
	}
	var totalStakedRule []interface{}
	for _, totalStakedItem := range totalStaked {
		totalStakedRule = append(totalStakedRule, totalStakedItem)
	}

	logs, sub, err := _Stakinginfo.contract.WatchLogs(opts, "DelegatorRestaked", validatorIdRule, userRule, totalStakedRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(StakinginfoDelegatorRestaked)
				if err := _Stakinginfo.contract.UnpackLog(event, "DelegatorRestaked", log); err != nil {
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

// ParseDelegatorRestaked is a log parse operation binding the contract event 0x0f9ccdda16b467e719059c85ebd8383fcb7f8ffa5576629fe3b842836e04dad1.
//
// Solidity: event DelegatorRestaked(uint256 indexed validatorId, address indexed user, uint256 indexed totalStaked)
func (_Stakinginfo *StakinginfoFilterer) ParseDelegatorRestaked(log types.Log) (*StakinginfoDelegatorRestaked, error) {
	event := new(StakinginfoDelegatorRestaked)
	if err := _Stakinginfo.contract.UnpackLog(event, "DelegatorRestaked", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// StakinginfoDelegatorUnstakedIterator is returned from FilterDelegatorUnstaked and is used to iterate over the raw logs and unpacked data for DelegatorUnstaked events raised by the Stakinginfo contract.
type StakinginfoDelegatorUnstakedIterator struct {
	Event *StakinginfoDelegatorUnstaked // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  appchain.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *StakinginfoDelegatorUnstakedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(StakinginfoDelegatorUnstaked)
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
		it.Event = new(StakinginfoDelegatorUnstaked)
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
func (it *StakinginfoDelegatorUnstakedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *StakinginfoDelegatorUnstakedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// StakinginfoDelegatorUnstaked represents a DelegatorUnstaked event raised by the Stakinginfo contract.
type StakinginfoDelegatorUnstaked struct {
	ValidatorId *big.Int
	User        common.Address
	Amount      *big.Int
	Raw         types.Log // Blockchain specific contextual infos
}

// FilterDelegatorUnstaked is a free log retrieval operation binding the contract event 0x770c7c7d8e20347e5080e2ac70e8519793bedaff621f044396fd8d6d052c4aa8.
//
// Solidity: event DelegatorUnstaked(uint256 indexed validatorId, address indexed user, uint256 amount)
func (_Stakinginfo *StakinginfoFilterer) FilterDelegatorUnstaked(opts *bind.FilterOpts, validatorId []*big.Int, user []common.Address) (*StakinginfoDelegatorUnstakedIterator, error) {

	var validatorIdRule []interface{}
	for _, validatorIdItem := range validatorId {
		validatorIdRule = append(validatorIdRule, validatorIdItem)
	}
	var userRule []interface{}
	for _, userItem := range user {
		userRule = append(userRule, userItem)
	}

	logs, sub, err := _Stakinginfo.contract.FilterLogs(opts, "DelegatorUnstaked", validatorIdRule, userRule)
	if err != nil {
		return nil, err
	}
	return &StakinginfoDelegatorUnstakedIterator{contract: _Stakinginfo.contract, event: "DelegatorUnstaked", logs: logs, sub: sub}, nil
}

// WatchDelegatorUnstaked is a free log subscription operation binding the contract event 0x770c7c7d8e20347e5080e2ac70e8519793bedaff621f044396fd8d6d052c4aa8.
//
// Solidity: event DelegatorUnstaked(uint256 indexed validatorId, address indexed user, uint256 amount)
func (_Stakinginfo *StakinginfoFilterer) WatchDelegatorUnstaked(opts *bind.WatchOpts, sink chan<- *StakinginfoDelegatorUnstaked, validatorId []*big.Int, user []common.Address) (event.Subscription, error) {

	var validatorIdRule []interface{}
	for _, validatorIdItem := range validatorId {
		validatorIdRule = append(validatorIdRule, validatorIdItem)
	}
	var userRule []interface{}
	for _, userItem := range user {
		userRule = append(userRule, userItem)
	}

	logs, sub, err := _Stakinginfo.contract.WatchLogs(opts, "DelegatorUnstaked", validatorIdRule, userRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(StakinginfoDelegatorUnstaked)
				if err := _Stakinginfo.contract.UnpackLog(event, "DelegatorUnstaked", log); err != nil {
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

// ParseDelegatorUnstaked is a log parse operation binding the contract event 0x770c7c7d8e20347e5080e2ac70e8519793bedaff621f044396fd8d6d052c4aa8.
//
// Solidity: event DelegatorUnstaked(uint256 indexed validatorId, address indexed user, uint256 amount)
func (_Stakinginfo *StakinginfoFilterer) ParseDelegatorUnstaked(log types.Log) (*StakinginfoDelegatorUnstaked, error) {
	event := new(StakinginfoDelegatorUnstaked)
	if err := _Stakinginfo.contract.UnpackLog(event, "DelegatorUnstaked", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// StakinginfoDynastyValueChangeIterator is returned from FilterDynastyValueChange and is used to iterate over the raw logs and unpacked data for DynastyValueChange events raised by the Stakinginfo contract.
type StakinginfoDynastyValueChangeIterator struct {
	Event *StakinginfoDynastyValueChange // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  appchain.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *StakinginfoDynastyValueChangeIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(StakinginfoDynastyValueChange)
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
		it.Event = new(StakinginfoDynastyValueChange)
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
func (it *StakinginfoDynastyValueChangeIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *StakinginfoDynastyValueChangeIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// StakinginfoDynastyValueChange represents a DynastyValueChange event raised by the Stakinginfo contract.
type StakinginfoDynastyValueChange struct {
	NewDynasty *big.Int
	OldDynasty *big.Int
	Raw        types.Log // Blockchain specific contextual infos
}

// FilterDynastyValueChange is a free log retrieval operation binding the contract event 0x9444bfcfa6aed72a15da73de1220dcc07d7864119c44abfec0037bbcacefda98.
//
// Solidity: event DynastyValueChange(uint256 newDynasty, uint256 oldDynasty)
func (_Stakinginfo *StakinginfoFilterer) FilterDynastyValueChange(opts *bind.FilterOpts) (*StakinginfoDynastyValueChangeIterator, error) {

	logs, sub, err := _Stakinginfo.contract.FilterLogs(opts, "DynastyValueChange")
	if err != nil {
		return nil, err
	}
	return &StakinginfoDynastyValueChangeIterator{contract: _Stakinginfo.contract, event: "DynastyValueChange", logs: logs, sub: sub}, nil
}

// WatchDynastyValueChange is a free log subscription operation binding the contract event 0x9444bfcfa6aed72a15da73de1220dcc07d7864119c44abfec0037bbcacefda98.
//
// Solidity: event DynastyValueChange(uint256 newDynasty, uint256 oldDynasty)
func (_Stakinginfo *StakinginfoFilterer) WatchDynastyValueChange(opts *bind.WatchOpts, sink chan<- *StakinginfoDynastyValueChange) (event.Subscription, error) {

	logs, sub, err := _Stakinginfo.contract.WatchLogs(opts, "DynastyValueChange")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(StakinginfoDynastyValueChange)
				if err := _Stakinginfo.contract.UnpackLog(event, "DynastyValueChange", log); err != nil {
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

// ParseDynastyValueChange is a log parse operation binding the contract event 0x9444bfcfa6aed72a15da73de1220dcc07d7864119c44abfec0037bbcacefda98.
//
// Solidity: event DynastyValueChange(uint256 newDynasty, uint256 oldDynasty)
func (_Stakinginfo *StakinginfoFilterer) ParseDynastyValueChange(log types.Log) (*StakinginfoDynastyValueChange, error) {
	event := new(StakinginfoDynastyValueChange)
	if err := _Stakinginfo.contract.UnpackLog(event, "DynastyValueChange", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// StakinginfoJailedIterator is returned from FilterJailed and is used to iterate over the raw logs and unpacked data for Jailed events raised by the Stakinginfo contract.
type StakinginfoJailedIterator struct {
	Event *StakinginfoJailed // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  appchain.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *StakinginfoJailedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(StakinginfoJailed)
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
		it.Event = new(StakinginfoJailed)
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
func (it *StakinginfoJailedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *StakinginfoJailedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// StakinginfoJailed represents a Jailed event raised by the Stakinginfo contract.
type StakinginfoJailed struct {
	ValidatorId *big.Int
	ExitEpoch   *big.Int
	Signer      common.Address
	Raw         types.Log // Blockchain specific contextual infos
}

// FilterJailed is a free log retrieval operation binding the contract event 0xf6566d8fbe8f23227826ba3da2ecc1ec48698c5be051a829965e3358fd5b9658.
//
// Solidity: event Jailed(uint256 indexed validatorId, uint256 indexed exitEpoch, address indexed signer)
func (_Stakinginfo *StakinginfoFilterer) FilterJailed(opts *bind.FilterOpts, validatorId []*big.Int, exitEpoch []*big.Int, signer []common.Address) (*StakinginfoJailedIterator, error) {

	var validatorIdRule []interface{}
	for _, validatorIdItem := range validatorId {
		validatorIdRule = append(validatorIdRule, validatorIdItem)
	}
	var exitEpochRule []interface{}
	for _, exitEpochItem := range exitEpoch {
		exitEpochRule = append(exitEpochRule, exitEpochItem)
	}
	var signerRule []interface{}
	for _, signerItem := range signer {
		signerRule = append(signerRule, signerItem)
	}

	logs, sub, err := _Stakinginfo.contract.FilterLogs(opts, "Jailed", validatorIdRule, exitEpochRule, signerRule)
	if err != nil {
		return nil, err
	}
	return &StakinginfoJailedIterator{contract: _Stakinginfo.contract, event: "Jailed", logs: logs, sub: sub}, nil
}

// WatchJailed is a free log subscription operation binding the contract event 0xf6566d8fbe8f23227826ba3da2ecc1ec48698c5be051a829965e3358fd5b9658.
//
// Solidity: event Jailed(uint256 indexed validatorId, uint256 indexed exitEpoch, address indexed signer)
func (_Stakinginfo *StakinginfoFilterer) WatchJailed(opts *bind.WatchOpts, sink chan<- *StakinginfoJailed, validatorId []*big.Int, exitEpoch []*big.Int, signer []common.Address) (event.Subscription, error) {

	var validatorIdRule []interface{}
	for _, validatorIdItem := range validatorId {
		validatorIdRule = append(validatorIdRule, validatorIdItem)
	}
	var exitEpochRule []interface{}
	for _, exitEpochItem := range exitEpoch {
		exitEpochRule = append(exitEpochRule, exitEpochItem)
	}
	var signerRule []interface{}
	for _, signerItem := range signer {
		signerRule = append(signerRule, signerItem)
	}

	logs, sub, err := _Stakinginfo.contract.WatchLogs(opts, "Jailed", validatorIdRule, exitEpochRule, signerRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(StakinginfoJailed)
				if err := _Stakinginfo.contract.UnpackLog(event, "Jailed", log); err != nil {
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

// ParseJailed is a log parse operation binding the contract event 0xf6566d8fbe8f23227826ba3da2ecc1ec48698c5be051a829965e3358fd5b9658.
//
// Solidity: event Jailed(uint256 indexed validatorId, uint256 indexed exitEpoch, address indexed signer)
func (_Stakinginfo *StakinginfoFilterer) ParseJailed(log types.Log) (*StakinginfoJailed, error) {
	event := new(StakinginfoJailed)
	if err := _Stakinginfo.contract.UnpackLog(event, "Jailed", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// StakinginfoOwnershipTransferredIterator is returned from FilterOwnershipTransferred and is used to iterate over the raw logs and unpacked data for OwnershipTransferred events raised by the Stakinginfo contract.
type StakinginfoOwnershipTransferredIterator struct {
	Event *StakinginfoOwnershipTransferred // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  appchain.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *StakinginfoOwnershipTransferredIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(StakinginfoOwnershipTransferred)
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
		it.Event = new(StakinginfoOwnershipTransferred)
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
func (it *StakinginfoOwnershipTransferredIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *StakinginfoOwnershipTransferredIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// StakinginfoOwnershipTransferred represents a OwnershipTransferred event raised by the Stakinginfo contract.
type StakinginfoOwnershipTransferred struct {
	PreviousOwner common.Address
	NewOwner      common.Address
	Raw           types.Log // Blockchain specific contextual infos
}

// FilterOwnershipTransferred is a free log retrieval operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
//
// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
func (_Stakinginfo *StakinginfoFilterer) FilterOwnershipTransferred(opts *bind.FilterOpts, previousOwner []common.Address, newOwner []common.Address) (*StakinginfoOwnershipTransferredIterator, error) {

	var previousOwnerRule []interface{}
	for _, previousOwnerItem := range previousOwner {
		previousOwnerRule = append(previousOwnerRule, previousOwnerItem)
	}
	var newOwnerRule []interface{}
	for _, newOwnerItem := range newOwner {
		newOwnerRule = append(newOwnerRule, newOwnerItem)
	}

	logs, sub, err := _Stakinginfo.contract.FilterLogs(opts, "OwnershipTransferred", previousOwnerRule, newOwnerRule)
	if err != nil {
		return nil, err
	}
	return &StakinginfoOwnershipTransferredIterator{contract: _Stakinginfo.contract, event: "OwnershipTransferred", logs: logs, sub: sub}, nil
}

// WatchOwnershipTransferred is a free log subscription operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
//
// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
func (_Stakinginfo *StakinginfoFilterer) WatchOwnershipTransferred(opts *bind.WatchOpts, sink chan<- *StakinginfoOwnershipTransferred, previousOwner []common.Address, newOwner []common.Address) (event.Subscription, error) {

	var previousOwnerRule []interface{}
	for _, previousOwnerItem := range previousOwner {
		previousOwnerRule = append(previousOwnerRule, previousOwnerItem)
	}
	var newOwnerRule []interface{}
	for _, newOwnerItem := range newOwner {
		newOwnerRule = append(newOwnerRule, newOwnerItem)
	}

	logs, sub, err := _Stakinginfo.contract.WatchLogs(opts, "OwnershipTransferred", previousOwnerRule, newOwnerRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(StakinginfoOwnershipTransferred)
				if err := _Stakinginfo.contract.UnpackLog(event, "OwnershipTransferred", log); err != nil {
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
func (_Stakinginfo *StakinginfoFilterer) ParseOwnershipTransferred(log types.Log) (*StakinginfoOwnershipTransferred, error) {
	event := new(StakinginfoOwnershipTransferred)
	if err := _Stakinginfo.contract.UnpackLog(event, "OwnershipTransferred", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// StakinginfoProposerBonusChangeIterator is returned from FilterProposerBonusChange and is used to iterate over the raw logs and unpacked data for ProposerBonusChange events raised by the Stakinginfo contract.
type StakinginfoProposerBonusChangeIterator struct {
	Event *StakinginfoProposerBonusChange // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  appchain.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *StakinginfoProposerBonusChangeIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(StakinginfoProposerBonusChange)
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
		it.Event = new(StakinginfoProposerBonusChange)
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
func (it *StakinginfoProposerBonusChangeIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *StakinginfoProposerBonusChangeIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// StakinginfoProposerBonusChange represents a ProposerBonusChange event raised by the Stakinginfo contract.
type StakinginfoProposerBonusChange struct {
	NewProposerBonus *big.Int
	OldProposerBonus *big.Int
	Raw              types.Log // Blockchain specific contextual infos
}

// FilterProposerBonusChange is a free log retrieval operation binding the contract event 0x4a501a9c4d5cce5c32415945bbc8973764f31b844e3e8fd4c15f51f315ac8792.
//
// Solidity: event ProposerBonusChange(uint256 newProposerBonus, uint256 oldProposerBonus)
func (_Stakinginfo *StakinginfoFilterer) FilterProposerBonusChange(opts *bind.FilterOpts) (*StakinginfoProposerBonusChangeIterator, error) {

	logs, sub, err := _Stakinginfo.contract.FilterLogs(opts, "ProposerBonusChange")
	if err != nil {
		return nil, err
	}
	return &StakinginfoProposerBonusChangeIterator{contract: _Stakinginfo.contract, event: "ProposerBonusChange", logs: logs, sub: sub}, nil
}

// WatchProposerBonusChange is a free log subscription operation binding the contract event 0x4a501a9c4d5cce5c32415945bbc8973764f31b844e3e8fd4c15f51f315ac8792.
//
// Solidity: event ProposerBonusChange(uint256 newProposerBonus, uint256 oldProposerBonus)
func (_Stakinginfo *StakinginfoFilterer) WatchProposerBonusChange(opts *bind.WatchOpts, sink chan<- *StakinginfoProposerBonusChange) (event.Subscription, error) {

	logs, sub, err := _Stakinginfo.contract.WatchLogs(opts, "ProposerBonusChange")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(StakinginfoProposerBonusChange)
				if err := _Stakinginfo.contract.UnpackLog(event, "ProposerBonusChange", log); err != nil {
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

// ParseProposerBonusChange is a log parse operation binding the contract event 0x4a501a9c4d5cce5c32415945bbc8973764f31b844e3e8fd4c15f51f315ac8792.
//
// Solidity: event ProposerBonusChange(uint256 newProposerBonus, uint256 oldProposerBonus)
func (_Stakinginfo *StakinginfoFilterer) ParseProposerBonusChange(log types.Log) (*StakinginfoProposerBonusChange, error) {
	event := new(StakinginfoProposerBonusChange)
	if err := _Stakinginfo.contract.UnpackLog(event, "ProposerBonusChange", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// StakinginfoRestakedIterator is returned from FilterRestaked and is used to iterate over the raw logs and unpacked data for Restaked events raised by the Stakinginfo contract.
type StakinginfoRestakedIterator struct {
	Event *StakinginfoRestaked // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  appchain.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *StakinginfoRestakedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(StakinginfoRestaked)
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
		it.Event = new(StakinginfoRestaked)
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
func (it *StakinginfoRestakedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *StakinginfoRestakedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// StakinginfoRestaked represents a Restaked event raised by the Stakinginfo contract.
type StakinginfoRestaked struct {
	ValidatorId *big.Int
	Amount      *big.Int
	Total       *big.Int
	Raw         types.Log // Blockchain specific contextual infos
}

// FilterRestaked is a free log retrieval operation binding the contract event 0x09b24121f82c610c13909ec63bd0843468819a45f6eda5838c3a80568c2046a8.
//
// Solidity: event Restaked(uint256 indexed validatorId, uint256 amount, uint256 total)
func (_Stakinginfo *StakinginfoFilterer) FilterRestaked(opts *bind.FilterOpts, validatorId []*big.Int) (*StakinginfoRestakedIterator, error) {

	var validatorIdRule []interface{}
	for _, validatorIdItem := range validatorId {
		validatorIdRule = append(validatorIdRule, validatorIdItem)
	}

	logs, sub, err := _Stakinginfo.contract.FilterLogs(opts, "Restaked", validatorIdRule)
	if err != nil {
		return nil, err
	}
	return &StakinginfoRestakedIterator{contract: _Stakinginfo.contract, event: "Restaked", logs: logs, sub: sub}, nil
}

// WatchRestaked is a free log subscription operation binding the contract event 0x09b24121f82c610c13909ec63bd0843468819a45f6eda5838c3a80568c2046a8.
//
// Solidity: event Restaked(uint256 indexed validatorId, uint256 amount, uint256 total)
func (_Stakinginfo *StakinginfoFilterer) WatchRestaked(opts *bind.WatchOpts, sink chan<- *StakinginfoRestaked, validatorId []*big.Int) (event.Subscription, error) {

	var validatorIdRule []interface{}
	for _, validatorIdItem := range validatorId {
		validatorIdRule = append(validatorIdRule, validatorIdItem)
	}

	logs, sub, err := _Stakinginfo.contract.WatchLogs(opts, "Restaked", validatorIdRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(StakinginfoRestaked)
				if err := _Stakinginfo.contract.UnpackLog(event, "Restaked", log); err != nil {
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

// ParseRestaked is a log parse operation binding the contract event 0x09b24121f82c610c13909ec63bd0843468819a45f6eda5838c3a80568c2046a8.
//
// Solidity: event Restaked(uint256 indexed validatorId, uint256 amount, uint256 total)
func (_Stakinginfo *StakinginfoFilterer) ParseRestaked(log types.Log) (*StakinginfoRestaked, error) {
	event := new(StakinginfoRestaked)
	if err := _Stakinginfo.contract.UnpackLog(event, "Restaked", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// StakinginfoRewardUpdateIterator is returned from FilterRewardUpdate and is used to iterate over the raw logs and unpacked data for RewardUpdate events raised by the Stakinginfo contract.
type StakinginfoRewardUpdateIterator struct {
	Event *StakinginfoRewardUpdate // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  appchain.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *StakinginfoRewardUpdateIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(StakinginfoRewardUpdate)
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
		it.Event = new(StakinginfoRewardUpdate)
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
func (it *StakinginfoRewardUpdateIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *StakinginfoRewardUpdateIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// StakinginfoRewardUpdate represents a RewardUpdate event raised by the Stakinginfo contract.
type StakinginfoRewardUpdate struct {
	NewReward *big.Int
	OldReward *big.Int
	Raw       types.Log // Blockchain specific contextual infos
}

// FilterRewardUpdate is a free log retrieval operation binding the contract event 0xf67f33e8589d3ea0356303c0f9a8e764873692159f777ff79e4fc523d389dfcd.
//
// Solidity: event RewardUpdate(uint256 newReward, uint256 oldReward)
func (_Stakinginfo *StakinginfoFilterer) FilterRewardUpdate(opts *bind.FilterOpts) (*StakinginfoRewardUpdateIterator, error) {

	logs, sub, err := _Stakinginfo.contract.FilterLogs(opts, "RewardUpdate")
	if err != nil {
		return nil, err
	}
	return &StakinginfoRewardUpdateIterator{contract: _Stakinginfo.contract, event: "RewardUpdate", logs: logs, sub: sub}, nil
}

// WatchRewardUpdate is a free log subscription operation binding the contract event 0xf67f33e8589d3ea0356303c0f9a8e764873692159f777ff79e4fc523d389dfcd.
//
// Solidity: event RewardUpdate(uint256 newReward, uint256 oldReward)
func (_Stakinginfo *StakinginfoFilterer) WatchRewardUpdate(opts *bind.WatchOpts, sink chan<- *StakinginfoRewardUpdate) (event.Subscription, error) {

	logs, sub, err := _Stakinginfo.contract.WatchLogs(opts, "RewardUpdate")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(StakinginfoRewardUpdate)
				if err := _Stakinginfo.contract.UnpackLog(event, "RewardUpdate", log); err != nil {
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

// ParseRewardUpdate is a log parse operation binding the contract event 0xf67f33e8589d3ea0356303c0f9a8e764873692159f777ff79e4fc523d389dfcd.
//
// Solidity: event RewardUpdate(uint256 newReward, uint256 oldReward)
func (_Stakinginfo *StakinginfoFilterer) ParseRewardUpdate(log types.Log) (*StakinginfoRewardUpdate, error) {
	event := new(StakinginfoRewardUpdate)
	if err := _Stakinginfo.contract.UnpackLog(event, "RewardUpdate", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// StakinginfoShareBurnedIterator is returned from FilterShareBurned and is used to iterate over the raw logs and unpacked data for ShareBurned events raised by the Stakinginfo contract.
type StakinginfoShareBurnedIterator struct {
	Event *StakinginfoShareBurned // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  appchain.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *StakinginfoShareBurnedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(StakinginfoShareBurned)
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
		it.Event = new(StakinginfoShareBurned)
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
func (it *StakinginfoShareBurnedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *StakinginfoShareBurnedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// StakinginfoShareBurned represents a ShareBurned event raised by the Stakinginfo contract.
type StakinginfoShareBurned struct {
	ValidatorId *big.Int
	User        common.Address
	Amount      *big.Int
	Tokens      *big.Int
	Raw         types.Log // Blockchain specific contextual infos
}

// FilterShareBurned is a free log retrieval operation binding the contract event 0x7e86625aa6e668407f095af342e0cc237809c4c5086b4d665a0067de122980a9.
//
// Solidity: event ShareBurned(uint256 indexed validatorId, address indexed user, uint256 indexed amount, uint256 tokens)
func (_Stakinginfo *StakinginfoFilterer) FilterShareBurned(opts *bind.FilterOpts, validatorId []*big.Int, user []common.Address, amount []*big.Int) (*StakinginfoShareBurnedIterator, error) {

	var validatorIdRule []interface{}
	for _, validatorIdItem := range validatorId {
		validatorIdRule = append(validatorIdRule, validatorIdItem)
	}
	var userRule []interface{}
	for _, userItem := range user {
		userRule = append(userRule, userItem)
	}
	var amountRule []interface{}
	for _, amountItem := range amount {
		amountRule = append(amountRule, amountItem)
	}

	logs, sub, err := _Stakinginfo.contract.FilterLogs(opts, "ShareBurned", validatorIdRule, userRule, amountRule)
	if err != nil {
		return nil, err
	}
	return &StakinginfoShareBurnedIterator{contract: _Stakinginfo.contract, event: "ShareBurned", logs: logs, sub: sub}, nil
}

// WatchShareBurned is a free log subscription operation binding the contract event 0x7e86625aa6e668407f095af342e0cc237809c4c5086b4d665a0067de122980a9.
//
// Solidity: event ShareBurned(uint256 indexed validatorId, address indexed user, uint256 indexed amount, uint256 tokens)
func (_Stakinginfo *StakinginfoFilterer) WatchShareBurned(opts *bind.WatchOpts, sink chan<- *StakinginfoShareBurned, validatorId []*big.Int, user []common.Address, amount []*big.Int) (event.Subscription, error) {

	var validatorIdRule []interface{}
	for _, validatorIdItem := range validatorId {
		validatorIdRule = append(validatorIdRule, validatorIdItem)
	}
	var userRule []interface{}
	for _, userItem := range user {
		userRule = append(userRule, userItem)
	}
	var amountRule []interface{}
	for _, amountItem := range amount {
		amountRule = append(amountRule, amountItem)
	}

	logs, sub, err := _Stakinginfo.contract.WatchLogs(opts, "ShareBurned", validatorIdRule, userRule, amountRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(StakinginfoShareBurned)
				if err := _Stakinginfo.contract.UnpackLog(event, "ShareBurned", log); err != nil {
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

// ParseShareBurned is a log parse operation binding the contract event 0x7e86625aa6e668407f095af342e0cc237809c4c5086b4d665a0067de122980a9.
//
// Solidity: event ShareBurned(uint256 indexed validatorId, address indexed user, uint256 indexed amount, uint256 tokens)
func (_Stakinginfo *StakinginfoFilterer) ParseShareBurned(log types.Log) (*StakinginfoShareBurned, error) {
	event := new(StakinginfoShareBurned)
	if err := _Stakinginfo.contract.UnpackLog(event, "ShareBurned", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// StakinginfoShareMintedIterator is returned from FilterShareMinted and is used to iterate over the raw logs and unpacked data for ShareMinted events raised by the Stakinginfo contract.
type StakinginfoShareMintedIterator struct {
	Event *StakinginfoShareMinted // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  appchain.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *StakinginfoShareMintedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(StakinginfoShareMinted)
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
		it.Event = new(StakinginfoShareMinted)
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
func (it *StakinginfoShareMintedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *StakinginfoShareMintedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// StakinginfoShareMinted represents a ShareMinted event raised by the Stakinginfo contract.
type StakinginfoShareMinted struct {
	ValidatorId *big.Int
	User        common.Address
	Amount      *big.Int
	Tokens      *big.Int
	Raw         types.Log // Blockchain specific contextual infos
}

// FilterShareMinted is a free log retrieval operation binding the contract event 0xc9afff0972d33d68c8d330fe0ebd0e9f54491ad8c59ae17330a9206f280f0865.
//
// Solidity: event ShareMinted(uint256 indexed validatorId, address indexed user, uint256 indexed amount, uint256 tokens)
func (_Stakinginfo *StakinginfoFilterer) FilterShareMinted(opts *bind.FilterOpts, validatorId []*big.Int, user []common.Address, amount []*big.Int) (*StakinginfoShareMintedIterator, error) {

	var validatorIdRule []interface{}
	for _, validatorIdItem := range validatorId {
		validatorIdRule = append(validatorIdRule, validatorIdItem)
	}
	var userRule []interface{}
	for _, userItem := range user {
		userRule = append(userRule, userItem)
	}
	var amountRule []interface{}
	for _, amountItem := range amount {
		amountRule = append(amountRule, amountItem)
	}

	logs, sub, err := _Stakinginfo.contract.FilterLogs(opts, "ShareMinted", validatorIdRule, userRule, amountRule)
	if err != nil {
		return nil, err
	}
	return &StakinginfoShareMintedIterator{contract: _Stakinginfo.contract, event: "ShareMinted", logs: logs, sub: sub}, nil
}

// WatchShareMinted is a free log subscription operation binding the contract event 0xc9afff0972d33d68c8d330fe0ebd0e9f54491ad8c59ae17330a9206f280f0865.
//
// Solidity: event ShareMinted(uint256 indexed validatorId, address indexed user, uint256 indexed amount, uint256 tokens)
func (_Stakinginfo *StakinginfoFilterer) WatchShareMinted(opts *bind.WatchOpts, sink chan<- *StakinginfoShareMinted, validatorId []*big.Int, user []common.Address, amount []*big.Int) (event.Subscription, error) {

	var validatorIdRule []interface{}
	for _, validatorIdItem := range validatorId {
		validatorIdRule = append(validatorIdRule, validatorIdItem)
	}
	var userRule []interface{}
	for _, userItem := range user {
		userRule = append(userRule, userItem)
	}
	var amountRule []interface{}
	for _, amountItem := range amount {
		amountRule = append(amountRule, amountItem)
	}

	logs, sub, err := _Stakinginfo.contract.WatchLogs(opts, "ShareMinted", validatorIdRule, userRule, amountRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(StakinginfoShareMinted)
				if err := _Stakinginfo.contract.UnpackLog(event, "ShareMinted", log); err != nil {
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

// ParseShareMinted is a log parse operation binding the contract event 0xc9afff0972d33d68c8d330fe0ebd0e9f54491ad8c59ae17330a9206f280f0865.
//
// Solidity: event ShareMinted(uint256 indexed validatorId, address indexed user, uint256 indexed amount, uint256 tokens)
func (_Stakinginfo *StakinginfoFilterer) ParseShareMinted(log types.Log) (*StakinginfoShareMinted, error) {
	event := new(StakinginfoShareMinted)
	if err := _Stakinginfo.contract.UnpackLog(event, "ShareMinted", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// StakinginfoSignerChangeIterator is returned from FilterSignerChange and is used to iterate over the raw logs and unpacked data for SignerChange events raised by the Stakinginfo contract.
type StakinginfoSignerChangeIterator struct {
	Event *StakinginfoSignerChange // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  appchain.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *StakinginfoSignerChangeIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(StakinginfoSignerChange)
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
		it.Event = new(StakinginfoSignerChange)
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
func (it *StakinginfoSignerChangeIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *StakinginfoSignerChangeIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// StakinginfoSignerChange represents a SignerChange event raised by the Stakinginfo contract.
type StakinginfoSignerChange struct {
	ValidatorId  *big.Int
	Nonce        *big.Int
	OldSigner    common.Address
	NewSigner    common.Address
	SignerPubkey []byte
	Raw          types.Log // Blockchain specific contextual infos
}

// FilterSignerChange is a free log retrieval operation binding the contract event 0x086044c0612a8c965d4cccd907f0d588e40ad68438bd4c1274cac60f4c3a9d1f.
//
// Solidity: event SignerChange(uint256 indexed validatorId, uint256 nonce, address indexed oldSigner, address indexed newSigner, bytes signerPubkey)
func (_Stakinginfo *StakinginfoFilterer) FilterSignerChange(opts *bind.FilterOpts, validatorId []*big.Int, oldSigner []common.Address, newSigner []common.Address) (*StakinginfoSignerChangeIterator, error) {

	var validatorIdRule []interface{}
	for _, validatorIdItem := range validatorId {
		validatorIdRule = append(validatorIdRule, validatorIdItem)
	}

	var oldSignerRule []interface{}
	for _, oldSignerItem := range oldSigner {
		oldSignerRule = append(oldSignerRule, oldSignerItem)
	}
	var newSignerRule []interface{}
	for _, newSignerItem := range newSigner {
		newSignerRule = append(newSignerRule, newSignerItem)
	}

	logs, sub, err := _Stakinginfo.contract.FilterLogs(opts, "SignerChange", validatorIdRule, oldSignerRule, newSignerRule)
	if err != nil {
		return nil, err
	}
	return &StakinginfoSignerChangeIterator{contract: _Stakinginfo.contract, event: "SignerChange", logs: logs, sub: sub}, nil
}

// WatchSignerChange is a free log subscription operation binding the contract event 0x086044c0612a8c965d4cccd907f0d588e40ad68438bd4c1274cac60f4c3a9d1f.
//
// Solidity: event SignerChange(uint256 indexed validatorId, uint256 nonce, address indexed oldSigner, address indexed newSigner, bytes signerPubkey)
func (_Stakinginfo *StakinginfoFilterer) WatchSignerChange(opts *bind.WatchOpts, sink chan<- *StakinginfoSignerChange, validatorId []*big.Int, oldSigner []common.Address, newSigner []common.Address) (event.Subscription, error) {

	var validatorIdRule []interface{}
	for _, validatorIdItem := range validatorId {
		validatorIdRule = append(validatorIdRule, validatorIdItem)
	}

	var oldSignerRule []interface{}
	for _, oldSignerItem := range oldSigner {
		oldSignerRule = append(oldSignerRule, oldSignerItem)
	}
	var newSignerRule []interface{}
	for _, newSignerItem := range newSigner {
		newSignerRule = append(newSignerRule, newSignerItem)
	}

	logs, sub, err := _Stakinginfo.contract.WatchLogs(opts, "SignerChange", validatorIdRule, oldSignerRule, newSignerRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(StakinginfoSignerChange)
				if err := _Stakinginfo.contract.UnpackLog(event, "SignerChange", log); err != nil {
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

// ParseSignerChange is a log parse operation binding the contract event 0x086044c0612a8c965d4cccd907f0d588e40ad68438bd4c1274cac60f4c3a9d1f.
//
// Solidity: event SignerChange(uint256 indexed validatorId, uint256 nonce, address indexed oldSigner, address indexed newSigner, bytes signerPubkey)
func (_Stakinginfo *StakinginfoFilterer) ParseSignerChange(log types.Log) (*StakinginfoSignerChange, error) {
	event := new(StakinginfoSignerChange)
	if err := _Stakinginfo.contract.UnpackLog(event, "SignerChange", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// StakinginfoSlashedIterator is returned from FilterSlashed and is used to iterate over the raw logs and unpacked data for Slashed events raised by the Stakinginfo contract.
type StakinginfoSlashedIterator struct {
	Event *StakinginfoSlashed // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  appchain.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *StakinginfoSlashedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(StakinginfoSlashed)
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
		it.Event = new(StakinginfoSlashed)
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
func (it *StakinginfoSlashedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *StakinginfoSlashedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// StakinginfoSlashed represents a Slashed event raised by the Stakinginfo contract.
type StakinginfoSlashed struct {
	Epoch  *big.Int
	Amount *big.Int
	Raw    types.Log // Blockchain specific contextual infos
}

// FilterSlashed is a free log retrieval operation binding the contract event 0x4f5f38ee30b01a960b4dfdcd520a3ca59c1a664a32dcfe5418ca79b0de6b7236.
//
// Solidity: event Slashed(uint256 indexed epoch, uint256 indexed amount)
func (_Stakinginfo *StakinginfoFilterer) FilterSlashed(opts *bind.FilterOpts, epoch []*big.Int, amount []*big.Int) (*StakinginfoSlashedIterator, error) {

	var epochRule []interface{}
	for _, epochItem := range epoch {
		epochRule = append(epochRule, epochItem)
	}
	var amountRule []interface{}
	for _, amountItem := range amount {
		amountRule = append(amountRule, amountItem)
	}

	logs, sub, err := _Stakinginfo.contract.FilterLogs(opts, "Slashed", epochRule, amountRule)
	if err != nil {
		return nil, err
	}
	return &StakinginfoSlashedIterator{contract: _Stakinginfo.contract, event: "Slashed", logs: logs, sub: sub}, nil
}

// WatchSlashed is a free log subscription operation binding the contract event 0x4f5f38ee30b01a960b4dfdcd520a3ca59c1a664a32dcfe5418ca79b0de6b7236.
//
// Solidity: event Slashed(uint256 indexed epoch, uint256 indexed amount)
func (_Stakinginfo *StakinginfoFilterer) WatchSlashed(opts *bind.WatchOpts, sink chan<- *StakinginfoSlashed, epoch []*big.Int, amount []*big.Int) (event.Subscription, error) {

	var epochRule []interface{}
	for _, epochItem := range epoch {
		epochRule = append(epochRule, epochItem)
	}
	var amountRule []interface{}
	for _, amountItem := range amount {
		amountRule = append(amountRule, amountItem)
	}

	logs, sub, err := _Stakinginfo.contract.WatchLogs(opts, "Slashed", epochRule, amountRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(StakinginfoSlashed)
				if err := _Stakinginfo.contract.UnpackLog(event, "Slashed", log); err != nil {
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

// ParseSlashed is a log parse operation binding the contract event 0x4f5f38ee30b01a960b4dfdcd520a3ca59c1a664a32dcfe5418ca79b0de6b7236.
//
// Solidity: event Slashed(uint256 indexed epoch, uint256 indexed amount)
func (_Stakinginfo *StakinginfoFilterer) ParseSlashed(log types.Log) (*StakinginfoSlashed, error) {
	event := new(StakinginfoSlashed)
	if err := _Stakinginfo.contract.UnpackLog(event, "Slashed", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// StakinginfoStakeUpdateIterator is returned from FilterStakeUpdate and is used to iterate over the raw logs and unpacked data for StakeUpdate events raised by the Stakinginfo contract.
type StakinginfoStakeUpdateIterator struct {
	Event *StakinginfoStakeUpdate // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  appchain.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *StakinginfoStakeUpdateIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(StakinginfoStakeUpdate)
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
		it.Event = new(StakinginfoStakeUpdate)
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
func (it *StakinginfoStakeUpdateIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *StakinginfoStakeUpdateIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// StakinginfoStakeUpdate represents a StakeUpdate event raised by the Stakinginfo contract.
type StakinginfoStakeUpdate struct {
	ValidatorId *big.Int
	Nonce       *big.Int
	NewAmount   *big.Int
	Raw         types.Log // Blockchain specific contextual infos
}

// FilterStakeUpdate is a free log retrieval operation binding the contract event 0x35af9eea1f0e7b300b0a14fae90139a072470e44daa3f14b5069bebbc1265bda.
//
// Solidity: event StakeUpdate(uint256 indexed validatorId, uint256 indexed nonce, uint256 indexed newAmount)
func (_Stakinginfo *StakinginfoFilterer) FilterStakeUpdate(opts *bind.FilterOpts, validatorId []*big.Int, nonce []*big.Int, newAmount []*big.Int) (*StakinginfoStakeUpdateIterator, error) {

	var validatorIdRule []interface{}
	for _, validatorIdItem := range validatorId {
		validatorIdRule = append(validatorIdRule, validatorIdItem)
	}
	var nonceRule []interface{}
	for _, nonceItem := range nonce {
		nonceRule = append(nonceRule, nonceItem)
	}
	var newAmountRule []interface{}
	for _, newAmountItem := range newAmount {
		newAmountRule = append(newAmountRule, newAmountItem)
	}

	logs, sub, err := _Stakinginfo.contract.FilterLogs(opts, "StakeUpdate", validatorIdRule, nonceRule, newAmountRule)
	if err != nil {
		return nil, err
	}
	return &StakinginfoStakeUpdateIterator{contract: _Stakinginfo.contract, event: "StakeUpdate", logs: logs, sub: sub}, nil
}

// WatchStakeUpdate is a free log subscription operation binding the contract event 0x35af9eea1f0e7b300b0a14fae90139a072470e44daa3f14b5069bebbc1265bda.
//
// Solidity: event StakeUpdate(uint256 indexed validatorId, uint256 indexed nonce, uint256 indexed newAmount)
func (_Stakinginfo *StakinginfoFilterer) WatchStakeUpdate(opts *bind.WatchOpts, sink chan<- *StakinginfoStakeUpdate, validatorId []*big.Int, nonce []*big.Int, newAmount []*big.Int) (event.Subscription, error) {

	var validatorIdRule []interface{}
	for _, validatorIdItem := range validatorId {
		validatorIdRule = append(validatorIdRule, validatorIdItem)
	}
	var nonceRule []interface{}
	for _, nonceItem := range nonce {
		nonceRule = append(nonceRule, nonceItem)
	}
	var newAmountRule []interface{}
	for _, newAmountItem := range newAmount {
		newAmountRule = append(newAmountRule, newAmountItem)
	}

	logs, sub, err := _Stakinginfo.contract.WatchLogs(opts, "StakeUpdate", validatorIdRule, nonceRule, newAmountRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(StakinginfoStakeUpdate)
				if err := _Stakinginfo.contract.UnpackLog(event, "StakeUpdate", log); err != nil {
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

// ParseStakeUpdate is a log parse operation binding the contract event 0x35af9eea1f0e7b300b0a14fae90139a072470e44daa3f14b5069bebbc1265bda.
//
// Solidity: event StakeUpdate(uint256 indexed validatorId, uint256 indexed nonce, uint256 indexed newAmount)
func (_Stakinginfo *StakinginfoFilterer) ParseStakeUpdate(log types.Log) (*StakinginfoStakeUpdate, error) {
	event := new(StakinginfoStakeUpdate)
	if err := _Stakinginfo.contract.UnpackLog(event, "StakeUpdate", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// StakinginfoStakedIterator is returned from FilterStaked and is used to iterate over the raw logs and unpacked data for Staked events raised by the Stakinginfo contract.
type StakinginfoStakedIterator struct {
	Event *StakinginfoStaked // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  appchain.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *StakinginfoStakedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(StakinginfoStaked)
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
		it.Event = new(StakinginfoStaked)
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
func (it *StakinginfoStakedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *StakinginfoStakedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// StakinginfoStaked represents a Staked event raised by the Stakinginfo contract.
type StakinginfoStaked struct {
	Signer          common.Address
	Owner           common.Address
	ValidatorId     *big.Int
	Nonce           *big.Int
	ActivationEpoch *big.Int
	Amount          *big.Int
	Total           *big.Int
	Pubkeys         []byte
	Raw             types.Log // Blockchain specific contextual infos
}

// FilterStaked is a free log retrieval operation binding the contract event 0x42aca3a8d2d8ba37d07af1816267145b860bb56fd509c7d123053e57951feda5.
//
// Solidity: event Staked(address indexed signer, address owner, uint256 indexed validatorId, uint256 nonce, uint256 indexed activationEpoch, uint256 amount, uint256 total, bytes pubkeys)
func (_Stakinginfo *StakinginfoFilterer) FilterStaked(opts *bind.FilterOpts, signer []common.Address, validatorId []*big.Int, activationEpoch []*big.Int) (*StakinginfoStakedIterator, error) {

	var signerRule []interface{}
	for _, signerItem := range signer {
		signerRule = append(signerRule, signerItem)
	}

	var validatorIdRule []interface{}
	for _, validatorIdItem := range validatorId {
		validatorIdRule = append(validatorIdRule, validatorIdItem)
	}

	var activationEpochRule []interface{}
	for _, activationEpochItem := range activationEpoch {
		activationEpochRule = append(activationEpochRule, activationEpochItem)
	}

	logs, sub, err := _Stakinginfo.contract.FilterLogs(opts, "Staked", signerRule, validatorIdRule, activationEpochRule)
	if err != nil {
		return nil, err
	}
	return &StakinginfoStakedIterator{contract: _Stakinginfo.contract, event: "Staked", logs: logs, sub: sub}, nil
}

// WatchStaked is a free log subscription operation binding the contract event 0x42aca3a8d2d8ba37d07af1816267145b860bb56fd509c7d123053e57951feda5.
//
// Solidity: event Staked(address indexed signer, address owner, uint256 indexed validatorId, uint256 nonce, uint256 indexed activationEpoch, uint256 amount, uint256 total, bytes pubkeys)
func (_Stakinginfo *StakinginfoFilterer) WatchStaked(opts *bind.WatchOpts, sink chan<- *StakinginfoStaked, signer []common.Address, validatorId []*big.Int, activationEpoch []*big.Int) (event.Subscription, error) {

	var signerRule []interface{}
	for _, signerItem := range signer {
		signerRule = append(signerRule, signerItem)
	}

	var validatorIdRule []interface{}
	for _, validatorIdItem := range validatorId {
		validatorIdRule = append(validatorIdRule, validatorIdItem)
	}

	var activationEpochRule []interface{}
	for _, activationEpochItem := range activationEpoch {
		activationEpochRule = append(activationEpochRule, activationEpochItem)
	}

	logs, sub, err := _Stakinginfo.contract.WatchLogs(opts, "Staked", signerRule, validatorIdRule, activationEpochRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(StakinginfoStaked)
				if err := _Stakinginfo.contract.UnpackLog(event, "Staked", log); err != nil {
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

// ParseStaked is a log parse operation binding the contract event 0x42aca3a8d2d8ba37d07af1816267145b860bb56fd509c7d123053e57951feda5.
//
// Solidity: event Staked(address indexed signer, address owner, uint256 indexed validatorId, uint256 nonce, uint256 indexed activationEpoch, uint256 amount, uint256 total, bytes pubkeys)
func (_Stakinginfo *StakinginfoFilterer) ParseStaked(log types.Log) (*StakinginfoStaked, error) {
	event := new(StakinginfoStaked)
	if err := _Stakinginfo.contract.UnpackLog(event, "Staked", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// StakinginfoStartAuctionIterator is returned from FilterStartAuction and is used to iterate over the raw logs and unpacked data for StartAuction events raised by the Stakinginfo contract.
type StakinginfoStartAuctionIterator struct {
	Event *StakinginfoStartAuction // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  appchain.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *StakinginfoStartAuctionIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(StakinginfoStartAuction)
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
		it.Event = new(StakinginfoStartAuction)
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
func (it *StakinginfoStartAuctionIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *StakinginfoStartAuctionIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// StakinginfoStartAuction represents a StartAuction event raised by the Stakinginfo contract.
type StakinginfoStartAuction struct {
	ValidatorId   *big.Int
	Amount        *big.Int
	AuctionAmount *big.Int
	Raw           types.Log // Blockchain specific contextual infos
}

// FilterStartAuction is a free log retrieval operation binding the contract event 0x683d0f47c7fa11331f4e9563b3f5a7fdc3d3c5b75c600357a91d991f5a13a437.
//
// Solidity: event StartAuction(uint256 indexed validatorId, uint256 indexed amount, uint256 indexed auctionAmount)
func (_Stakinginfo *StakinginfoFilterer) FilterStartAuction(opts *bind.FilterOpts, validatorId []*big.Int, amount []*big.Int, auctionAmount []*big.Int) (*StakinginfoStartAuctionIterator, error) {

	var validatorIdRule []interface{}
	for _, validatorIdItem := range validatorId {
		validatorIdRule = append(validatorIdRule, validatorIdItem)
	}
	var amountRule []interface{}
	for _, amountItem := range amount {
		amountRule = append(amountRule, amountItem)
	}
	var auctionAmountRule []interface{}
	for _, auctionAmountItem := range auctionAmount {
		auctionAmountRule = append(auctionAmountRule, auctionAmountItem)
	}

	logs, sub, err := _Stakinginfo.contract.FilterLogs(opts, "StartAuction", validatorIdRule, amountRule, auctionAmountRule)
	if err != nil {
		return nil, err
	}
	return &StakinginfoStartAuctionIterator{contract: _Stakinginfo.contract, event: "StartAuction", logs: logs, sub: sub}, nil
}

// WatchStartAuction is a free log subscription operation binding the contract event 0x683d0f47c7fa11331f4e9563b3f5a7fdc3d3c5b75c600357a91d991f5a13a437.
//
// Solidity: event StartAuction(uint256 indexed validatorId, uint256 indexed amount, uint256 indexed auctionAmount)
func (_Stakinginfo *StakinginfoFilterer) WatchStartAuction(opts *bind.WatchOpts, sink chan<- *StakinginfoStartAuction, validatorId []*big.Int, amount []*big.Int, auctionAmount []*big.Int) (event.Subscription, error) {

	var validatorIdRule []interface{}
	for _, validatorIdItem := range validatorId {
		validatorIdRule = append(validatorIdRule, validatorIdItem)
	}
	var amountRule []interface{}
	for _, amountItem := range amount {
		amountRule = append(amountRule, amountItem)
	}
	var auctionAmountRule []interface{}
	for _, auctionAmountItem := range auctionAmount {
		auctionAmountRule = append(auctionAmountRule, auctionAmountItem)
	}

	logs, sub, err := _Stakinginfo.contract.WatchLogs(opts, "StartAuction", validatorIdRule, amountRule, auctionAmountRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(StakinginfoStartAuction)
				if err := _Stakinginfo.contract.UnpackLog(event, "StartAuction", log); err != nil {
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

// ParseStartAuction is a log parse operation binding the contract event 0x683d0f47c7fa11331f4e9563b3f5a7fdc3d3c5b75c600357a91d991f5a13a437.
//
// Solidity: event StartAuction(uint256 indexed validatorId, uint256 indexed amount, uint256 indexed auctionAmount)
func (_Stakinginfo *StakinginfoFilterer) ParseStartAuction(log types.Log) (*StakinginfoStartAuction, error) {
	event := new(StakinginfoStartAuction)
	if err := _Stakinginfo.contract.UnpackLog(event, "StartAuction", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// StakinginfoThresholdChangeIterator is returned from FilterThresholdChange and is used to iterate over the raw logs and unpacked data for ThresholdChange events raised by the Stakinginfo contract.
type StakinginfoThresholdChangeIterator struct {
	Event *StakinginfoThresholdChange // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  appchain.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *StakinginfoThresholdChangeIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(StakinginfoThresholdChange)
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
		it.Event = new(StakinginfoThresholdChange)
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
func (it *StakinginfoThresholdChangeIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *StakinginfoThresholdChangeIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// StakinginfoThresholdChange represents a ThresholdChange event raised by the Stakinginfo contract.
type StakinginfoThresholdChange struct {
	NewThreshold *big.Int
	OldThreshold *big.Int
	Raw          types.Log // Blockchain specific contextual infos
}

// FilterThresholdChange is a free log retrieval operation binding the contract event 0x5d16a900896e1160c2033bc940e6b072d3dc3b6a996fefb9b3b9b9678841824c.
//
// Solidity: event ThresholdChange(uint256 newThreshold, uint256 oldThreshold)
func (_Stakinginfo *StakinginfoFilterer) FilterThresholdChange(opts *bind.FilterOpts) (*StakinginfoThresholdChangeIterator, error) {

	logs, sub, err := _Stakinginfo.contract.FilterLogs(opts, "ThresholdChange")
	if err != nil {
		return nil, err
	}
	return &StakinginfoThresholdChangeIterator{contract: _Stakinginfo.contract, event: "ThresholdChange", logs: logs, sub: sub}, nil
}

// WatchThresholdChange is a free log subscription operation binding the contract event 0x5d16a900896e1160c2033bc940e6b072d3dc3b6a996fefb9b3b9b9678841824c.
//
// Solidity: event ThresholdChange(uint256 newThreshold, uint256 oldThreshold)
func (_Stakinginfo *StakinginfoFilterer) WatchThresholdChange(opts *bind.WatchOpts, sink chan<- *StakinginfoThresholdChange) (event.Subscription, error) {

	logs, sub, err := _Stakinginfo.contract.WatchLogs(opts, "ThresholdChange")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(StakinginfoThresholdChange)
				if err := _Stakinginfo.contract.UnpackLog(event, "ThresholdChange", log); err != nil {
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

// ParseThresholdChange is a log parse operation binding the contract event 0x5d16a900896e1160c2033bc940e6b072d3dc3b6a996fefb9b3b9b9678841824c.
//
// Solidity: event ThresholdChange(uint256 newThreshold, uint256 oldThreshold)
func (_Stakinginfo *StakinginfoFilterer) ParseThresholdChange(log types.Log) (*StakinginfoThresholdChange, error) {
	event := new(StakinginfoThresholdChange)
	if err := _Stakinginfo.contract.UnpackLog(event, "ThresholdChange", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// StakinginfoTopUpFeeIterator is returned from FilterTopUpFee and is used to iterate over the raw logs and unpacked data for TopUpFee events raised by the Stakinginfo contract.
type StakinginfoTopUpFeeIterator struct {
	Event *StakinginfoTopUpFee // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  appchain.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *StakinginfoTopUpFeeIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(StakinginfoTopUpFee)
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
		it.Event = new(StakinginfoTopUpFee)
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
func (it *StakinginfoTopUpFeeIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *StakinginfoTopUpFeeIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// StakinginfoTopUpFee represents a TopUpFee event raised by the Stakinginfo contract.
type StakinginfoTopUpFee struct {
	User common.Address
	Fee  *big.Int
	Raw  types.Log // Blockchain specific contextual infos
}

// FilterTopUpFee is a free log retrieval operation binding the contract event 0x2c3bb5458e3dd671c31974c4ca8e8ebc2cdd892ae8602374d9a6f789b00c6b94.
//
// Solidity: event TopUpFee(address indexed user, uint256 indexed fee)
func (_Stakinginfo *StakinginfoFilterer) FilterTopUpFee(opts *bind.FilterOpts, user []common.Address, fee []*big.Int) (*StakinginfoTopUpFeeIterator, error) {

	var userRule []interface{}
	for _, userItem := range user {
		userRule = append(userRule, userItem)
	}
	var feeRule []interface{}
	for _, feeItem := range fee {
		feeRule = append(feeRule, feeItem)
	}

	logs, sub, err := _Stakinginfo.contract.FilterLogs(opts, "TopUpFee", userRule, feeRule)
	if err != nil {
		return nil, err
	}
	return &StakinginfoTopUpFeeIterator{contract: _Stakinginfo.contract, event: "TopUpFee", logs: logs, sub: sub}, nil
}

// WatchTopUpFee is a free log subscription operation binding the contract event 0x2c3bb5458e3dd671c31974c4ca8e8ebc2cdd892ae8602374d9a6f789b00c6b94.
//
// Solidity: event TopUpFee(address indexed user, uint256 indexed fee)
func (_Stakinginfo *StakinginfoFilterer) WatchTopUpFee(opts *bind.WatchOpts, sink chan<- *StakinginfoTopUpFee, user []common.Address, fee []*big.Int) (event.Subscription, error) {

	var userRule []interface{}
	for _, userItem := range user {
		userRule = append(userRule, userItem)
	}
	var feeRule []interface{}
	for _, feeItem := range fee {
		feeRule = append(feeRule, feeItem)
	}

	logs, sub, err := _Stakinginfo.contract.WatchLogs(opts, "TopUpFee", userRule, feeRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(StakinginfoTopUpFee)
				if err := _Stakinginfo.contract.UnpackLog(event, "TopUpFee", log); err != nil {
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

// ParseTopUpFee is a log parse operation binding the contract event 0x2c3bb5458e3dd671c31974c4ca8e8ebc2cdd892ae8602374d9a6f789b00c6b94.
//
// Solidity: event TopUpFee(address indexed user, uint256 indexed fee)
func (_Stakinginfo *StakinginfoFilterer) ParseTopUpFee(log types.Log) (*StakinginfoTopUpFee, error) {
	event := new(StakinginfoTopUpFee)
	if err := _Stakinginfo.contract.UnpackLog(event, "TopUpFee", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// StakinginfoUnJailedIterator is returned from FilterUnJailed and is used to iterate over the raw logs and unpacked data for UnJailed events raised by the Stakinginfo contract.
type StakinginfoUnJailedIterator struct {
	Event *StakinginfoUnJailed // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  appchain.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *StakinginfoUnJailedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(StakinginfoUnJailed)
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
		it.Event = new(StakinginfoUnJailed)
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
func (it *StakinginfoUnJailedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *StakinginfoUnJailedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// StakinginfoUnJailed represents a UnJailed event raised by the Stakinginfo contract.
type StakinginfoUnJailed struct {
	ValidatorId *big.Int
	Signer      common.Address
	Raw         types.Log // Blockchain specific contextual infos
}

// FilterUnJailed is a free log retrieval operation binding the contract event 0xd3cb87a9c75a0d21336afc0f79f7e398f06748db5ce1815af01d315c7c135c0b.
//
// Solidity: event UnJailed(uint256 indexed validatorId, address indexed signer)
func (_Stakinginfo *StakinginfoFilterer) FilterUnJailed(opts *bind.FilterOpts, validatorId []*big.Int, signer []common.Address) (*StakinginfoUnJailedIterator, error) {

	var validatorIdRule []interface{}
	for _, validatorIdItem := range validatorId {
		validatorIdRule = append(validatorIdRule, validatorIdItem)
	}
	var signerRule []interface{}
	for _, signerItem := range signer {
		signerRule = append(signerRule, signerItem)
	}

	logs, sub, err := _Stakinginfo.contract.FilterLogs(opts, "UnJailed", validatorIdRule, signerRule)
	if err != nil {
		return nil, err
	}
	return &StakinginfoUnJailedIterator{contract: _Stakinginfo.contract, event: "UnJailed", logs: logs, sub: sub}, nil
}

// WatchUnJailed is a free log subscription operation binding the contract event 0xd3cb87a9c75a0d21336afc0f79f7e398f06748db5ce1815af01d315c7c135c0b.
//
// Solidity: event UnJailed(uint256 indexed validatorId, address indexed signer)
func (_Stakinginfo *StakinginfoFilterer) WatchUnJailed(opts *bind.WatchOpts, sink chan<- *StakinginfoUnJailed, validatorId []*big.Int, signer []common.Address) (event.Subscription, error) {

	var validatorIdRule []interface{}
	for _, validatorIdItem := range validatorId {
		validatorIdRule = append(validatorIdRule, validatorIdItem)
	}
	var signerRule []interface{}
	for _, signerItem := range signer {
		signerRule = append(signerRule, signerItem)
	}

	logs, sub, err := _Stakinginfo.contract.WatchLogs(opts, "UnJailed", validatorIdRule, signerRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(StakinginfoUnJailed)
				if err := _Stakinginfo.contract.UnpackLog(event, "UnJailed", log); err != nil {
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

// ParseUnJailed is a log parse operation binding the contract event 0xd3cb87a9c75a0d21336afc0f79f7e398f06748db5ce1815af01d315c7c135c0b.
//
// Solidity: event UnJailed(uint256 indexed validatorId, address indexed signer)
func (_Stakinginfo *StakinginfoFilterer) ParseUnJailed(log types.Log) (*StakinginfoUnJailed, error) {
	event := new(StakinginfoUnJailed)
	if err := _Stakinginfo.contract.UnpackLog(event, "UnJailed", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// StakinginfoUnstakeInitIterator is returned from FilterUnstakeInit and is used to iterate over the raw logs and unpacked data for UnstakeInit events raised by the Stakinginfo contract.
type StakinginfoUnstakeInitIterator struct {
	Event *StakinginfoUnstakeInit // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  appchain.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *StakinginfoUnstakeInitIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(StakinginfoUnstakeInit)
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
		it.Event = new(StakinginfoUnstakeInit)
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
func (it *StakinginfoUnstakeInitIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *StakinginfoUnstakeInitIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// StakinginfoUnstakeInit represents a UnstakeInit event raised by the Stakinginfo contract.
type StakinginfoUnstakeInit struct {
	User              common.Address
	ValidatorId       *big.Int
	Nonce             *big.Int
	DeactivationEpoch *big.Int
	Amount            *big.Int
	Raw               types.Log // Blockchain specific contextual infos
}

// FilterUnstakeInit is a free log retrieval operation binding the contract event 0x69b288bb79cd5386c9fe0af060f650e823bcdfa96a44cdc07f862db060f57120.
//
// Solidity: event UnstakeInit(address indexed user, uint256 indexed validatorId, uint256 nonce, uint256 deactivationEpoch, uint256 indexed amount)
func (_Stakinginfo *StakinginfoFilterer) FilterUnstakeInit(opts *bind.FilterOpts, user []common.Address, validatorId []*big.Int, amount []*big.Int) (*StakinginfoUnstakeInitIterator, error) {

	var userRule []interface{}
	for _, userItem := range user {
		userRule = append(userRule, userItem)
	}
	var validatorIdRule []interface{}
	for _, validatorIdItem := range validatorId {
		validatorIdRule = append(validatorIdRule, validatorIdItem)
	}

	var amountRule []interface{}
	for _, amountItem := range amount {
		amountRule = append(amountRule, amountItem)
	}

	logs, sub, err := _Stakinginfo.contract.FilterLogs(opts, "UnstakeInit", userRule, validatorIdRule, amountRule)
	if err != nil {
		return nil, err
	}
	return &StakinginfoUnstakeInitIterator{contract: _Stakinginfo.contract, event: "UnstakeInit", logs: logs, sub: sub}, nil
}

// WatchUnstakeInit is a free log subscription operation binding the contract event 0x69b288bb79cd5386c9fe0af060f650e823bcdfa96a44cdc07f862db060f57120.
//
// Solidity: event UnstakeInit(address indexed user, uint256 indexed validatorId, uint256 nonce, uint256 deactivationEpoch, uint256 indexed amount)
func (_Stakinginfo *StakinginfoFilterer) WatchUnstakeInit(opts *bind.WatchOpts, sink chan<- *StakinginfoUnstakeInit, user []common.Address, validatorId []*big.Int, amount []*big.Int) (event.Subscription, error) {

	var userRule []interface{}
	for _, userItem := range user {
		userRule = append(userRule, userItem)
	}
	var validatorIdRule []interface{}
	for _, validatorIdItem := range validatorId {
		validatorIdRule = append(validatorIdRule, validatorIdItem)
	}

	var amountRule []interface{}
	for _, amountItem := range amount {
		amountRule = append(amountRule, amountItem)
	}

	logs, sub, err := _Stakinginfo.contract.WatchLogs(opts, "UnstakeInit", userRule, validatorIdRule, amountRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(StakinginfoUnstakeInit)
				if err := _Stakinginfo.contract.UnpackLog(event, "UnstakeInit", log); err != nil {
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

// ParseUnstakeInit is a log parse operation binding the contract event 0x69b288bb79cd5386c9fe0af060f650e823bcdfa96a44cdc07f862db060f57120.
//
// Solidity: event UnstakeInit(address indexed user, uint256 indexed validatorId, uint256 nonce, uint256 deactivationEpoch, uint256 indexed amount)
func (_Stakinginfo *StakinginfoFilterer) ParseUnstakeInit(log types.Log) (*StakinginfoUnstakeInit, error) {
	event := new(StakinginfoUnstakeInit)
	if err := _Stakinginfo.contract.UnpackLog(event, "UnstakeInit", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// StakinginfoUnstakedIterator is returned from FilterUnstaked and is used to iterate over the raw logs and unpacked data for Unstaked events raised by the Stakinginfo contract.
type StakinginfoUnstakedIterator struct {
	Event *StakinginfoUnstaked // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  appchain.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *StakinginfoUnstakedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(StakinginfoUnstaked)
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
		it.Event = new(StakinginfoUnstaked)
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
func (it *StakinginfoUnstakedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *StakinginfoUnstakedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// StakinginfoUnstaked represents a Unstaked event raised by the Stakinginfo contract.
type StakinginfoUnstaked struct {
	User        common.Address
	ValidatorId *big.Int
	Amount      *big.Int
	Total       *big.Int
	Raw         types.Log // Blockchain specific contextual infos
}

// FilterUnstaked is a free log retrieval operation binding the contract event 0x204fccf0d92ed8d48f204adb39b2e81e92bad0dedb93f5716ca9478cfb57de00.
//
// Solidity: event Unstaked(address indexed user, uint256 indexed validatorId, uint256 amount, uint256 total)
func (_Stakinginfo *StakinginfoFilterer) FilterUnstaked(opts *bind.FilterOpts, user []common.Address, validatorId []*big.Int) (*StakinginfoUnstakedIterator, error) {

	var userRule []interface{}
	for _, userItem := range user {
		userRule = append(userRule, userItem)
	}
	var validatorIdRule []interface{}
	for _, validatorIdItem := range validatorId {
		validatorIdRule = append(validatorIdRule, validatorIdItem)
	}

	logs, sub, err := _Stakinginfo.contract.FilterLogs(opts, "Unstaked", userRule, validatorIdRule)
	if err != nil {
		return nil, err
	}
	return &StakinginfoUnstakedIterator{contract: _Stakinginfo.contract, event: "Unstaked", logs: logs, sub: sub}, nil
}

// WatchUnstaked is a free log subscription operation binding the contract event 0x204fccf0d92ed8d48f204adb39b2e81e92bad0dedb93f5716ca9478cfb57de00.
//
// Solidity: event Unstaked(address indexed user, uint256 indexed validatorId, uint256 amount, uint256 total)
func (_Stakinginfo *StakinginfoFilterer) WatchUnstaked(opts *bind.WatchOpts, sink chan<- *StakinginfoUnstaked, user []common.Address, validatorId []*big.Int) (event.Subscription, error) {

	var userRule []interface{}
	for _, userItem := range user {
		userRule = append(userRule, userItem)
	}
	var validatorIdRule []interface{}
	for _, validatorIdItem := range validatorId {
		validatorIdRule = append(validatorIdRule, validatorIdItem)
	}

	logs, sub, err := _Stakinginfo.contract.WatchLogs(opts, "Unstaked", userRule, validatorIdRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(StakinginfoUnstaked)
				if err := _Stakinginfo.contract.UnpackLog(event, "Unstaked", log); err != nil {
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

// ParseUnstaked is a log parse operation binding the contract event 0x204fccf0d92ed8d48f204adb39b2e81e92bad0dedb93f5716ca9478cfb57de00.
//
// Solidity: event Unstaked(address indexed user, uint256 indexed validatorId, uint256 amount, uint256 total)
func (_Stakinginfo *StakinginfoFilterer) ParseUnstaked(log types.Log) (*StakinginfoUnstaked, error) {
	event := new(StakinginfoUnstaked)
	if err := _Stakinginfo.contract.UnpackLog(event, "Unstaked", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// StakinginfoUpdateCommissionRateIterator is returned from FilterUpdateCommissionRate and is used to iterate over the raw logs and unpacked data for UpdateCommissionRate events raised by the Stakinginfo contract.
type StakinginfoUpdateCommissionRateIterator struct {
	Event *StakinginfoUpdateCommissionRate // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  appchain.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *StakinginfoUpdateCommissionRateIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(StakinginfoUpdateCommissionRate)
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
		it.Event = new(StakinginfoUpdateCommissionRate)
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
func (it *StakinginfoUpdateCommissionRateIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *StakinginfoUpdateCommissionRateIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// StakinginfoUpdateCommissionRate represents a UpdateCommissionRate event raised by the Stakinginfo contract.
type StakinginfoUpdateCommissionRate struct {
	ValidatorId       *big.Int
	NewCommissionRate *big.Int
	OldCommissionRate *big.Int
	Raw               types.Log // Blockchain specific contextual infos
}

// FilterUpdateCommissionRate is a free log retrieval operation binding the contract event 0x7d5da5ece9d43013d62ab966f4704ca376b92be29ca6fbb958154baf1c0dc17e.
//
// Solidity: event UpdateCommissionRate(uint256 indexed validatorId, uint256 indexed newCommissionRate, uint256 indexed oldCommissionRate)
func (_Stakinginfo *StakinginfoFilterer) FilterUpdateCommissionRate(opts *bind.FilterOpts, validatorId []*big.Int, newCommissionRate []*big.Int, oldCommissionRate []*big.Int) (*StakinginfoUpdateCommissionRateIterator, error) {

	var validatorIdRule []interface{}
	for _, validatorIdItem := range validatorId {
		validatorIdRule = append(validatorIdRule, validatorIdItem)
	}
	var newCommissionRateRule []interface{}
	for _, newCommissionRateItem := range newCommissionRate {
		newCommissionRateRule = append(newCommissionRateRule, newCommissionRateItem)
	}
	var oldCommissionRateRule []interface{}
	for _, oldCommissionRateItem := range oldCommissionRate {
		oldCommissionRateRule = append(oldCommissionRateRule, oldCommissionRateItem)
	}

	logs, sub, err := _Stakinginfo.contract.FilterLogs(opts, "UpdateCommissionRate", validatorIdRule, newCommissionRateRule, oldCommissionRateRule)
	if err != nil {
		return nil, err
	}
	return &StakinginfoUpdateCommissionRateIterator{contract: _Stakinginfo.contract, event: "UpdateCommissionRate", logs: logs, sub: sub}, nil
}

// WatchUpdateCommissionRate is a free log subscription operation binding the contract event 0x7d5da5ece9d43013d62ab966f4704ca376b92be29ca6fbb958154baf1c0dc17e.
//
// Solidity: event UpdateCommissionRate(uint256 indexed validatorId, uint256 indexed newCommissionRate, uint256 indexed oldCommissionRate)
func (_Stakinginfo *StakinginfoFilterer) WatchUpdateCommissionRate(opts *bind.WatchOpts, sink chan<- *StakinginfoUpdateCommissionRate, validatorId []*big.Int, newCommissionRate []*big.Int, oldCommissionRate []*big.Int) (event.Subscription, error) {

	var validatorIdRule []interface{}
	for _, validatorIdItem := range validatorId {
		validatorIdRule = append(validatorIdRule, validatorIdItem)
	}
	var newCommissionRateRule []interface{}
	for _, newCommissionRateItem := range newCommissionRate {
		newCommissionRateRule = append(newCommissionRateRule, newCommissionRateItem)
	}
	var oldCommissionRateRule []interface{}
	for _, oldCommissionRateItem := range oldCommissionRate {
		oldCommissionRateRule = append(oldCommissionRateRule, oldCommissionRateItem)
	}

	logs, sub, err := _Stakinginfo.contract.WatchLogs(opts, "UpdateCommissionRate", validatorIdRule, newCommissionRateRule, oldCommissionRateRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(StakinginfoUpdateCommissionRate)
				if err := _Stakinginfo.contract.UnpackLog(event, "UpdateCommissionRate", log); err != nil {
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

// ParseUpdateCommissionRate is a log parse operation binding the contract event 0x7d5da5ece9d43013d62ab966f4704ca376b92be29ca6fbb958154baf1c0dc17e.
//
// Solidity: event UpdateCommissionRate(uint256 indexed validatorId, uint256 indexed newCommissionRate, uint256 indexed oldCommissionRate)
func (_Stakinginfo *StakinginfoFilterer) ParseUpdateCommissionRate(log types.Log) (*StakinginfoUpdateCommissionRate, error) {
	event := new(StakinginfoUpdateCommissionRate)
	if err := _Stakinginfo.contract.UnpackLog(event, "UpdateCommissionRate", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}
