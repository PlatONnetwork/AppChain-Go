package manager

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"
	"os"
	"sync"

	"github.com/PlatONnetwork/AppChain-Go/accounts/keystore"
	"github.com/PlatONnetwork/AppChain-Go/common"
	"github.com/PlatONnetwork/AppChain-Go/core/types"
	"github.com/PlatONnetwork/AppChain-Go/crypto"
	"github.com/PlatONnetwork/AppChain-Go/log"
	etypes "github.com/ethereum/go-ethereum/core/types"
)

type GetNonceFunc func(addr common.Address) uint64

type ManagerAccount struct {
	mutex   sync.Mutex
	NonceFn GetNonceFunc
	private *ecdsa.PrivateKey
	nonce   uint64
	address common.Address
	log     log.Logger
	signer  types.Signer
}

func NewManagerAccount(path string, passphrase string, nonceFn GetNonceFunc, chainId *big.Int) (*ManagerAccount, error) {
	json, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := keystore.DecryptKey(json, passphrase)
	if err != nil {
		return nil, err
	}
	nonce := nonceFn(key.Address)
	return &ManagerAccount{
		NonceFn: nonceFn,
		private: key.PrivateKey,
		nonce:   nonce,
		address: key.Address,
		signer:  types.NewPIP11Signer(chainId, chainId),
		log:     log.New(),
	}, nil
}
func (m *ManagerAccount) Address() common.Address {
	return m.address
}

func (m *ManagerAccount) Nonce() uint64 {
	/*
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if err := m.checkNonce(); err != nil {
		m.log.Warn("check nonce exception", "err", err)
	}
	nonce := m.nonce
	m.nonce++
	return nonce
	*/
	return m.NonceFn(m.address)
}
func (m *ManagerAccount) checkNonce() error {
	nonce := m.NonceFn(m.address)
	distance := func(a, b uint64) uint64 {
		if a < b {
			a, b = b, a
		}
		return a - b
	}
	if distance(m.nonce, nonce) > 5 {
		return errors.New(fmt.Sprintf("nonce is too big, cache:%d, state:%d", m.nonce, nonce))
	}
	return nil
}
func (m *ManagerAccount) ResetState() error {
	nonce := m.NonceFn(m.address)

	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.nonce = nonce
	return nil
}

func (m *ManagerAccount) Reset(nonce uint64) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.nonce = nonce
}

func (m *ManagerAccount) Sign(tx *types.Transaction, chainId *big.Int) (*types.Transaction, error) {
	signer := m.signer
	if chainId != nil {
		signer = types.NewPIP11Signer(chainId, chainId)
	}
	signature, err := crypto.Sign(signer.Hash(tx, chainId).Bytes(), m.private)
	if err != nil {
		return nil, err
	}
	tx, err = tx.WithSignature(signer, signature)
	return tx, nil
}

func (m *ManagerAccount) SignEthTx(tx *etypes.Transaction, chainId *big.Int) (*etypes.Transaction, error) {
	return etypes.SignTx(tx, etypes.NewEIP155Signer(chainId), m.private)
}
