package manager

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"github.com/PlatONnetwork/AppChain-Go/accounts/keystore"
	"github.com/PlatONnetwork/AppChain-Go/common"
	"github.com/PlatONnetwork/AppChain-Go/core/types"
	"github.com/PlatONnetwork/AppChain-Go/crypto"
	"github.com/PlatONnetwork/AppChain-Go/log"
	"math/big"
	"os"
	"sync"
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
		signer:  types.NewEIP155Signer(chainId),
		log:     log.New(),
	}, nil
}
func (m *ManagerAccount) Address() common.Address {
	return m.address
}

func (m *ManagerAccount) Nonce() uint64 {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if err := m.checkNonce(); err != nil {
		m.log.Warn("check nonce exception", "err", err)
	}
	nonce := m.nonce
	m.nonce++
	return nonce
}
func (m *ManagerAccount) checkNonce() error {
	nonce := m.NonceFn(m.address)
	if m.nonce-nonce > 5 {
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
	signature, err := crypto.Sign(m.signer.Hash(tx, chainId).Bytes(), m.private)
	if err != nil {
		return nil, err
	}
	tx, err = tx.WithSignature(m.signer, signature)
	return tx, nil
}
