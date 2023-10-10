// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package types

import (
	"bytes"
	"fmt"
	"hash"
	"math/big"
	"reflect"
	"strconv"
	"testing"

	"github.com/PlatONnetwork/AppChain-Go/common/math"
	"github.com/PlatONnetwork/AppChain-Go/crypto"
	"github.com/PlatONnetwork/AppChain-Go/params"

	"golang.org/x/crypto/sha3"

	"github.com/PlatONnetwork/AppChain-Go/common/hexutil"

	"github.com/PlatONnetwork/AppChain-Go/common"
	"github.com/PlatONnetwork/AppChain-Go/rlp"
)

// testHasher is the helper tool for transaction/receipt list hashing.
// The original hasher is trie, in order to get rid of import cycle,
// use the testing hasher instead.
type testHasher struct {
	hasher hash.Hash
}

func newHasher() *testHasher {
	return &testHasher{hasher: sha3.NewLegacyKeccak256()}
}

func (h *testHasher) Reset() {
	h.hasher.Reset()
}

func (h *testHasher) Update(key, val []byte) {
	h.hasher.Write(key)
	h.hasher.Write(val)
}

func (h *testHasher) Hash() common.Hash {
	return common.BytesToHash(h.hasher.Sum(nil))
}
func Test_sealHash2(t *testing.T) {
	header := new(Header)

	header.ParentHash = common.BytesToHash(hexutil.MustDecode("0xef99021b30d7caab822ff0629ba213a9be72d241b89cfe4a555d231066445f32"))

	coinbase, err := common.StringToAddress("0x1a57A5924C11691a1120A952FeC87B005bA11e75")
	if err != nil {
		t.Fatal(err)
	}
	header.Coinbase = coinbase

	header.Root = common.BytesToHash(hexutil.MustDecode("0xd6577cfd7dc0eb4ac937edfa1ff878fe253044799c28448664cbd101e1a9db69"))
	header.TxHash = common.BytesToHash(hexutil.MustDecode("0xd84e10d732662132f79c0f156d2a5744ac086af1f2dd7e79061e59cfd00ad0db"))
	header.ReceiptHash = common.BytesToHash(hexutil.MustDecode("0x27c539ea5678c560835cc2beadbc28fa773b46bd1e89a3f62626cd13d57bdffb"))
	header.Bloom = BytesToBloom(hexutil.MustDecode("0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000080000000000000008000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000000020000000000080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"))
	header.Number = common.Big1

	gasLimit, err := strconv.ParseInt("201403126", 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	header.GasLimit = uint64(gasLimit)

	gasUsed, err := strconv.ParseInt("21508", 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	header.GasUsed = uint64(gasUsed)

	time, err := strconv.ParseInt("1696927699078", 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	header.Time = uint64(time)
	header.Extra = hexutil.MustDecode("0xda830104008868736b636861696e86676f312e3230856c696e7578000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001e49d73")

	header.Nonce = EncodeNonce(hexutil.MustDecode("0x03eaa12a2503b4968818bdc0f95f7da28c21417a83fa4220364b8524869f280e6f7bef29c3a4c2314fa7f5b0bdfb28c40c9e05c823ea853a14c0a3898dcce4024a1f6a59599f7adff1ad7f05b2b4d3f9af"))

	sealHash := header._sealHash()
	fmt.Println(sealHash.Hex())
}

func Test_sealHash(t *testing.T) {

	hasher := sha3.NewLegacyKeccak256()

	parentHash := common.BytesToHash(hexutil.MustDecode("0xef99021b30d7caab822ff0629ba213a9be72d241b89cfe4a555d231066445f32"))
	coinbase, _ := common.StringToAddress("hsk1rft6tyjvz9535yfq49f0ajrmqpd6z8n45uxnck")
	root := common.BytesToHash(hexutil.MustDecode("0x0a3790512bca18581f67e583b82536930db384304d68986d0ea3b6604ed3694c"))
	txHash := common.BytesToHash(hexutil.MustDecode("0xd84e10d732662132f79c0f156d2a5744ac086af1f2dd7e79061e59cfd00ad0db"))
	receiptHash := common.BytesToHash(hexutil.MustDecode("0x27c539ea5678c560835cc2beadbc28fa773b46bd1e89a3f62626cd13d57bdffb"))
	bloom := BytesToBloom(hexutil.MustDecode("0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000080000000000000008000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000000020000000000080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"))
	number := common.Big1
	gasLimit, _ := strconv.ParseInt("0xc012af6", 16, 64)
	gasLimitUint64 := uint64(gasLimit)

	gasUsed, _ := strconv.ParseInt("0x5404", 16, 64)
	gasUsedUint64 := uint64(gasUsed)

	time, _ := strconv.ParseInt("0x65236e1a", 16, 64)
	timeUint64 := uint64(time)
	extra := hexutil.MustDecode("0xda830104008868736b636861696e86676f312e3230856c696e75780000000000")

	var nonce BlockNonce
	nonce.UnmarshalText(hexutil.MustDecode("0x03eaa12a2503b496"))

	rlp.Encode(hasher, []interface{}{
		parentHash,
		coinbase,
		root,
		txHash,
		receiptHash,
		bloom,
		number,
		gasLimitUint64,
		gasUsedUint64,
		timeUint64,
		extra,
		nonce,
	})

	var hash common.Hash
	hasher.Sum(hash[:0])
	fmt.Println(hash.Hex())

}

// from bcValidBlockTest.json, "SimpleTx"
func TestBlockEncoding(t *testing.T) {
	blockEnc := common.FromHex("f90264f901fda00000000000000000000000000000000000000000000000000000000000000000948888f1f195afa192cfee860698584c030f4c9db1a0ef1552a40b7165c3cd773806b9e0c165b75356e0314bf0706f279c729f51e017a00000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000000b901000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080832fefd8825208845506eb0780b8510376e56dffd12ab53bb149bda4e0cbce2b6aabe4cccc0df0b5a39e12977a2fcd23000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f861f85f800a82c35094095e7baea6a6c7c4c2dfeb977efac326af552d870a8023a09bea4c4daac7c7c52e093e6a4c35dbbcf8856f1af7b059ba20253e70848d094fa08a8fae537ce25ed8cb5af9adac3f141af69bd515bd2ba031522df09b97dd72b180")
	var block Block
	if err := rlp.DecodeBytes(blockEnc, &block); err != nil {
		t.Fatal("decode error: ", err)
	}

	check := func(f string, got, want interface{}) {
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s mismatch: got %v, want %v", f, got, want)
		}
	}
	check("GasLimit", block.GasLimit(), uint64(3141592))
	check("GasUsed", block.GasUsed(), uint64(21000))
	check("Coinbase", block.Coinbase(), common.MustBech32ToAddress("lax13zy0ruv447se9nlwscrfskzvqv85e8d35gau40"))
	check("Root", block.Root(), common.HexToHash("ef1552a40b7165c3cd773806b9e0c165b75356e0314bf0706f279c729f51e017"))
	check("Hash", block.Hash(), common.HexToHash("499987a73fa100f582328c92c1239262edf5c0a3479face652c89f60314aa805"))
	check("Nonce", block.Nonce(), EncodeNonce(hexutil.MustDecode("0x0376e56dffd12ab53bb149bda4e0cbce2b6aabe4cccc0df0b5a39e12977a2fcd23")).Bytes())
	check("Time", block.Time(), uint64(1426516743))
	check("Size", block.Size(), common.StorageSize(len(blockEnc)))

	tx1 := NewTransaction(0, common.MustBech32ToAddress("lax1p908ht4x5mrufsklawtha7kry6h42tv8sxxrdc"), big.NewInt(10), 50000, big.NewInt(10), nil)

	tx1, _ = tx1.WithSignature(NewEIP155Signer(new(big.Int)), common.Hex2Bytes("9bea4c4daac7c7c52e093e6a4c35dbbcf8856f1af7b059ba20253e70848d094f8a8fae537ce25ed8cb5af9adac3f141af69bd515bd2ba031522df09b97dd72b100"))
	fmt.Println(block.Transactions()[0].Hash())
	fmt.Println(tx1.data)
	fmt.Println(tx1.Hash())
	check("len(Transactions)", len(block.Transactions()), 1)
	check("Transactions[0].Hash", block.Transactions()[0].Hash(), tx1.Hash())

	ourBlockEnc, err := rlp.EncodeToBytes(&block)
	if err != nil {
		t.Fatal("encode error: ", err)
	}
	if !bytes.Equal(ourBlockEnc, blockEnc) {
		t.Errorf("encoded block mismatch:\ngot:  %x\nwant: %x", ourBlockEnc, blockEnc)
	}
}

var benchBuffer = bytes.NewBuffer(make([]byte, 0, 32000))

func BenchmarkEncodeBlock(b *testing.B) {
	block := makeBenchBlock()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		benchBuffer.Reset()
		if err := rlp.Encode(benchBuffer, block); err != nil {
			b.Fatal(err)
		}
	}
}

func makeBenchBlock() *Block {
	var (
		key, _   = crypto.GenerateKey()
		txs      = make([]*Transaction, 70)
		receipts = make([]*Receipt, len(txs))
		signer   = NewEIP155Signer(params.TestChainConfig.ChainID)
		uncles   = make([]*Header, 3)
	)
	header := &Header{
		Number:   math.BigPow(2, 9),
		GasLimit: 12345678,
		GasUsed:  1476322,
		Time:     9876543,
		Extra:    []byte("coolest block on chain"),
	}
	for i := range txs {
		amount := math.BigPow(2, int64(i))
		price := big.NewInt(300000)
		data := make([]byte, 100)
		tx := NewTransaction(uint64(i), common.Address{}, amount, 123457, price, data)
		signedTx, err := SignTx(tx, signer, key)
		if err != nil {
			panic(err)
		}
		txs[i] = signedTx
		receipts[i] = NewReceipt(make([]byte, 32), false, tx.Gas())
	}
	for i := range uncles {
		uncles[i] = &Header{
			Number:   math.BigPow(2, 9),
			GasLimit: 12345678,
			GasUsed:  1476322,
			Time:     9876543,
			Extra:    []byte("benchmark uncle"),
		}
	}
	return NewBlock(header, txs, receipts, newHasher())
}
