package monitor

import (
	"encoding/hex"
	"github.com/PlatONnetwork/AppChain-Go/accounts/abi"
	"github.com/PlatONnetwork/AppChain-Go/common"
	"github.com/PlatONnetwork/AppChain-Go/common/hexutil"
	"github.com/PlatONnetwork/AppChain-Go/log"
	"golang.org/x/crypto/sha3"
	"math/big"
	"strings"
)

type StateDB interface {
	GetState(common.Address, []byte) []byte
	GetCode(common.Address) []byte
	TxHash() common.Hash
}

type ContractType int

const (
	EVM     ContractType = iota + 1 //1, start with 1
	WASM                            //2
	_                               //3, skipped
	ERC20                           //4
	ERC721                          //5
	ERC1155                         //6
)

// 定义 MonitorDbKey 类型的方法 String(), 返回字符串。
func (t ContractType) String() string {
	return [...]string{
		"EVM",
		"WASM",
		"UNKNOWN",
		"ERC20",
		"ERC721",
		"ERC1155",
	}[t]
}

var (
	// 返回方法签名的hash, 这个hash将出现在合约的bin中，为了方便比较，返回hash的string(不含0x前缀)
	evmFuncHashBytes = func(funcName string) []byte {
		prefix := sha3.NewLegacyKeccak256()
		prefix.Write([]byte(funcName))
		return prefix.Sum(nil)[:4]
	}

	evmFuncHash = func(funcName string) string {
		prefix := sha3.NewLegacyKeccak256()
		prefix.Write([]byte(funcName))
		bin := hexutil.Encode(prefix.Sum(nil)[:4])
		binHex := bin[2:]
		found00 := false
		for {
			binHex, found00 = strings.CutPrefix(binHex, "00")
			if !found00 {
				break
			}
		}
		return binHex
	}

	keccak256_eip1967 = func(data string) string {
		prefix := sha3.NewLegacyKeccak256()
		prefix.Write([]byte(data))
		bytes := prefix.Sum(nil)

		z := new(big.Int).SetBytes(bytes)
		z = z.Sub(z, big.NewInt(1))
		return hexutil.Encode(z.Bytes())[2:] //remove the prefix 0x
	}
	keccak256_zeppelin = func(data string) string {
		prefix := sha3.NewLegacyKeccak256()
		prefix.Write([]byte(data))
		bytes := prefix.Sum(nil)
		return hexutil.Encode(bytes)[2:] //remove the prefix 0x
	}

	implSlotOfEip1967  = keccak256_eip1967("eip1967.proxy.implementation")
	adminSlotOfEip1967 = keccak256_eip1967("eip1967.proxy.admin")

	implSlotZeppelinos    = keccak256_zeppelin("org.zeppelinos.proxy.implementation")
	adminSlotOfZeppelinos = keccak256_zeppelin("org.zeppelinos.proxy.admin")
)

type ContractInfo struct {
	Address                   common.Address `json:"address"`
	Code                      []byte         `json:"-"`
	Bin                       string         `json:"-"`
	Type                      ContractType   `json:"contractType"` // 0 should be returned also
	TokenName                 string         `json:"tokenName,omitempty"`
	TokenSymbol               string         `json:"tokenSymbol,omitempty"`
	TokenDecimals             uint8          `json:"tokenDecimals,omitempty"`
	TokenTotalSupply          *big.Int       `json:"tokenTotalSupply,omitempty"`
	IsSupportErc721Metadata   bool           `json:"isSupportErc721Metadata,omitempty"`
	IsSupportErc721Enumerable bool           `json:"isSupportErc721Enumerable,omitempty"`
	IsSupportErc1155Metadata  bool           `json:"isSupportErc1155Metadata,omitempty"`
}

func NewContractInfo(address common.Address, code []byte) *ContractInfo {
	instance := new(ContractInfo)
	instance.Address = address
	instance.Code = code
	instance.Type = EVM
	if len(code) > 0 {
		binHex := hex.EncodeToString(code)
		instance.Bin = binHex
		instance.Type = getType(instance.Bin)
		if instance.Type == ERC721 {
			instance.IsSupportErc721Metadata = isERC721Metadata(binHex)
			instance.IsSupportErc721Enumerable = isERC721Enumerable(binHex)
		}
		if instance.Type == ERC1155 {
			instance.IsSupportErc1155Metadata = isERC1155Metadata(binHex)
		}
	}
	return instance
}

func (c *ContractInfo) matchProxyPattern() bool {
	return c.Type == EVM &&
		((strings.Index(c.Bin, adminSlotOfEip1967) != -1 && strings.Index(c.Bin, implSlotOfEip1967) != -1) ||
			(strings.Index(c.Bin, adminSlotOfZeppelinos) != -1 && strings.Index(c.Bin, implSlotZeppelinos) != -1))
}

func getType(binHex string) ContractType {
	if isERC20(binHex) {
		return ERC20
	} else if isERC165(binHex) {
		if isERC721(binHex) {
			return ERC721
		} else if isERC1155(binHex) {
			return ERC1155
		}
	}
	//参考：com.platon.browser.decoder.TxInputDecodeUtil#isWASM
	//"0x0061736d"
	if strings.Contains(binHex, "0061736d") {
		return WASM
	}

	return EVM
}

func isERC20(binHex string) bool {
	return implementsAll(binHex,
		"totalSupply()",
		"balanceOf(address)",
		"transfer(address,uint256)",
		"transferFrom(address,address,uint256)",
		"approve(address,uint256)",
		"allowance(address,address)")
}

var (
	InputForName        = evmFuncHashBytes("name()")
	InputForSymbol      = evmFuncHashBytes("symbol()")
	InputForDecimals    = evmFuncHashBytes("decimals()")
	InputForTotalSupply = evmFuncHashBytes("totalSupply()")
)

func isERC165(binHex string) bool {
	return implements(binHex, "supportsInterface(bytes4)")
}

func isERC721(binHex string) bool {
	return implementsAll(binHex,
		"balanceOf(address)",
		"ownerOf(uint256)",
		"approve(address,uint256)",
		"getApproved(uint256)",
		"setApprovalForAll(address,bool)",
		"isApprovedForAll(address,address)",
		"transferFrom(address,address,uint256)",
		"safeTransferFrom(address,address,uint256)",
		"safeTransferFrom(address,address,uint256,bytes)")
}
func isERC721Metadata(binHex string) bool {
	return implementsAll(binHex,
		"name()",
		"symbol()",
		"tokenURI(uint256)")
}

func isERC721Enumerable(binHex string) bool {
	return implementsAll(binHex,
		"totalSupply()",
		"tokenByIndex(uint256)",
		"tokenOfOwnerByIndex(address,uint256)")
}

func isERC1155(binHex string) bool {
	return implementsAll(binHex,
		"safeTransferFrom(address,address,uint256,uint256,bytes)",
		"safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)",
		"balanceOf(address,uint256)",
		"balanceOfBatch(address[],uint256[])",
		"setApprovalForAll(address,bool)",
		"isApprovedForAll(address,address)")
}
func isERC1155Metadata(binHex string) bool {
	return implements(binHex, "uri(uint256)")
}

func implements(binHex string, funcName string) bool {
	return strings.Index(binHex, evmFuncHash(funcName)) != -1
}

func implementsAll(binHex string, funcNames ...string) bool {
	for _, funcName := range funcNames {
		if !implements(binHex, funcName) {
			return false
		}
	}
	return true
}

func implementsAnyOf(binHex string, funcNames ...string) bool {
	for _, funcName := range funcNames {
		if implements(binHex, funcName) {
			return true
		}
	}
	return false
}

var abiStringType, _ = abi.NewType("string", "", nil)
var abiUint8Type, _ = abi.NewType("uint8", "", nil)
var abiUint256Type, _ = abi.NewType("uint256", "", nil)
var abiAddressType, _ = abi.NewType("address", "", nil)
var erc20Methods = map[string]abi.Method{
	"balanceOf":   abi.NewMethod("balanceOf", "balanceOf", abi.Function, "view", false, false, []abi.Argument{{"address", abiAddressType, false}}, []abi.Argument{{"amount", abiUint256Type, false}}),
	"name":        abi.NewMethod("name", "name", abi.Function, "view", false, false, nil, []abi.Argument{{"nameStr", abiStringType, false}}),
	"symbol":      abi.NewMethod("symbol", "symbol", abi.Function, "view", false, false, nil, []abi.Argument{{"symbolStr", abiStringType, false}}),
	"decimals":    abi.NewMethod("decimals", "decimals", abi.Function, "view", false, false, nil, []abi.Argument{{"num", abiUint8Type, false}}),
	"totalSupply": abi.NewMethod("totalSupply", "totalSupply", abi.Function, "view", false, false, nil, []abi.Argument{{"symbol", abiUint256Type, false}}),
}

var erc20Abi = abi.ABI{
	Methods: erc20Methods,
}

func UnpackName(callOutput []byte) string {
	ret, err := erc20Abi.Unpack("name", callOutput)
	if err != nil || len(ret) == 0 {
		return string([]byte{})
	} else {
		name, ok := ret[0].(string)
		if ok {
			return name
		} else {
			return string([]byte{})
		}
	}
}

func UnpackSymbol(callOutput []byte) string {
	ret, err := erc20Abi.Unpack("symbol", callOutput)
	if err != nil || len(ret) == 0 {
		return string([]byte{})
	} else {
		name, ok := ret[0].(string)
		if ok {
			return name
		} else {
			return string([]byte{})
		}
	}
}

func UnpackDecimals(callOutput []byte) uint8 {
	ret, err := erc20Abi.Unpack("decimals", callOutput)
	if err != nil || len(ret) == 0 {
		return 0
	} else {
		decimals, ok := ret[0].(uint8)
		if ok {
			return decimals
		} else {
			return 0
		}
	}
}

func UnpackTotalSupply(callOutput []byte) *big.Int {
	ret, err := erc20Abi.Unpack("totalSupply", callOutput)
	log.Debug("UnpackTotalSupply", "callOutput", callOutput, "pack ret", ret)
	if err != nil || len(ret) == 0 {
		return big.NewInt(0)
	} else {
		log.Debug("UnpackTotalSupply", "callOutput[0]", ret[0])
		totalSupply, ok := ret[0].(*big.Int)
		if ok {
			return totalSupply
		} else {
			return big.NewInt(0)
		}
	}
}
