package evm

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// Default RPC and registry addresses
const (
	DefaultRPCURL       = "https://sepolia.base.org"
	DefaultNameRegistry = "0x73094B9DAb2421878A20Abed1497001fbD51302c"
	DefaultDIDRegistry  = "0x8046284116C5ac6724adbBf860feBeA85692d574"
)

// Client is a minimal Ethereum JSON-RPC client.
type Client struct {
	RPCURL string
	HTTP   *http.Client
}

// NewClient returns a new EVM RPC client.
func NewClient(rpcURL string) *Client {
	if rpcURL == "" {
		rpcURL = DefaultRPCURL
	}
	return &Client{
		RPCURL: rpcURL,
		HTTP: &http.Client{
			Timeout: 15 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) > 10 {
					return http.ErrUseLastResponse
				}
				if len(via) > 0 {
					prev := via[len(via)-1]
					// Security: Only allow same-origin redirects to prevent redirect hijacking/SSRF
					if prev.URL.Scheme != req.URL.Scheme || prev.URL.Host != req.URL.Host {
						return http.ErrUseLastResponse
					}
				}
				return nil
			},
		},
	}
}

// EthCall executes an eth_call RPC.
func (c *Client) EthCall(toAddress, dataHex string) ([]byte, error) {
	if !strings.HasPrefix(dataHex, "0x") {
		dataHex = "0x" + dataHex
	}

	reqBody, err := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "eth_call",
		"params": []interface{}{
			map[string]string{
				"to":   toAddress,
				"data": dataHex,
			},
			"latest",
		},
	})
	if err != nil {
		return nil, err
	}

	resp, err := c.HTTP.Post(c.RPCURL, "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("eth_call failed: %w", err)
	}
	defer resp.Body.Close()

	var rpcResp struct {
		Result string `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		return nil, fmt.Errorf("decoding RPC response: %w", err)
	}

	if rpcResp.Error != nil {
		return nil, fmt.Errorf("RPC error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}

	hexStr := strings.TrimPrefix(rpcResp.Result, "0x")
	return hex.DecodeString(hexStr)
}

// EncodeFunctionSignature returns the 4-byte selector.
func EncodeFunctionSignature(sig string) []byte {
	return Keccak256([]byte(sig))[:4]
}

// EncodeStringParameter encodes a dynamic string argument per ABI specs.
// Optimized to single buffer allocation and binary big-endian encoding.
func EncodeStringParameter(s string) []byte {
	strBytes := []byte(s)
	dataLen := ((len(strBytes) + 31) / 32) * 32
	res := make([]byte, 32+32+dataLen)
	res[31] = 0x20 // Offset: 32 bytes (points to 0x20)
	binary.BigEndian.PutUint64(res[56:64], uint64(len(strBytes)))
	copy(res[64:], strBytes)
	return res
}

// EncodeStringParams encodes multiple dynamic string arguments per ABI specs.
// Optimized to compute total required buffer size upfront and allocate a single byte slice,
// avoiding big.Int allocations, repeated re-allocations, and intermediate slice copies.
func EncodeStringParams(strs ...string) []byte {
	headSize := 32 * len(strs)
	totalLen := headSize
	for _, s := range strs {
		totalLen += 32 + ((len(s)+31)/32)*32
	}

	res := make([]byte, totalLen)
	headOffset := 0
	tailOffset := headSize

	for _, s := range strs {
		// Write head entry (offset to string data in tail)
		binary.BigEndian.PutUint64(res[headOffset+24:headOffset+32], uint64(tailOffset))
		headOffset += 32

		// Write tail entry (string length + padded string bytes)
		strLen := len(s)
		binary.BigEndian.PutUint64(res[tailOffset+24:tailOffset+32], uint64(strLen))
		copy(res[tailOffset+32:], s)
		tailOffset += 32 + ((strLen+31)/32)*32
	}
	return res
}

// decodeABIUint64 decodes a 32-byte ABI word as a uint64 without allocating big.Int.
// Returns an error if the value exceeds uint64 or signed int64 bounds.
func decodeABIUint64(word []byte) (uint64, error) {
	if len(word) < 32 {
		return 0, errors.New("data too short for uint64 word")
	}
	for i := 0; i < 24; i++ {
		if word[i] != 0 {
			return 0, errors.New("value exceeds uint64 limit")
		}
	}
	val := binary.BigEndian.Uint64(word[24:32])
	if val > 0x7fffffffffffffff {
		return 0, errors.New("value exceeds int64 limit")
	}
	return val, nil
}

// DecodeString decodes a dynamic string from ABI return data.
// Optimized: Replaces big.Int allocations for offset and length with direct
// binary decoding, reducing heap allocations from 3 to 1 per call.
func DecodeString(data []byte, offset int) (string, error) {
	if offset < 0 || len(data) < offset+32 {
		return "", errors.New("data too short for string offset")
	}
	strOffset, err := decodeABIUint64(data[offset : offset+32])
	if err != nil {
		return "", fmt.Errorf("string offset error: %w", err)
	}
	uStrOffset := int(strOffset)
	if uStrOffset > len(data) || uStrOffset+32 > len(data) {
		return "", errors.New("data too short for string length")
	}
	strLen, err := decodeABIUint64(data[uStrOffset : uStrOffset+32])
	if err != nil {
		return "", fmt.Errorf("string length error: %w", err)
	}
	uStrLen := int(strLen)
	if uStrLen > len(data)-(uStrOffset+32) {
		return "", errors.New("data too short for string content")
	}
	return string(data[uStrOffset+32 : uStrOffset+32+uStrLen]), nil
}

// DecodeAddress decodes a 20-byte address from a 32-byte ABI word.
// Optimized: Uses stack buffer and hex lookup table to avoid string concatenation,
// reducing heap allocations from 2 to 1 per call.
func DecodeAddress(data []byte, offset int) string {
	if offset < 0 || len(data) < offset+32 {
		return "0x0000000000000000000000000000000000000000"
	}
	const digits = "0123456789abcdef"
	var buf [42]byte
	buf[0] = '0'
	buf[1] = 'x'
	addrBytes := data[offset+12 : offset+32]
	for i, v := range addrBytes {
		buf[2+i*2] = digits[v>>4]
		buf[2+i*2+1] = digits[v&0x0f]
	}
	return string(buf[:])
}

// DecodeUint256 decodes a uint256 word into *big.Int.
func DecodeUint256(data []byte, offset int) *big.Int {
	if offset < 0 || len(data) < offset+32 {
		return big.NewInt(0)
	}
	return new(big.Int).SetBytes(data[offset : offset+32])
}

// DecodeBool decodes a boolean word.
// Optimized: Directly checks byte values in slice instead of instantiating big.Int,
// reducing heap allocations from 1 to 0 per call.
func DecodeBool(data []byte, offset int) bool {
	if offset < 0 || len(data) < offset+32 {
		return false
	}
	for _, b := range data[offset : offset+32] {
		if b != 0 {
			return true
		}
	}
	return false
}

// PadLeftBytes pads b with leading zeroes to target length l.
// Optimized: Allocates a single slice res of size l and copies b to the end,
// reducing heap allocations from 2 to 1 compared to appending to a zero slice.
func PadLeftBytes(b []byte, l int) []byte {
	if len(b) >= l {
		return b
	}
	res := make([]byte, l)
	copy(res[l-len(b):], b)
	return res
}

// PadRightBytes pads b with trailing zeroes to target length l.
// Optimized: Allocates a single slice res of size l and copies b to the front,
// reducing heap allocations from 2 to 1 compared to appending to a zero slice.
func PadRightBytes(b []byte, l int) []byte {
	if len(b) >= l {
		return b
	}
	res := make([]byte, l)
	copy(res, b)
	return res
}
