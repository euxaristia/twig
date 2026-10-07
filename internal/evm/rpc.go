package evm

import (
	"bytes"
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
func EncodeStringParameter(s string) []byte {
	// Offset: 32 bytes (points to 0x20)
	offset := PadLeftBytes(big.NewInt(32).Bytes(), 32)
	strBytes := []byte(s)
	length := PadLeftBytes(big.NewInt(int64(len(strBytes))).Bytes(), 32)
	paddedData := PadRightBytes(strBytes, ((len(strBytes)+31)/32)*32)

	var res []byte
	res = append(res, offset...)
	res = append(res, length...)
	res = append(res, paddedData...)
	return res
}

// DecodeString decodes a dynamic string from ABI return data.
func DecodeString(data []byte, offset int) (string, error) {
	if offset < 0 || len(data) < offset+32 {
		return "", errors.New("data too short for string offset")
	}
	strOffsetBig := new(big.Int).SetBytes(data[offset : offset+32])
	if !strOffsetBig.IsInt64() {
		return "", errors.New("string offset exceeds int64 limit")
	}
	strOffset := int(strOffsetBig.Int64())
	if strOffset < 0 || strOffset > len(data) || strOffset+32 > len(data) {
		return "", errors.New("data too short for string length")
	}
	strLenBig := new(big.Int).SetBytes(data[strOffset : strOffset+32])
	if !strLenBig.IsInt64() {
		return "", errors.New("string length exceeds int64 limit")
	}
	strLen := int(strLenBig.Int64())
	if strLen < 0 || strLen > len(data)-(strOffset+32) {
		return "", errors.New("data too short for string content")
	}
	return string(data[strOffset+32 : strOffset+32+strLen]), nil
}

// DecodeAddress decodes a 20-byte address from a 32-byte ABI word.
func DecodeAddress(data []byte, offset int) string {
	if offset < 0 || len(data) < offset+32 {
		return "0x0000000000000000000000000000000000000000"
	}
	return "0x" + hex.EncodeToString(data[offset+12:offset+32])
}

// DecodeUint256 decodes a uint256 word into *big.Int.
func DecodeUint256(data []byte, offset int) *big.Int {
	if offset < 0 || len(data) < offset+32 {
		return big.NewInt(0)
	}
	return new(big.Int).SetBytes(data[offset : offset+32])
}

// DecodeBool decodes a boolean word.
func DecodeBool(data []byte, offset int) bool {
	n := DecodeUint256(data, offset)
	return n.Sign() != 0
}

// PadLeftBytes pads b with leading zeroes to target length l.
func PadLeftBytes(b []byte, l int) []byte {
	if len(b) >= l {
		return b
	}
	pad := make([]byte, l-len(b))
	return append(pad, b...)
}

// PadRightBytes pads b with trailing zeroes to target length l.
func PadRightBytes(b []byte, l int) []byte {
	if len(b) >= l {
		return b
	}
	pad := make([]byte, l-len(b))
	return append(b, pad...)
}
