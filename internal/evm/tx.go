package evm

// EIP-1559 transaction construction, signing, submission, and receipt
// polling. Uses the secp256k1 implementation in secp256k1.go; no new
// dependencies.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// Tunables for receipt polling (overridden in tests).
var (
	txPollInterval = 2 * time.Second
	txPollTimeout  = 5 * time.Minute
)

// TxReceipt is a confirmed transaction receipt.
type TxReceipt struct {
	TxHash      string
	BlockNumber uint64
	Status      bool // true == success (status 0x1)
}

// --- RLP (minimal, sufficient for transactions) ---

func rlpEncodeBytes(b []byte) []byte {
	if len(b) == 1 && b[0] < 0x80 {
		return b
	}
	return append(rlpEncodeLength(len(b), 0x80), b...)
}

func rlpEncodeLength(l int, offset byte) []byte {
	if l <= 55 {
		return []byte{offset + byte(l)}
	}
	bl := big.NewInt(int64(l)).Bytes()
	return append([]byte{offset + 55 + byte(len(bl))}, bl...)
}

func rlpEncodeList(items [][]byte) []byte {
	var payload []byte
	for _, it := range items {
		payload = append(payload, it...)
	}
	return append(rlpEncodeLength(len(payload), 0xc0), payload...)
}

func rlpUint(v *big.Int) []byte {
	if v == nil || v.Sign() == 0 {
		return rlpEncodeBytes(nil)
	}
	return rlpEncodeBytes(v.Bytes())
}

// --- JSON-RPC helpers ---

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (c *Client) rpcCall(method string, params []interface{}) (string, error) {
	reqBody, err := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  method,
		"params":  params,
	})
	if err != nil {
		return "", err
	}
	resp, err := c.HTTP.Post(c.RPCURL, "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return "", fmt.Errorf("%s failed: %w", method, err)
	}
	defer resp.Body.Close()
	var rpcResp struct {
		Result string    `json:"result"`
		Error  *rpcError `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		return "", fmt.Errorf("decoding %s response: %w", method, err)
	}
	if rpcResp.Error != nil {
		return "", fmt.Errorf("RPC error %d (%s): %s", rpcResp.Error.Code, method, rpcResp.Error.Message)
	}
	return rpcResp.Result, nil
}

func rpcUintHex(s string) (uint64, error) {
	s = strings.TrimPrefix(s, "0x")
	if s == "" {
		return 0, nil
	}
	v, ok := new(big.Int).SetString(s, 16)
	if !ok {
		return 0, fmt.Errorf("invalid hex quantity %q", s)
	}
	return v.Uint64(), nil
}

// EthChainID returns the chain ID via eth_chainId.
func (c *Client) EthChainID() (uint64, error) {
	res, err := c.rpcCall("eth_chainId", []interface{}{})
	if err != nil {
		return 0, err
	}
	return rpcUintHex(res)
}

// EthNonce returns the pending transaction count for an address.
func (c *Client) EthNonce(address string) (uint64, error) {
	res, err := c.rpcCall("eth_getTransactionCount", []interface{}{address, "pending"})
	if err != nil {
		return 0, err
	}
	return rpcUintHex(res)
}

// EthMaxPriorityFee suggests a priority fee via eth_maxPriorityFeePerGas,
// falling back to eth_gasPrice.
func (c *Client) EthMaxPriorityFee() (*big.Int, error) {
	res, err := c.rpcCall("eth_maxPriorityFeePerGas", []interface{}{})
	if err == nil {
		if v, ok := new(big.Int).SetString(strings.TrimPrefix(res, "0x"), 16); ok {
			return v, nil
		}
	}
	res, err = c.rpcCall("eth_gasPrice", []interface{}{})
	if err != nil {
		return nil, err
	}
	v, ok := new(big.Int).SetString(strings.TrimPrefix(res, "0x"), 16)
	if !ok {
		return nil, fmt.Errorf("invalid gas price %q", res)
	}
	return v, nil
}

// EthBaseFee returns the latest block's base fee, or nil if unavailable.
func (c *Client) EthBaseFee() *big.Int {
	reqBody, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "eth_getBlockByNumber",
		"params": []interface{}{"latest", false},
	})
	resp, err := c.HTTP.Post(c.RPCURL, "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	var rpcResp struct {
		Result *struct {
			BaseFeePerGas string `json:"baseFeePerGas"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		return nil
	}
	if rpcResp.Result == nil || rpcResp.Result.BaseFeePerGas == "" {
		return nil
	}
	v, ok := new(big.Int).SetString(strings.TrimPrefix(rpcResp.Result.BaseFeePerGas, "0x"), 16)
	if !ok {
		return nil
	}
	return v
}

// EthEstimateGas estimates gas for a contract call.
func (c *Client) EthEstimateGas(from, to string, data []byte) (uint64, error) {
	tx := map[string]string{"from": from, "to": to, "data": "0x" + hex.EncodeToString(data)}
	res, err := c.rpcCall("eth_estimateGas", []interface{}{tx})
	if err != nil {
		return 0, err
	}
	return rpcUintHex(res)
}

// EthSendRawTransaction broadcasts a signed transaction.
func (c *Client) EthSendRawTransaction(signedHex string) (string, error) {
	if !strings.HasPrefix(signedHex, "0x") {
		signedHex = "0x" + signedHex
	}
	return c.rpcCall("eth_sendRawTransaction", []interface{}{signedHex})
}

// EthGetTransactionReceipt fetches a receipt, or nil when still pending.
func (c *Client) EthGetTransactionReceipt(txHash string) (*TxReceipt, error) {
	reqBody, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "eth_getTransactionReceipt",
		"params": []interface{}{txHash},
	})
	resp, err := c.HTTP.Post(c.RPCURL, "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("eth_getTransactionReceipt failed: %w", err)
	}
	defer resp.Body.Close()
	var rpcResp struct {
		Result *struct {
			BlockNumber string `json:"blockNumber"`
			Status      string `json:"status"`
		} `json:"result"`
		Error *rpcError `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		return nil, fmt.Errorf("decoding receipt: %w", err)
	}
	if rpcResp.Error != nil {
		return nil, fmt.Errorf("RPC error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}
	if rpcResp.Result == nil {
		return nil, nil // still pending
	}
	block, err := rpcUintHex(rpcResp.Result.BlockNumber)
	if err != nil {
		return nil, err
	}
	status, err := rpcUintHex(rpcResp.Result.Status)
	if err != nil {
		return nil, err
	}
	return &TxReceipt{TxHash: txHash, BlockNumber: block, Status: status == 1}, nil
}

// --- Transaction flow ---

// SendTransaction signs and submits an EIP-1559 contract call, waits for the
// receipt, and returns an error when the transaction reverts. The private key
// is validated before any RPC call is made.
func SendTransaction(rpcURL, privateKeyHex, to string, data []byte) (*TxReceipt, error) {
	d, err := parsePrivateKey(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}
	c := NewClient(rpcURL)
	curve := secp256k1()
	px, py := curve.ScalarBaseMult(PadLeftBytes(d.Bytes(), 32))
	from := addressFromPubkey(px, py)
	fromHex := "0x" + hexEncode(from[:])

	if !isHexAddress(to) {
		return nil, fmt.Errorf("invalid contract address %q", to)
	}

	chainID, err := c.EthChainID()
	if err != nil {
		return nil, fmt.Errorf("fetching chain ID: %w", err)
	}
	nonce, err := c.EthNonce(fromHex)
	if err != nil {
		return nil, fmt.Errorf("fetching nonce: %w", err)
	}
	priorityFee, err := c.EthMaxPriorityFee()
	if err != nil {
		return nil, fmt.Errorf("fetching priority fee: %w", err)
	}
	maxFee := new(big.Int).Mul(priorityFee, big.NewInt(2))
	if baseFee := c.EthBaseFee(); baseFee != nil {
		// maxFee = 2*baseFee + priorityFee (alloy default strategy)
		maxFee = new(big.Int).Add(new(big.Int).Mul(baseFee, big.NewInt(2)), priorityFee)
	}
	gasLimit, err := c.EthEstimateGas(fromHex, to, data)
	if err != nil {
		return nil, fmt.Errorf("estimating gas: %w", err)
	}

	toBytes, _ := hex.DecodeString(strings.TrimPrefix(to, "0x"))
	unsigned := [][]byte{
		rlpUint(new(big.Int).SetUint64(chainID)),
		rlpUint(new(big.Int).SetUint64(nonce)),
		rlpUint(priorityFee),
		rlpUint(maxFee),
		rlpUint(new(big.Int).SetUint64(gasLimit)),
		rlpEncodeBytes(toBytes),
		rlpUint(big.NewInt(0)), // value
		rlpEncodeBytes(data),
		rlpEncodeList(nil), // access list
	}
	sigHash := Keccak256(append([]byte{0x02}, rlpEncodeList(unsigned)...))
	r, s, yParity, err := secpSign(d, sigHash)
	if err != nil {
		return nil, fmt.Errorf("signing transaction: %w", err)
	}
	signed := append(unsigned,
		rlpUint(new(big.Int).SetUint64(uint64(yParity))),
		rlpUint(r),
		rlpUint(s),
	)
	rawTx := append([]byte{0x02}, rlpEncodeList(signed)...)
	txHash, err := c.EthSendRawTransaction(hex.EncodeToString(rawTx))
	if err != nil {
		return nil, fmt.Errorf("submitting transaction: %w", err)
	}

	deadline := time.Now().Add(txPollTimeout)
	for {
		receipt, err := c.EthGetTransactionReceipt(txHash)
		if err != nil {
			return nil, err
		}
		if receipt != nil {
			if !receipt.Status {
				return nil, fmt.Errorf("transaction %s reverted", txHash)
			}
			return receipt, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timed out waiting for receipt of %s", txHash)
		}
		time.Sleep(txPollInterval)
	}
}

// CallContract is SendTransaction for a contract address with ABI-encoded data.
func CallContract(rpcURL, privateKeyHex, contractAddr string, data []byte) (*TxReceipt, error) {
	return SendTransaction(rpcURL, privateKeyHex, contractAddr, data)
}

func isHexAddress(s string) bool {
	s = strings.TrimPrefix(s, "0x")
	if len(s) != 40 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// --- ABI encoding helpers for writes ---

// EncodeAddressParam encodes an address argument.
func EncodeAddressParam(addr string) ([]byte, error) {
	b, err := hex.DecodeString(strings.TrimPrefix(addr, "0x"))
	if err != nil || len(b) != 20 {
		return nil, fmt.Errorf("invalid address %q", addr)
	}
	return PadLeftBytes(b, 32), nil
}

// EncodeUint256Param encodes a uint256 argument.
func EncodeUint256Param(v *big.Int) []byte {
	return PadLeftBytes(v.Bytes(), 32)
}

// EncodeBytes32Param encodes a bytes32 argument.
func EncodeBytes32Param(b []byte) ([]byte, error) {
	if len(b) != 32 {
		return nil, errors.New("bytes32 must be 32 bytes")
	}
	out := make([]byte, 32)
	copy(out, b)
	return out, nil
}

// TokensToWei converts whole tokens to wei (18 decimals).
func TokensToWei(tokens uint64) *big.Int {
	return new(big.Int).Mul(new(big.Int).SetUint64(tokens), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
}

// WeiToTokens formats wei as tokens with two decimals.
func WeiToTokens(wei *big.Int) string {
	scale := new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
	whole := new(big.Int).Div(wei, scale)
	frac := new(big.Int).Mod(wei, scale)
	if frac.Sign() == 0 {
		return whole.String()
	}
	twoDP := new(big.Int).Div(new(big.Int).Mul(frac, big.NewInt(100)), scale)
	return whole.String() + "." + fmt.Sprintf("%02d", twoDP.Int64())
}
