package evm

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testPrivKey = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// rlpDecodeItem decodes one RLP item, returning payload and rest.
func rlpDecodeItem(b []byte) ([]byte, []byte, bool) {
	if len(b) == 0 {
		return nil, nil, false
	}
	prefix := b[0]
	switch {
	case prefix < 0x80:
		return b[:1], b[1:], true
	case prefix < 0xb8:
		l := int(prefix - 0x80)
		return b[1 : 1+l], b[1+l:], true
	case prefix < 0xc0:
		ll := int(prefix - 0xb7)
		l := int(new(big.Int).SetBytes(b[1 : 1+ll]).Int64())
		return b[1+ll : 1+ll+l], b[1+ll+l:], true
	case prefix < 0xf8:
		l := int(prefix - 0xc0)
		return b[1 : 1+l], b[1+l:], true
	default:
		ll := int(prefix - 0xf7)
		l := int(new(big.Int).SetBytes(b[1 : 1+ll]).Int64())
		return b[1+ll : 1+ll+l], b[1+ll+l:], true
	}
}

func rlpDecodeList(b []byte) ([][]byte, bool) {
	payload, rest, ok := rlpDecodeItem(b)
	if !ok || len(rest) != 0 {
		return nil, false
	}
	var items [][]byte
	for len(payload) > 0 {
		it, rem, ok := rlpDecodeItem(payload)
		if !ok {
			return nil, false
		}
		items = append(items, it)
		payload = rem
	}
	return items, true
}

type mockRPC struct {
	t           *testing.T
	calls       []string
	rawTx       string
	receiptMode string // "ok", "reverted", "pending"
	receiptSeen int
}

func (m *mockRPC) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var req struct {
		Method string            `json:"method"`
		Params []json.RawMessage `json:"params"`
	}
	_ = json.Unmarshal(body, &req)
	m.calls = append(m.calls, req.Method)
	writeResult := func(v string) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": 1, "result": v,
		})
	}
	switch req.Method {
	case "eth_chainId":
		writeResult("0x14a") // Base Sepolia
	case "eth_getTransactionCount":
		writeResult("0x5")
	case "eth_maxPriorityFeePerGas":
		writeResult("0x3b9aca00")
	case "eth_getBlockByNumber":
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": 1,
			"result": map[string]string{"baseFeePerGas": "0x12a05f200"},
		})
	case "eth_estimateGas":
		writeResult("0x186a0")
	case "eth_sendRawTransaction":
		var p string
		_ = json.Unmarshal(req.Params[0], &p)
		m.rawTx = p
		writeResult("0xdeadbeef")
	case "eth_getTransactionReceipt":
		m.receiptSeen++
		if m.receiptMode == "pending" || (m.receiptMode == "ok" && m.receiptSeen == 1) {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": 1, "result": nil,
			})
			return
		}
		status := "0x1"
		if m.receiptMode == "reverted" {
			status = "0x0"
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": 1,
			"result": map[string]string{"blockNumber": "0x100", "status": status},
		})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func TestSendTransactionFullFlow(t *testing.T) {
	txPollInterval = time.Millisecond
	txPollTimeout = 5 * time.Second
	m := &mockRPC{t: t, receiptMode: "ok"}
	srv := httptest.NewServer(m)
	defer srv.Close()

	to := "0x73094B9DAb2421878A20Abed1497001fbD51302c"
	data := append(EncodeFunctionSignature("register(string,string)"), EncodeStringParameter("alice")...)
	receipt, err := SendTransaction(srv.URL, testPrivKey, to, data)
	if err != nil {
		t.Fatalf("SendTransaction failed: %v", err)
	}
	if !receipt.Status || receipt.TxHash != "0xdeadbeef" || receipt.BlockNumber != 0x100 {
		t.Fatalf("bad receipt: %+v", receipt)
	}

	// Verify the signed payload: strip 0x02, RLP-decode, re-derive the
	// signing hash, and check the ECDSA signature against the signer key.
	raw, _ := hex.DecodeString(strings.TrimPrefix(m.rawTx, "0x"))
	if raw[0] != 0x02 {
		t.Fatalf("not a type-2 transaction")
	}
	fields, ok := rlpDecodeList(raw[1:])
	if !ok || len(fields) != 12 {
		t.Fatalf("RLP decode failed: %d fields", len(fields))
	}
	// Re-encode the first 9 fields exactly as the signer did (the access
	// list is an empty list, not an empty string).
	reenc := make([][]byte, 9)
	for i, f := range fields[:9] {
		if i == 8 {
			reenc[i] = rlpEncodeList(nil)
		} else {
			reenc[i] = rlpEncodeBytes(f)
		}
	}
	sigHash := Keccak256(append([]byte{0x02}, rlpEncodeList(reenc)...))
	r := new(big.Int).SetBytes(fields[9+1])
	s := new(big.Int).SetBytes(fields[9+2])
	yParity := new(big.Int).SetBytes(fields[9]).Uint64()

	d, _ := parsePrivateKey(testPrivKey)
	curve := secp256k1()
	px, py := curve.ScalarBaseMult(PadLeftBytes(d.Bytes(), 32))
	pub := ecdsa.PublicKey{Curve: curve, X: px, Y: py}
	if !ecdsa.Verify(&pub, sigHash, r, s) {
		t.Fatalf("transaction signature does not verify")
	}
	// y-parity must recover to the signer.
	qx, qy, err := recoverPubkey(r, s, sigHash, byte(yParity))
	if err != nil {
		t.Fatalf("recoverPubkey failed: %v", err)
	}
	wantAddr, _ := PrivateKeyToAddress(testPrivKey)
	recAddr := addressFromPubkey(qx, qy)
	gotAddr := "0x" + hex.EncodeToString(recAddr[:])
	if !strings.EqualFold(gotAddr, wantAddr) {
		t.Fatalf("recovered %s, want %s", gotAddr, wantAddr)
	}
	// chainId and to-address round-trip.
	if new(big.Int).SetBytes(fields[0]).Uint64() != 0x14a {
		t.Fatalf("chainId mismatch")
	}
	if "0x"+hex.EncodeToString(fields[5]) != strings.ToLower(to) {
		t.Fatalf("to mismatch: %x", fields[5])
	}
	if !bytes.Equal(fields[7], data) {
		t.Fatalf("data mismatch")
	}
}

func TestSendTransactionInvalidKey(t *testing.T) {
	m := &mockRPC{t: t}
	srv := httptest.NewServer(m)
	defer srv.Close()

	_, err := SendTransaction(srv.URL, "0x1234", "0x73094B9DAb2421878A20Abed1497001fbD51302c", []byte{1, 2, 3})
	if err == nil {
		t.Fatalf("expected error for invalid key")
	}
	if len(m.calls) != 0 {
		t.Fatalf("no RPC calls should happen with an invalid key, got %v", m.calls)
	}
}

func TestSendTransactionReverted(t *testing.T) {
	txPollInterval = time.Millisecond
	txPollTimeout = 5 * time.Second
	m := &mockRPC{t: t, receiptMode: "reverted"}
	srv := httptest.NewServer(m)
	defer srv.Close()

	_, err := SendTransaction(srv.URL, testPrivKey, "0x73094B9DAb2421878A20Abed1497001fbD51302c", []byte{1})
	if err == nil || !strings.Contains(err.Error(), "reverted") {
		t.Fatalf("expected revert error, got: %v", err)
	}
}
