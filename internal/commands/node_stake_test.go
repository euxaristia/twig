package commands

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Twigpine/twig/internal/evm"
	"github.com/Twigpine/twig/internal/identity"
)

// mockChain serves the JSON-RPC surface used by the staking flows.
type mockChain struct {
	t            *testing.T
	calls        []string
	sentTxs      []string
	balance      *big.Int
	allowance    *big.Int
	nodeInfoData string
}

func (m *mockChain) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var req struct {
		Method string            `json:"method"`
		Params []json.RawMessage `json:"params"`
	}
	_ = json.Unmarshal(body, &req)
	m.calls = append(m.calls, req.Method)
	result := func(v string) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": 1, "result": v})
	}
	switch req.Method {
	case "eth_chainId":
		result("0x14a")
	case "eth_getTransactionCount":
		result("0x1")
	case "eth_maxPriorityFeePerGas":
		result("0x3b9aca00")
	case "eth_getBlockByNumber":
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": 1,
			"result": map[string]string{"baseFeePerGas": "0x12a05f200"},
		})
	case "eth_estimateGas":
		result("0x186a0")
	case "eth_sendRawTransaction":
		var p string
		_ = json.Unmarshal(req.Params[0], &p)
		m.sentTxs = append(m.sentTxs, p)
		result("0xabc123")
	case "eth_getTransactionReceipt":
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": 1,
			"result": map[string]string{"blockNumber": "0x200", "status": "0x1"},
		})
	case "eth_call":
		var call struct {
			To   string `json:"to"`
			Data string `json:"data"`
		}
		_ = json.Unmarshal(req.Params[0], &call)
		sel := call.Data[:10] // 0x + 8 hex chars
		switch sel {
		case "0x" + hex.EncodeToString(evm.EncodeFunctionSignature("balanceOf(address)")):
			result("0x" + hex.EncodeToString(evm.PadLeftBytes(m.balance.Bytes(), 32)))
		case "0x" + hex.EncodeToString(evm.EncodeFunctionSignature("allowance(address,address)")):
			result("0x" + hex.EncodeToString(evm.PadLeftBytes(m.allowance.Bytes(), 32)))
		case "0x" + hex.EncodeToString(evm.EncodeFunctionSignature("getNodeInfo(bytes32)")):
			result(m.nodeInfoData)
		default:
			result("0x")
		}
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func stakeTestSetup(t *testing.T, m *mockChain) (srvURL, idDir string) {
	t.Helper()
	srv := httptest.NewServer(m)
	t.Cleanup(srv.Close)
	idDir = t.TempDir()
	if err := IdentityNew(idDir, false, strings.NewReader("")); err != nil {
		t.Fatalf("IdentityNew failed: %v", err)
	}
	return srv.URL, idDir
}

const (
	stakeContract = "0x1111111111111111111111111111111111111111"
	stakeToken    = "0x2222222222222222222222222222222222222222"
	stakePrivKey  = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

func txDataHex(t *testing.T, rawTx string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(strings.TrimPrefix(rawTx, "0x"))
	if err != nil || len(raw) == 0 || raw[0] != 0x02 {
		t.Fatalf("bad raw tx")
	}
	return raw[1:]
}

func stakeTestIdentityDID(t *testing.T, dir string) string {
	t.Helper()
	kp, err := identity.LoadKeypair(dir)
	if err != nil {
		t.Fatalf("LoadKeypair failed: %v", err)
	}
	return kp.DID()
}

func TestNodeHeartbeatSubmitsTx(t *testing.T) {
	m := &mockChain{t: t}
	srvURL, idDir := stakeTestSetup(t, m)

	if err := NodeHeartbeat(stakePrivKey, srvURL, stakeContract, idDir); err != nil {
		t.Fatalf("NodeHeartbeat failed: %v", err)
	}
	if len(m.sentTxs) != 1 {
		t.Fatalf("expected 1 tx, got %d", len(m.sentTxs))
	}
	// The tx data must call heartbeat(bytes32) with keccak256(did).
	raw := txDataHex(t, m.sentTxs[0])
	fields, ok := rlpDecodeTxFields(raw)
	if !ok {
		t.Fatalf("RLP decode failed")
	}
	data := fields[7]
	sel := hex.EncodeToString(evm.EncodeFunctionSignature("heartbeat(bytes32)"))
	if hex.EncodeToString(data[:4]) != sel {
		t.Fatalf("wrong selector: %x", data[:4])
	}
	kpDID := stakeTestIdentityDID(t, idDir)
	wantHash := evm.Keccak256([]byte(kpDID))
	if hex.EncodeToString(data[4:36]) != hex.EncodeToString(wantHash) {
		t.Fatalf("did hash mismatch")
	}
}

func TestNodeRegisterOnchainApprovesAndRegisters(t *testing.T) {
	m := &mockChain{t: t, balance: evm.TokensToWei(20000), allowance: big.NewInt(0)}
	srvURL, idDir := stakeTestSetup(t, m)

	if err := NodeRegisterOnchain(10000, "https://node.example", stakePrivKey, srvURL, stakeContract, stakeToken, idDir); err != nil {
		t.Fatalf("NodeRegisterOnchain failed: %v", err)
	}
	if len(m.sentTxs) != 2 {
		t.Fatalf("expected approve + register txs, got %d", len(m.sentTxs))
	}
	approveSel := hex.EncodeToString(evm.EncodeFunctionSignature("approve(address,uint256)"))
	regSel := hex.EncodeToString(evm.EncodeFunctionSignature("registerNode(bytes32,string,uint256)"))
	raw0 := txDataHex(t, m.sentTxs[0])
	f0, _ := rlpDecodeTxFields(raw0)
	raw1 := txDataHex(t, m.sentTxs[1])
	f1, _ := rlpDecodeTxFields(raw1)
	if hex.EncodeToString(f0[7][:4]) != approveSel {
		t.Fatalf("first tx not approve: %x", f0[7][:4])
	}
	if hex.EncodeToString(f1[7][:4]) != regSel {
		t.Fatalf("second tx not registerNode: %x", f1[7][:4])
	}
}

func TestNodeRegisterOnchainSkipsApproveWhenAllowed(t *testing.T) {
	m := &mockChain{t: t, balance: evm.TokensToWei(20000), allowance: evm.TokensToWei(50000)}
	srvURL, idDir := stakeTestSetup(t, m)

	if err := NodeRegisterOnchain(10000, "https://node.example", stakePrivKey, srvURL, stakeContract, stakeToken, idDir); err != nil {
		t.Fatalf("NodeRegisterOnchain failed: %v", err)
	}
	if len(m.sentTxs) != 1 {
		t.Fatalf("expected only register tx, got %d", len(m.sentTxs))
	}
}

func TestNodeRegisterOnchainInsufficientBalance(t *testing.T) {
	m := &mockChain{t: t, balance: big.NewInt(1), allowance: big.NewInt(0)}
	srvURL, idDir := stakeTestSetup(t, m)

	err := NodeRegisterOnchain(10000, "https://node.example", stakePrivKey, srvURL, stakeContract, stakeToken, idDir)
	if err == nil || !strings.Contains(err.Error(), "insufficient") {
		t.Fatalf("expected insufficient balance error, got: %v", err)
	}
	if len(m.sentTxs) != 0 {
		t.Fatalf("no tx should be sent, got %d", len(m.sentTxs))
	}
}

func TestNodeRegisterOnchainInvalidKey(t *testing.T) {
	m := &mockChain{t: t, balance: evm.TokensToWei(20000), allowance: big.NewInt(0)}
	srvURL, idDir := stakeTestSetup(t, m)

	err := NodeRegisterOnchain(10000, "https://node.example", "0xbad", srvURL, stakeContract, stakeToken, idDir)
	if err == nil {
		t.Fatalf("expected invalid key error")
	}
	if len(m.sentTxs) != 0 {
		t.Fatalf("no tx should be sent, got %d", len(m.sentTxs))
	}
}

func TestNodeOnchainStatusFromContract(t *testing.T) {
	// Encode getNodeInfo return: (address,string,uint256×3,bool×2,uint256×2)
	operator := "0x3333333333333333333333333333333333333333"
	var ret []byte
	ret = append(ret, evm.PadLeftBytes(mustDecodeHex(t, strings.TrimPrefix(operator, "0x")), 32)...)
	ret = append(ret, evm.PadLeftBytes(big.NewInt(9*32).Bytes(), 32)...)
	ret = append(ret, evm.PadLeftBytes(evm.TokensToWei(10000).Bytes(), 32)...)
	ret = append(ret, evm.PadLeftBytes(big.NewInt(1700000000).Bytes(), 32)...)
	ret = append(ret, evm.PadLeftBytes(big.NewInt(1699999999).Bytes(), 32)...)
	ret = append(ret, evm.PadLeftBytes(big.NewInt(1).Bytes(), 32)...)
	ret = append(ret, evm.PadLeftBytes(big.NewInt(1).Bytes(), 32)...)
	ret = append(ret, evm.PadLeftBytes(evm.TokensToWei(5).Bytes(), 32)...)
	ret = append(ret, evm.PadLeftBytes(big.NewInt(0).Bytes(), 32)...)
	ret = append(ret, evm.EncodeStringParams("https://node.example")...)

	m := &mockChain{t: t, nodeInfoData: "0x" + hex.EncodeToString(ret)}
	srvURL, idDir := stakeTestSetup(t, m)

	if err := NodeOnchainStatus("", srvURL, stakeContract, idDir); err != nil {
		t.Fatalf("NodeOnchainStatus failed: %v", err)
	}
	if len(m.sentTxs) != 0 {
		t.Fatalf("status must not send txs")
	}
}

func TestNameRegisterSubmitsTx(t *testing.T) {
	m := &mockChain{t: t}
	srv := httptest.NewServer(m)
	defer srv.Close()
	idDir := t.TempDir()
	if err := IdentityNew(idDir, false, strings.NewReader("")); err != nil {
		t.Fatalf("IdentityNew failed: %v", err)
	}

	if err := NameRegister("alice", stakePrivKey, srv.URL, stakeContract, idDir); err != nil {
		t.Fatalf("NameRegister failed: %v", err)
	}
	if len(m.sentTxs) != 1 {
		t.Fatalf("expected 1 tx, got %d", len(m.sentTxs))
	}
	raw := txDataHex(t, m.sentTxs[0])
	fields, ok := rlpDecodeTxFields(raw)
	if !ok {
		t.Fatalf("RLP decode failed")
	}
	sel := hex.EncodeToString(evm.EncodeFunctionSignature("register(string,string)"))
	if hex.EncodeToString(fields[7][:4]) != sel {
		t.Fatalf("wrong selector: %x", fields[7][:4])
	}
}

func TestNameRegisterInvalidKey(t *testing.T) {
	m := &mockChain{t: t}
	srv := httptest.NewServer(m)
	defer srv.Close()
	idDir := t.TempDir()
	if err := IdentityNew(idDir, false, strings.NewReader("")); err != nil {
		t.Fatalf("IdentityNew failed: %v", err)
	}

	if err := NameRegister("alice", "not-a-key", srv.URL, stakeContract, idDir); err == nil {
		t.Fatalf("expected invalid key error")
	}
	if len(m.sentTxs) != 0 {
		t.Fatalf("no tx should be sent")
	}
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

// rlpDecodeTxFields decodes a type-2 tx body (without the 0x02 prefix).
func rlpDecodeTxFields(raw []byte) ([][]byte, bool) {
	if len(raw) == 0 || raw[0] < 0xc0 {
		return nil, false
	}
	payload, rest, ok := rlpDecodeOne(raw)
	if !ok || len(rest) != 0 {
		return nil, false
	}
	// payload is the concatenated items.
	var items [][]byte
	p := payload
	for len(p) > 0 {
		it, rem, ok := rlpDecodeOne(p)
		if !ok {
			return nil, false
		}
		items = append(items, it)
		p = rem
	}
	return items, true
}

func rlpDecodeOne(b []byte) ([]byte, []byte, bool) {
	if len(b) == 0 {
		return nil, nil, false
	}
	prefix := b[0]
	switch {
	case prefix < 0x80:
		return b[:1], b[1:], true
	case prefix < 0xb8:
		l := int(prefix - 0x80)
		if len(b) < 1+l {
			return nil, nil, false
		}
		return b[1 : 1+l], b[1+l:], true
	case prefix < 0xc0:
		ll := int(prefix - 0xb7)
		if len(b) < 1+ll {
			return nil, nil, false
		}
		l := int(new(big.Int).SetBytes(b[1 : 1+ll]).Int64())
		return b[1+ll : 1+ll+l], b[1+ll+l:], true
	case prefix < 0xf8:
		l := int(prefix - 0xc0)
		if len(b) < 1+l {
			return nil, nil, false
		}
		return b[1 : 1+l], b[1+l:], true
	default:
		ll := int(prefix - 0xf7)
		if len(b) < 1+ll {
			return nil, nil, false
		}
		l := int(new(big.Int).SetBytes(b[1 : 1+ll]).Int64())
		return b[1+ll : 1+ll+l], b[1+ll+l:], true
	}
}
