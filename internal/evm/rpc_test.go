package evm

import (
	"math/big"
	"net/http"
	"testing"
)

func TestABIStringEncodeDecode(t *testing.T) {
	orig := "testname.twig"
	encoded := EncodeStringParameter(orig)

	decoded, err := DecodeString(encoded, 0)
	if err != nil {
		t.Fatalf("failed to decode string: %v", err)
	}

	if decoded != orig {
		t.Fatalf("expected %s, got %s", orig, decoded)
	}
}

func TestABIDecodeValues(t *testing.T) {
	data := make([]byte, 64)
	data[31] = 1 // bool true or uint 1
	copy(data[44:64], []byte("01234567890123456789"))

	val := DecodeUint256(data, 0)
	if val.Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("expected 1, got %v", val)
	}

	b := DecodeBool(data, 0)
	if !b {
		t.Fatalf("expected true")
	}

	addr := DecodeAddress(data, 32)
	if len(addr) != 42 {
		t.Fatalf("invalid address format: %s", addr)
	}
}

func TestEVMSameOriginRedirect(t *testing.T) {
	c := NewClient("https://example.com/rpc")
	if c.HTTP.CheckRedirect == nil {
		t.Fatal("expected CheckRedirect to be configured on EVM HTTP client")
	}

	req1, _ := http.NewRequest("POST", "https://example.com/rpc", nil)
	reqRedirect, _ := http.NewRequest("POST", "https://evil.com/rpc", nil)

	err := c.HTTP.CheckRedirect(reqRedirect, []*http.Request{req1})
	if err != http.ErrUseLastResponse {
		t.Errorf("expected ErrUseLastResponse for cross-origin redirect, got %v", err)
	}

	reqSameOrigin, _ := http.NewRequest("POST", "https://example.com/rpc2", nil)
	errSame := c.HTTP.CheckRedirect(reqSameOrigin, []*http.Request{req1})
	if errSame != nil {
		t.Errorf("expected nil error for same-origin redirect, got %v", errSame)
	}
}

func TestABIDecodeMalformedData(t *testing.T) {
	// Negative offset checks
	if _, err := DecodeString([]byte("short"), -1); err == nil {
		t.Errorf("expected error for negative offset in DecodeString")
	}
	if addr := DecodeAddress([]byte("short"), -1); addr != "0x0000000000000000000000000000000000000000" {
		t.Errorf("expected zero address for negative offset, got %s", addr)
	}
	if val := DecodeUint256([]byte("short"), -1); val.Sign() != 0 {
		t.Errorf("expected 0 for negative offset in DecodeUint256")
	}
	if b := DecodeBool([]byte("short"), -1); b {
		t.Errorf("expected false for negative offset in DecodeBool")
	}

	// Truncated data checks
	shortData := make([]byte, 10)
	if _, err := DecodeString(shortData, 0); err == nil {
		t.Errorf("expected error for truncated data in DecodeString")
	}

	// 256-bit offset with high bit set (would evaluate to negative int64 if cast signed)
	highBitData := make([]byte, 64)
	highBitData[0] = 0x80 // Offset = 2^255
	if _, err := DecodeString(highBitData, 0); err == nil {
		t.Errorf("expected error for oversized offset in DecodeString")
	}

	bit63Data := make([]byte, 64)
	bit63Data[24] = 0x80 // Offset = 2^63
	if _, err := DecodeString(bit63Data, 0); err == nil {
		t.Errorf("expected error for 2^63 offset in DecodeString")
	}

	// Valid offset, but string length exceeds remaining payload
	validOffsetData := make([]byte, 64)
	validOffsetData[31] = 32 // offset = 32
	validOffsetData[63] = 99 // length = 99 (payload only has 64 bytes total)
	if _, err := DecodeString(validOffsetData, 0); err == nil {
		t.Errorf("expected error for out-of-bounds string length in DecodeString")
	}
}
