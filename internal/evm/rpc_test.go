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

	// Large offset causing integer overflow when computing offset+32
	largeOffset := 0x7fffffffffffffff - 10
	if _, err := DecodeString(validOffsetData, largeOffset); err == nil {
		t.Errorf("expected error for large offset integer overflow in DecodeString")
	}
	if addr := DecodeAddress(validOffsetData, largeOffset); addr != "0x0000000000000000000000000000000000000000" {
		t.Errorf("expected default address for large offset integer overflow in DecodeAddress, got %s", addr)
	}
	if val := DecodeUint256(validOffsetData, largeOffset); val.Sign() != 0 {
		t.Errorf("expected 0 for large offset integer overflow in DecodeUint256")
	}
	if b := DecodeBool(validOffsetData, largeOffset); b {
		t.Errorf("expected false for large offset integer overflow in DecodeBool")
	}
}

func TestPadLeftAndRightBytes(t *testing.T) {
	input := []byte{0x12, 0x34}
	paddedLeft := PadLeftBytes(input, 4)
	if len(paddedLeft) != 4 || paddedLeft[0] != 0 || paddedLeft[1] != 0 || paddedLeft[2] != 0x12 || paddedLeft[3] != 0x34 {
		t.Fatalf("unexpected PadLeftBytes output: %x", paddedLeft)
	}

	paddedRight := PadRightBytes(input, 4)
	if len(paddedRight) != 4 || paddedRight[0] != 0x12 || paddedRight[1] != 0x34 || paddedRight[2] != 0 || paddedRight[3] != 0 {
		t.Fatalf("unexpected PadRightBytes output: %x", paddedRight)
	}

	// No padding needed case
	if res := PadLeftBytes(input, 2); &res[0] != &input[0] {
		t.Fatalf("expected original slice reference when length >= target")
	}
}

func BenchmarkPadLeftBytes(b *testing.B) {
	input := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = PadLeftBytes(input, 32)
	}
}

func BenchmarkPadRightBytes(b *testing.B) {
	input := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = PadRightBytes(input, 32)
	}
}

func TestABIStringParamsEncodeDecode(t *testing.T) {
	s1 := "alice.twig"
	s2 := "did:key:z6MksDvRhDBYj9CdqhZMeRF95axLdFsX5q81RzfJsgRLHNmT"
	encoded := EncodeStringParams(s1, s2)

	dec1, err := DecodeString(encoded, 0)
	if err != nil {
		t.Fatalf("failed to decode str1: %v", err)
	}
	if dec1 != s1 {
		t.Fatalf("str1 = %s, want %s", dec1, s1)
	}

	dec2, err := DecodeString(encoded, 32)
	if err != nil {
		t.Fatalf("failed to decode str2: %v", err)
	}
	if dec2 != s2 {
		t.Fatalf("str2 = %s, want %s", dec2, s2)
	}
}

func BenchmarkEncodeStringParameter(b *testing.B) {
	s := "alice.twig"
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = EncodeStringParameter(s)
	}
}

func BenchmarkDecodeString(b *testing.B) {
	s := EncodeStringParameter("alice.twig")
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = DecodeString(s, 0)
	}
}

func BenchmarkDecodeAddress(b *testing.B) {
	data := make([]byte, 64)
	copy(data[44:64], []byte("01234567890123456789"))
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = DecodeAddress(data, 32)
	}
}

func BenchmarkDecodeBool(b *testing.B) {
	data := make([]byte, 32)
	data[31] = 1
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = DecodeBool(data, 0)
	}
}
