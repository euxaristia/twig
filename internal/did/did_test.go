package did

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
)

func TestBase58RoundTrip(t *testing.T) {
	cases := [][]byte{
		{},
		{0},
		{0, 0, 1, 2, 3},
		[]byte("hello world"),
		{0xed, 0x01, 0x12, 0x34, 0x56, 0x78},
	}

	for _, c := range cases {
		encoded := EncodeBase58(c)
		decoded, err := DecodeBase58(encoded)
		if err != nil {
			t.Fatalf("decode error for %v: %v", c, err)
		}
		if string(decoded) != string(c) {
			t.Fatalf("expected %v, got %v", c, decoded)
		}
	}
}

func TestDidKeyGenerationAndParse(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	did := FromVerifyingKey(pub)
	if !strings.HasPrefix(did, "did:key:z6Mk") {
		t.Fatalf("expected did to start with did:key:z6Mk, got %s", did)
	}

	recovered, err := ToVerifyingKey(did)
	if err != nil {
		t.Fatalf("failed to recover verifying key: %v", err)
	}

	if !pub.Equal(recovered) {
		t.Fatalf("recovered key does not match original key")
	}
}

func TestDIDDocument(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	did := FromVerifyingKey(pub)
	doc := NewDIDDocument(did)
	if doc.ID != did {
		t.Fatalf("expected doc ID to match did")
	}
	if len(doc.VerificationMethod) != 1 {
		t.Fatalf("expected 1 verification method")
	}
}

func BenchmarkEncodeBase58(b *testing.B) {
	data := append([]byte{0xed, 0x01}, make([]byte, 32)...)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = EncodeBase58(data)
	}
}

func BenchmarkDecodeBase58(b *testing.B) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	d := FromVerifyingKey(pub)
	encoded := strings.TrimPrefix(d, "did:key:z")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DecodeBase58(encoded)
	}
}

func TestBase58KnownVectors(t *testing.T) {
	// Test vectors from Bitcoin Core's base58_tests.cpp.
	hexCases := []struct {
		hex     string
		encoded string
	}{
		{"", ""},
		{"61", "2g"},
		{"626262", "a3gV"},
		{"636363", "aPEr"},
		{"73696d706c792061206c6f6e6720737472696e67", "2cFupjhnEsSn59qHXstmK2ffpLv2"},
		{"00eb15231dfceb60925886b67d74", "1LafrWUQKYSX7Xn36Fu"},
		{"00000000000000000000", "1111111111"},
	}

	for _, c := range hexCases {
		raw, err := hex.DecodeString(c.hex)
		if err != nil {
			t.Fatalf("bad test vector hex %q: %v", c.hex, err)
		}
		if got := EncodeBase58(raw); got != c.encoded {
			t.Fatalf("EncodeBase58(%x) = %q, want %q", raw, got, c.encoded)
		}
		decoded, err := DecodeBase58(c.encoded)
		if err != nil {
			t.Fatalf("DecodeBase58(%q) error: %v", c.encoded, err)
		}
		if string(decoded) != string(raw) {
			t.Fatalf("DecodeBase58(%q) = %x, want %x", c.encoded, decoded, raw)
		}
	}
}

func TestBase58InvalidCharacters(t *testing.T) {
	// 0, O, I, l are not part of the Bitcoin base58 alphabet.
	for _, s := range []string{"0", "O", "I", "l", "abc0def", "12O34"} {
		if _, err := DecodeBase58(s); err == nil {
			t.Fatalf("DecodeBase58(%q) expected error, got nil", s)
		}
	}
}

func TestBase58LargeInputHeapPath(t *testing.T) {
	// 200 bytes needs a 277-byte scratch buffer, exercising the heap
	// fallback (stack buffer is 128 bytes).
	raw := make([]byte, 200)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}
	encoded := EncodeBase58(raw)
	decoded, err := DecodeBase58(encoded)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if string(decoded) != string(raw) {
		t.Fatalf("large roundtrip mismatch")
	}
}
