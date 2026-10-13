package did

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
)

func TestBase58RoundTrip(t *testing.T) {
	cases := [][]byte{
		{},
		{0},
		{0, 0, 0},
		{0, 0, 1, 2, 3},
		[]byte("hello world"),
		{0xed, 0x01, 0x12, 0x34, 0x56, 0x78},
		make([]byte, 32),
		make([]byte, 34),
		[]byte{0xff, 0xff, 0xff, 0xff},
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

	// Test invalid character error handling
	if _, err := DecodeBase58("invalid!char"); err == nil {
		t.Fatalf("expected error decoding string with invalid characters, got nil")
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

func BenchmarkEncodeBase58(b *testing.B) {
	data := []byte{0xed, 0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		EncodeBase58(data)
	}
}

func BenchmarkDecodeBase58(b *testing.B) {
	str := "1123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DecodeBase58(str)
	}
}

func BenchmarkFromVerifyingKey(b *testing.B) {
	pub := make(ed25519.PublicKey, 32)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		FromVerifyingKey(pub)
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
