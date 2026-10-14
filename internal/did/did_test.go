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
	input := []byte{0xed, 0x01, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = EncodeBase58(input)
	}
}

func BenchmarkDecodeBase58(b *testing.B) {
	input := "z6MkrRztzc985Jm8Bjq2nKusVniF6oatDiWtkoxv4JWJZ4Uq"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DecodeBase58(input[1:])
	}
}

func BenchmarkFromVerifyingKey(b *testing.B) {
	pub := ed25519.PublicKey(make([]byte, 32))
	for i := 0; i < 32; i++ {
		pub[i] = byte(i)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = FromVerifyingKey(pub)
	}
}

func BenchmarkToVerifyingKey(b *testing.B) {
	did := "did:key:z6MkrRztzc985Jm8Bjq2nKusVniF6oatDiWtkoxv4JWJZ4Uq"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ToVerifyingKey(did)
	}
}
