package did

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func BenchmarkEncodeBase58(b *testing.B) {
	data := []byte{0xed, 0x01, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = EncodeBase58(data)
	}
}

func BenchmarkDecodeBase58(b *testing.B) {
	data := []byte{0xed, 0x01, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	encoded := EncodeBase58(data)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DecodeBase58(encoded)
	}
}

func BenchmarkFromVerifyingKey(b *testing.B) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = FromVerifyingKey(pub)
	}
}

func BenchmarkToVerifyingKey(b *testing.B) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	did := FromVerifyingKey(pub)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ToVerifyingKey(did)
	}
}
