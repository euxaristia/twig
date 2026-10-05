package did

import (
	"crypto/ed25519"
	"testing"
)

func BenchmarkEncodeBase58(b *testing.B) {
	pubKey, _, _ := ed25519.GenerateKey(nil)
	prefixed := append([]byte{0xed, 0x01}, pubKey...)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = EncodeBase58(prefixed)
	}
}

func BenchmarkDecodeBase58(b *testing.B) {
	pubKey, _, _ := ed25519.GenerateKey(nil)
	didStr := FromVerifyingKey(pubKey)
	enc := didStr[len("did:key:z"):]
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = DecodeBase58(enc)
	}
}

func BenchmarkFromVerifyingKey(b *testing.B) {
	pubKey, _, _ := ed25519.GenerateKey(nil)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = FromVerifyingKey(pubKey)
	}
}
