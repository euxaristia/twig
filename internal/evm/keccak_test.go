package evm

import (
	"encoding/hex"
	"testing"
)

func TestKeccak256(t *testing.T) {
	// keccak256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
	emptyHash := hex.EncodeToString(Keccak256([]byte("")))
	expectedEmpty := "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
	if emptyHash != expectedEmpty {
		t.Fatalf("expected %s, got %s", expectedEmpty, emptyHash)
	}

	// keccak256("transfer(address,uint256)") = a9059cbb2ab09eb219583f4a59a5d0623ade346d962bcd4e46b11da047c9049b
	transferHash := hex.EncodeToString(Keccak256([]byte("transfer(address,uint256)")))
	expectedTransfer := "a9059cbb2ab09eb219583f4a59a5d0623ade346d962bcd4e46b11da047c9049b"
	if transferHash != expectedTransfer {
		t.Fatalf("expected %s, got %s", expectedTransfer, transferHash)
	}
}

func BenchmarkKeccak256(b *testing.B) {
	data := []byte("hello world this is a test string for keccak256 benchmarking")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Keccak256(data)
	}
}
