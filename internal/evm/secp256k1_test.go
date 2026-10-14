package evm

import (
	"crypto/ecdsa"
	"math/big"
	"strings"
	"testing"
)

func TestSecp256k1Generator(t *testing.T) {
	c := secp256k1()
	x, y := c.ScalarBaseMult([]byte{1})
	if x.Cmp(secpGx) != 0 || y.Cmp(secpGy) != 0 {
		t.Fatalf("1*G != G")
	}
	if !c.IsOnCurve(x, y) {
		t.Fatalf("G not on curve")
	}
}

func TestSecp256k1DoubleG(t *testing.T) {
	// Known 2*G from SEC 2.
	wantX, _ := new(big.Int).SetString("C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5", 16)
	wantY, _ := new(big.Int).SetString("1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A", 16)
	c := secp256k1()
	x, y := c.ScalarBaseMult([]byte{2})
	if x.Cmp(wantX) != 0 || y.Cmp(wantY) != 0 {
		t.Fatalf("2*G mismatch:\n%x\n%x", x, y)
	}
}

func TestPrivateKeyToAddressVector(t *testing.T) {
	// Well-known test vector: privkey 0x01.
	addr, err := PrivateKeyToAddress("0x0000000000000000000000000000000000000000000000000000000000000001")
	if err != nil {
		t.Fatalf("PrivateKeyToAddress failed: %v", err)
	}
	want := "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
	if strings.ToLower(addr) != want {
		t.Fatalf("address = %s, want %s", addr, want)
	}
}

func TestPrivateKeyValidation(t *testing.T) {
	for _, bad := range []string{"", "0x1234", "zzzz", strings.Repeat("0", 64), "0x" + strings.Repeat("f", 64)} {
		if _, err := parsePrivateKey(bad); err == nil {
			t.Errorf("expected error for key %q", bad[:min(10, len(bad))])
		}
	}
	// N itself is out of range.
	nHex := "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
	if _, err := parsePrivateKey(nHex); err == nil {
		t.Errorf("expected error for key == N")
	}
}

func TestSecpSignAndRecover(t *testing.T) {
	d, err := parsePrivateKey("0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("parsePrivateKey failed: %v", err)
	}
	msgHash := Keccak256([]byte("hello twigpine"))
	r, s, yParity, err := secpSign(d, msgHash)
	if err != nil {
		t.Fatalf("secpSign failed: %v", err)
	}
	if s.Cmp(secpHalfN) > 0 {
		t.Fatalf("S not normalized low")
	}
	// Verify with stdlib ECDSA.
	curve := secp256k1()
	px, py := curve.ScalarBaseMult(PadLeftBytes(d.Bytes(), 32))
	pub := ecdsa.PublicKey{Curve: curve, X: px, Y: py}
	if !ecdsa.Verify(&pub, msgHash, r, s) {
		t.Fatalf("ECDSA verification failed")
	}
	// Recovery must yield the signer.
	qx, qy, err := recoverPubkey(r, s, msgHash, yParity)
	if err != nil {
		t.Fatalf("recoverPubkey failed: %v", err)
	}
	if qx.Cmp(px) != 0 || qy.Cmp(py) != 0 {
		t.Fatalf("recovered key does not match signer")
	}
	addr1 := addressFromPubkey(px, py)
	addr2 := addressFromPubkey(qx, qy)
	if addr1 != addr2 {
		t.Fatalf("address mismatch after recovery")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
