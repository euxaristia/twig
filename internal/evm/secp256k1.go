package evm

// Minimal secp256k1 for Ethereum transaction signing, built on the standard
// library's ECDSA over an explicit curve description. No new dependencies.
//
// The curve parameters are the well-known secp256k1 constants. Signatures use
// the stdlib's ECDSA (CSPRNG nonces) with low-S normalization per EIP-2, and
// public-key recovery for the EIP-1559 y-parity bit.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"math/big"
)

var (
	secpP, _  = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	secpN, _  = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	secpB, _  = new(big.Int).SetString("0000000000000000000000000000000000000000000000000000000000000007", 16)
	secpGx, _ = new(big.Int).SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
	secpGy, _ = new(big.Int).SetString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
	secpHalfN = new(big.Int).Rsh(secpN, 1)
)

type secp256k1Curve struct {
	params *elliptic.CurveParams
}

func secp256k1() *secp256k1Curve {
	return &secp256k1Curve{
		params: &elliptic.CurveParams{
			P:       secpP,
			N:       secpN,
			B:       secpB,
			Gx:      secpGx,
			Gy:      secpGy,
			BitSize: 256,
			Name:    "secp256k1",
		},
	}
}

func (c *secp256k1Curve) Params() *elliptic.CurveParams { return c.params }

func (c *secp256k1Curve) IsOnCurve(x, y *big.Int) bool {
	if x == nil || y == nil {
		return false
	}
	// y^2 == x^3 + 7 (mod P)
	y2 := new(big.Int).Mul(y, y)
	y2.Mod(y2, secpP)
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)
	x3.Add(x3, secpB)
	x3.Mod(x3, secpP)
	return y2.Cmp(x3) == 0
}

func (c *secp256k1Curve) affineAdd(x1, y1, x2, y2 *big.Int) (x, y *big.Int) {
	if x1 == nil || y1 == nil {
		return x2, y2
	}
	if x2 == nil || y2 == nil {
		return x1, y1
	}
	if x1.Cmp(x2) == 0 {
		if y1.Cmp(y2) != 0 {
			return nil, nil // point at infinity
		}
		return c.affineDouble(x1, y1)
	}
	// lambda = (y2-y1)/(x2-x1)
	num := new(big.Int).Sub(y2, y1)
	den := new(big.Int).Sub(x2, x1)
	den.ModInverse(den, secpP)
	lambda := num.Mul(num, den)
	lambda.Mod(lambda, secpP)
	// x3 = lambda^2 - x1 - x2
	x3 := new(big.Int).Mul(lambda, lambda)
	x3.Sub(x3, x1)
	x3.Sub(x3, x2)
	x3.Mod(x3, secpP)
	// y3 = lambda*(x1-x3) - y1
	y3 := new(big.Int).Sub(x1, x3)
	y3.Mul(lambda, y3)
	y3.Sub(y3, y1)
	y3.Mod(y3, secpP)
	return x3, y3
}

func (c *secp256k1Curve) affineDouble(x1, y1 *big.Int) (x, y *big.Int) {
	if x1 == nil || y1 == nil || y1.Sign() == 0 {
		return nil, nil // point at infinity
	}
	// lambda = 3*x1^2 / (2*y1)
	num := new(big.Int).Mul(x1, x1)
	num.Mul(num, big.NewInt(3))
	den := new(big.Int).Lsh(y1, 1)
	den.ModInverse(den, secpP)
	lambda := num.Mul(num, den)
	lambda.Mod(lambda, secpP)
	// x3 = lambda^2 - 2*x1
	x3 := new(big.Int).Mul(lambda, lambda)
	x3.Sub(x3, new(big.Int).Lsh(x1, 1))
	x3.Mod(x3, secpP)
	// y3 = lambda*(x1-x3) - y1
	y3 := new(big.Int).Sub(x1, x3)
	y3.Mul(lambda, y3)
	y3.Sub(y3, y1)
	y3.Mod(y3, secpP)
	return x3, y3
}

func (c *secp256k1Curve) Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int) {
	return c.affineAdd(x1, y1, x2, y2)
}

func (c *secp256k1Curve) Double(x1, y1 *big.Int) (x, y *big.Int) {
	return c.affineDouble(x1, y1)
}

func (c *secp256k1Curve) ScalarMult(x1, y1 *big.Int, k []byte) (x, y *big.Int) {
	var rx, ry *big.Int
	for _, b := range k {
		for i := 7; i >= 0; i-- {
			if rx != nil {
				rx, ry = c.affineDouble(rx, ry)
			}
			if (b>>uint(i))&1 == 1 {
				if rx == nil {
					rx, ry = new(big.Int).Set(x1), new(big.Int).Set(y1)
				} else {
					rx, ry = c.affineAdd(rx, ry, x1, y1)
				}
			}
		}
	}
	return rx, ry
}

func (c *secp256k1Curve) ScalarBaseMult(k []byte) (x, y *big.Int) {
	return c.ScalarMult(secpGx, secpGy, k)
}

// parsePrivateKey validates a hex private key: 32 bytes, 0 < key < N.
func parsePrivateKey(hexKey string) (*big.Int, error) {
	s := hexKey
	if len(s) >= 2 && (s[:2] == "0x" || s[:2] == "0X") {
		s = s[2:]
	}
	if len(s) != 64 {
		return nil, errors.New("private key must be 32 bytes (64 hex chars)")
	}
	d := new(big.Int)
	if _, ok := d.SetString(s, 16); !ok {
		return nil, errors.New("private key is not valid hex")
	}
	if d.Sign() <= 0 || d.Cmp(secpN) >= 0 {
		return nil, errors.New("private key out of range")
	}
	return d, nil
}

// addressFromPubkey derives the Ethereum address from uncompressed x, y.
func addressFromPubkey(x, y *big.Int) [20]byte {
	xb := PadLeftBytes(x.Bytes(), 32)
	yb := PadLeftBytes(y.Bytes(), 32)
	h := Keccak256(append(xb, yb...))
	var addr [20]byte
	copy(addr[:], h[12:])
	return addr
}

// PrivateKeyToAddress derives the checksummed-lowercase hex address.
func PrivateKeyToAddress(hexKey string) (string, error) {
	d, err := parsePrivateKey(hexKey)
	if err != nil {
		return "", err
	}
	curve := secp256k1()
	x, y := curve.ScalarBaseMult(PadLeftBytes(d.Bytes(), 32))
	addr := addressFromPubkey(x, y)
	return "0x" + hexEncode(addr[:]), nil
}

// secpSign signs msgHash (32 bytes) with the private key, returning low-S
// (r, s) per EIP-2 and the y-parity bit for EIP-1559.
func secpSign(d *big.Int, msgHash []byte) (r, s *big.Int, yParity byte, err error) {
	curve := secp256k1()
	priv := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: curve}, D: d}
	priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(PadLeftBytes(d.Bytes(), 32))
	r, s, err = ecdsa.Sign(rand.Reader, priv, msgHash)
	if err != nil {
		return nil, nil, 0, err
	}
	// EIP-2: low-S normalization.
	if s.Cmp(secpHalfN) > 0 {
		s.Sub(secpN, s)
	}
	yParity, err = recoverYParity(priv.PublicKey.X, priv.PublicKey.Y, r, s, msgHash)
	if err != nil {
		return nil, nil, 0, err
	}
	return r, s, yParity, nil
}

// recoverYParity finds the parity bit (0/1) whose recovered key matches the
// signer's public key.
func recoverYParity(px, py, r, s *big.Int, msgHash []byte) (byte, error) {
	for parity := byte(0); parity <= 1; parity++ {
		qx, qy, err := recoverPubkey(r, s, msgHash, parity)
		if err != nil {
			continue
		}
		if qx.Cmp(px) == 0 && qy.Cmp(py) == 0 {
			return parity, nil
		}
	}
	return 0, errors.New("could not recover y-parity")
}

// recoverPubkey recovers the public key from (r, s, hash, parity).
func recoverPubkey(r, s *big.Int, msgHash []byte, parity byte) (*big.Int, *big.Int, error) {
	// x = r (r < N < P, so no wraparound for y-parity 0/1)
	x := new(big.Int).Set(r)
	// y = sqrt(x^3 + 7) mod P; P % 4 == 3 so sqrt(a) = a^((P+1)/4)
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)
	x3.Add(x3, secpB)
	x3.Mod(x3, secpP)
	exp := new(big.Int).Add(secpP, big.NewInt(1))
	exp.Rsh(exp, 2)
	y := new(big.Int).Exp(x3, exp, secpP)
	if y.Bit(0) != uint(parity) {
		y.Sub(secpP, y)
	}
	curve := secp256k1()
	if !curve.IsOnCurve(x, y) {
		return nil, nil, errors.New("recovered point not on curve")
	}
	// Q = r^-1 * (s*R - e*G), e = hash as integer truncated to N bits
	e := new(big.Int).SetBytes(msgHash)
	if e.BitLen() > 256 {
		e.Rsh(e, uint(e.BitLen()-256))
	}
	rInv := new(big.Int).ModInverse(r, secpN)
	if rInv == nil {
		return nil, nil, errors.New("no modular inverse for r")
	}
	// s*R
	sRx, sRy := curve.ScalarMult(x, y, PadLeftBytes(s.Bytes(), 32))
	// e*G
	eGx, eGy := curve.ScalarBaseMult(PadLeftBytes(e.Bytes(), 32))
	// s*R - e*G
	neGy := new(big.Int).Neg(eGy)
	neGy.Mod(neGy, secpP)
	sx, sy := curve.Add(sRx, sRy, eGx, neGy)
	if sx == nil {
		return nil, nil, errors.New("recovery produced infinity")
	}
	qx, qy := curve.ScalarMult(sx, sy, PadLeftBytes(rInv.Bytes(), 32))
	return qx, qy, nil
}

func hexEncode(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, v := range b {
		out = append(out, digits[v>>4], digits[v&0x0f])
	}
	return string(out)
}
