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
	"encoding/hex"
	"errors"
	"math/big"
)

var (
	secpP, _    = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	secpN, _    = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	secpB, _    = new(big.Int).SetString("0000000000000000000000000000000000000000000000000000000000000007", 16)
	secpGx, _   = new(big.Int).SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
	secpGy, _   = new(big.Int).SetString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
	secpHalfN   = new(big.Int).Rsh(secpN, 1)
	secp3       = big.NewInt(3)
	secpSqrtExp = new(big.Int).Rsh(new(big.Int).Add(secpP, big.NewInt(1)), 2)
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

type secpScratch struct {
	t1, t2, t3, lambda big.Int
}

func (c *secp256k1Curve) affineDoubleScratch(x1, y1 *big.Int, s *secpScratch) (x, y *big.Int) {
	if x1 == nil || y1 == nil || y1.Sign() == 0 {
		return nil, nil // point at infinity
	}
	// lambda = 3*x1^2 / (2*y1)
	s.t1.Mul(x1, x1)
	s.t1.Mul(&s.t1, secp3)
	s.t2.Lsh(y1, 1)
	s.t2.ModInverse(&s.t2, secpP)
	s.lambda.Mul(&s.t1, &s.t2)
	s.lambda.Mod(&s.lambda, secpP)
	// x3 = lambda^2 - 2*x1
	s.t3.Mul(&s.lambda, &s.lambda)
	s.t1.Lsh(x1, 1)
	s.t3.Sub(&s.t3, &s.t1)
	s.t3.Mod(&s.t3, secpP)
	// y3 = lambda*(x1-x3) - y1
	s.t1.Sub(x1, &s.t3)
	s.t1.Mul(&s.lambda, &s.t1)
	s.t1.Sub(&s.t1, y1)
	s.t1.Mod(&s.t1, secpP)
	return new(big.Int).Set(&s.t3), new(big.Int).Set(&s.t1)
}

func (c *secp256k1Curve) affineDoubleInPlace(rx, ry *big.Int, s *secpScratch) bool {
	if rx == nil || ry == nil || ry.Sign() == 0 {
		return false // point at infinity
	}
	// lambda = 3*rx^2 / (2*ry)
	s.t1.Mul(rx, rx)
	s.t1.Mul(&s.t1, secp3)
	s.t2.Lsh(ry, 1)
	s.t2.ModInverse(&s.t2, secpP)
	s.lambda.Mul(&s.t1, &s.t2)
	s.lambda.Mod(&s.lambda, secpP)
	// x3 = lambda^2 - 2*rx
	s.t3.Mul(&s.lambda, &s.lambda)
	s.t1.Lsh(rx, 1)
	s.t3.Sub(&s.t3, &s.t1)
	s.t3.Mod(&s.t3, secpP)
	// y3 = lambda*(rx-x3) - ry
	s.t1.Sub(rx, &s.t3)
	s.t1.Mul(&s.lambda, &s.t1)
	s.t1.Sub(&s.t1, ry)
	s.t1.Mod(&s.t1, secpP)
	rx.Set(&s.t3)
	ry.Set(&s.t1)
	return true
}

func (c *secp256k1Curve) affineAddScratch(x1, y1, x2, y2 *big.Int, s *secpScratch) (x, y *big.Int) {
	if x1 == nil || y1 == nil {
		if x2 == nil || y2 == nil {
			return nil, nil
		}
		return new(big.Int).Set(x2), new(big.Int).Set(y2)
	}
	if x2 == nil || y2 == nil {
		return new(big.Int).Set(x1), new(big.Int).Set(y1)
	}
	if x1.Cmp(x2) == 0 {
		if y1.Cmp(y2) != 0 {
			return nil, nil // point at infinity
		}
		return c.affineDoubleScratch(x1, y1, s)
	}
	// lambda = (y2-y1)/(x2-x1)
	s.t1.Sub(y2, y1)
	s.t2.Sub(x2, x1)
	s.t2.ModInverse(&s.t2, secpP)
	s.lambda.Mul(&s.t1, &s.t2)
	s.lambda.Mod(&s.lambda, secpP)
	// x3 = lambda^2 - x1 - x2
	s.t3.Mul(&s.lambda, &s.lambda)
	s.t3.Sub(&s.t3, x1)
	s.t3.Sub(&s.t3, x2)
	s.t3.Mod(&s.t3, secpP)
	// y3 = lambda*(x1-x3) - y1
	s.t1.Sub(x1, &s.t3)
	s.t1.Mul(&s.lambda, &s.t1)
	s.t1.Sub(&s.t1, y1)
	s.t1.Mod(&s.t1, secpP)
	return new(big.Int).Set(&s.t3), new(big.Int).Set(&s.t1)
}

func (c *secp256k1Curve) affineAddInPlace(rx, ry, x2, y2 *big.Int, s *secpScratch) bool {
	if rx == nil || ry == nil || x2 == nil || y2 == nil {
		return false // point at infinity
	}
	if rx.Cmp(x2) == 0 {
		if ry.Cmp(y2) != 0 {
			return false // point at infinity
		}
		return c.affineDoubleInPlace(rx, ry, s)
	}
	// lambda = (y2-ry)/(x2-rx)
	s.t1.Sub(y2, ry)
	s.t2.Sub(x2, rx)
	s.t2.ModInverse(&s.t2, secpP)
	s.lambda.Mul(&s.t1, &s.t2)
	s.lambda.Mod(&s.lambda, secpP)
	// x3 = lambda^2 - rx - x2
	s.t3.Mul(&s.lambda, &s.lambda)
	s.t3.Sub(&s.t3, rx)
	s.t3.Sub(&s.t3, x2)
	s.t3.Mod(&s.t3, secpP)
	// y3 = lambda*(rx-x3) - ry
	s.t1.Sub(rx, &s.t3)
	s.t1.Mul(&s.lambda, &s.t1)
	s.t1.Sub(&s.t1, ry)
	s.t1.Mod(&s.t1, secpP)
	rx.Set(&s.t3)
	ry.Set(&s.t1)
	return true
}

func (c *secp256k1Curve) affineAdd(x1, y1, x2, y2 *big.Int) (x, y *big.Int) {
	var scratch secpScratch
	return c.affineAddScratch(x1, y1, x2, y2, &scratch)
}

func (c *secp256k1Curve) affineDouble(x1, y1 *big.Int) (x, y *big.Int) {
	var scratch secpScratch
	return c.affineDoubleScratch(x1, y1, &scratch)
}

func (c *secp256k1Curve) Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int) {
	return c.affineAdd(x1, y1, x2, y2)
}

func (c *secp256k1Curve) Double(x1, y1 *big.Int) (x, y *big.Int) {
	return c.affineDouble(x1, y1)
}

// ScalarMult computes k*(x1, y1).
// Optimized: Uses single secpScratch struct and in-place point operations during loop
// iterations to eliminate thousands of big.Int heap allocations per scalar multiplication.
func (c *secp256k1Curve) ScalarMult(x1, y1 *big.Int, k []byte) (x, y *big.Int) {
	if x1 == nil || y1 == nil {
		return nil, nil
	}
	var rx, ry *big.Int
	var scratch secpScratch
	for _, b := range k {
		for i := 7; i >= 0; i-- {
			if rx != nil {
				if !c.affineDoubleInPlace(rx, ry, &scratch) {
					rx, ry = nil, nil
				}
			}
			if (b>>uint(i))&1 == 1 {
				if rx == nil {
					rx, ry = new(big.Int).Set(x1), new(big.Int).Set(y1)
				} else {
					if !c.affineAddInPlace(rx, ry, x1, y1, &scratch) {
						rx, ry = nil, nil
					}
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
// Optimized: Uses FillBytes to pad and copy x and y directly into a fixed 64-byte
// stack array pub [64]byte, eliminating heap allocations from x.Bytes() and y.Bytes().
func addressFromPubkey(x, y *big.Int) [20]byte {
	var pub [64]byte
	x.FillBytes(pub[:32])
	y.FillBytes(pub[32:64])
	h := Keccak256(pub[:])
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
	var dBuf [32]byte
	d.FillBytes(dBuf[:])
	x, y := curve.ScalarBaseMult(dBuf[:])
	addr := addressFromPubkey(x, y)
	return "0x" + hexEncode(addr[:]), nil
}

// secpSign signs msgHash (32 bytes) with the private key, returning low-S
// (r, s) per EIP-2 and the y-parity bit for EIP-1559.
func secpSign(d *big.Int, msgHash []byte) (r, s *big.Int, yParity byte, err error) {
	curve := secp256k1()
	priv := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: curve}, D: d}
	var dBuf [32]byte
	d.FillBytes(dBuf[:])
	priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(dBuf[:])
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
	// Optimized: Uses precomputed package variable secpSqrtExp = (P+1)/4 to avoid allocations.
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)
	x3.Add(x3, secpB)
	x3.Mod(x3, secpP)
	y := new(big.Int).Exp(x3, secpSqrtExp, secpP)
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
	// Optimized: Uses FillBytes into stack buffers instead of PadLeftBytes(x.Bytes(), 32)
	// to eliminate temporary byte slice heap allocations during public key recovery.
	var sBuf, eBuf, rInvBuf [32]byte
	s.FillBytes(sBuf[:])
	sRx, sRy := curve.ScalarMult(x, y, sBuf[:])
	// e*G
	e.FillBytes(eBuf[:])
	eGx, eGy := curve.ScalarBaseMult(eBuf[:])
	// s*R - e*G
	neGy := new(big.Int).Neg(eGy)
	neGy.Mod(neGy, secpP)
	sx, sy := curve.Add(sRx, sRy, eGx, neGy)
	if sx == nil {
		return nil, nil, errors.New("recovery produced infinity")
	}
	rInv.FillBytes(rInvBuf[:])
	qx, qy := curve.ScalarMult(sx, sy, rInvBuf[:])
	return qx, qy, nil
}

func hexEncode(b []byte) string {
	// Optimized: Uses encoding/hex to avoid loop/append slice overhead.
	return hex.EncodeToString(b)
}
