package did

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
)

const (
	b58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
)

var (
	ed25519Multicodec = []byte{0xed, 0x01}
	b58Indexes        [256]int
)

func init() {
	for i := 0; i < 256; i++ {
		b58Indexes[i] = -1
	}
	for i, c := range b58Alphabet {
		b58Indexes[c] = i
	}
}

// EncodeBase58 encodes a byte slice into Bitcoin base58.
// Optimized to perform base conversion in-place using stack-allocated buffers,
// avoiding big.Int heap allocations and arithmetic overhead.
func EncodeBase58(input []byte) string {
	if len(input) == 0 {
		return ""
	}

	zeros := 0
	for zeros < len(input) && input[zeros] == 0 {
		zeros++
	}

	var tmpBuf [128]byte
	var tmp []byte
	if len(input) <= len(tmpBuf) {
		tmp = tmpBuf[:len(input)]
		copy(tmp, input)
	} else {
		tmp = make([]byte, len(input))
		copy(tmp, input)
	}

	outCap := len(input)*138/100 + 2
	var outBuf [256]byte
	var out []byte
	if outCap <= len(outBuf) {
		out = outBuf[:0]
	} else {
		out = make([]byte, 0, outCap)
	}

	start := zeros
	for start < len(tmp) {
		var remainder uint32
		for i := start; i < len(tmp); i++ {
			acc := uint32(tmp[i]) + remainder*256
			tmp[i] = byte(acc / 58)
			remainder = acc % 58
		}
		out = append(out, b58Alphabet[remainder])
		for start < len(tmp) && tmp[start] == 0 {
			start++
		}
	}

	for i := 0; i < zeros; i++ {
		out = append(out, b58Alphabet[0])
	}

	// Reverse
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}

	return string(out)
}

// DecodeBase58 decodes a Bitcoin base58 encoded string.
// Optimized to convert base58 to bytes directly using stack-allocated buffers,
// eliminating big.Int allocations.
func DecodeBase58(input string) ([]byte, error) {
	if len(input) == 0 {
		return nil, nil
	}

	zeros := 0
	for zeros < len(input) && input[zeros] == b58Alphabet[0] {
		zeros++
	}

	outCap := (len(input)-zeros)*733/1000 + 1
	var outBuf [128]byte
	var out []byte
	if outCap <= len(outBuf) {
		out = outBuf[:outCap]
		for i := range out {
			out[i] = 0
		}
	} else {
		out = make([]byte, outCap)
	}

	outLen := 0
	for i := zeros; i < len(input); i++ {
		idx := b58Indexes[input[i]]
		if idx == -1 {
			return nil, fmt.Errorf("invalid base58 character: %c", input[i])
		}

		carry := uint32(idx)
		for j := 0; j < outLen; j++ {
			acc := uint32(out[outCap-1-j])*58 + carry
			out[outCap-1-j] = byte(acc)
			carry = acc >> 8
		}
		for carry > 0 {
			if outLen >= len(out) {
				newOut := make([]byte, len(out)+8)
				copy(newOut[8:], out)
				out = newOut
				outCap = len(out)
			}
			acc := uint32(out[outCap-1-outLen])*58 + carry
			out[outCap-1-outLen] = byte(acc)
			carry = acc >> 8
			outLen++
		}
	}

	start := outCap - outLen
	for start < outCap && out[start] == 0 {
		start++
	}

	actualBytesLen := outCap - start
	result := make([]byte, zeros+actualBytesLen)
	copy(result[zeros:], out[start:outCap])
	return result, nil
}

// FromVerifyingKey constructs a did:key string from an Ed25519 public key.
// Optimized with stack array allocation and direct string concatenation.
func FromVerifyingKey(pubKey ed25519.PublicKey) string {
	var prefixed [34]byte
	prefixed[0] = ed25519Multicodec[0]
	prefixed[1] = ed25519Multicodec[1]
	copy(prefixed[2:], pubKey)

	encoded := EncodeBase58(prefixed[:])
	return "did:key:z" + encoded
}

// ToVerifyingKey extracts the Ed25519 public key from a did:key string.
func ToVerifyingKey(did string) (ed25519.PublicKey, error) {
	if !strings.HasPrefix(did, "did:key:") {
		return nil, errors.New("expected did:key prefix")
	}

	methodID := strings.TrimPrefix(did, "did:key:")
	if len(methodID) > 64 {
		return nil, errors.New("did:key method-specific id too long")
	}

	if !strings.HasPrefix(methodID, "z") {
		return nil, errors.New("missing multibase 'z' prefix")
	}

	data, error := DecodeBase58(methodID[1:])
	if error != nil {
		return nil, fmt.Errorf("base58 decode error: %w", error)
	}

	if len(data) < len(ed25519Multicodec) || data[0] != ed25519Multicodec[0] || data[1] != ed25519Multicodec[1] {
		return nil, errors.New("missing or invalid ed25519 multicodec prefix")
	}

	pubKey := data[len(ed25519Multicodec):]
	if len(pubKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("expected 32-byte public key, got %d bytes", len(pubKey))
	}

	return ed25519.PublicKey(pubKey), nil
}

// ShortDID returns the last segment of a DID (after the last colon), or the full DID.
func ShortDID(did string) string {
	idx := strings.LastIndex(did, ":")
	if idx >= 0 && idx < len(did)-1 {
		return did[idx+1:]
	}
	return did
}

// DIDDocument represents a standard W3C DID document for did:key.
type DIDDocument struct {
	Context            []string             `json:"@context"`
	ID                 string               `json:"id"`
	VerificationMethod []VerificationMethod `json:"verificationMethod"`
	Authentication     []string             `json:"authentication"`
	AssertionMethod    []string             `json:"assertionMethod"`
}

// VerificationMethod describes a verification key in the DID Document.
type VerificationMethod struct {
	ID                 string `json:"id"`
	Type               string `json:"type"`
	Controller         string `json:"controller"`
	PublicKeyMultibase string `json:"publicKeyMultibase"`
}

// NewDIDDocument creates a DID document for a did:key.
func NewDIDDocument(did string) *DIDDocument {
	vmID := fmt.Sprintf("%s#%s", did, ShortDID(did))
	multibaseKey := strings.TrimPrefix(did, "did:key:")

	return &DIDDocument{
		Context: []string{
			"https://www.w3.org/ns/did/v1",
			"https://w3id.org/security/suites/ed25519-2020/v1",
		},
		ID: did,
		VerificationMethod: []VerificationMethod{
			{
				ID:                 vmID,
				Type:               "Ed25519VerificationKey2020",
				Controller:         did,
				PublicKeyMultibase: multibaseKey,
			},
		},
		Authentication:  []string{vmID},
		AssertionMethod: []string{vmID},
	}
}
