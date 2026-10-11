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
// Optimized base-256 to base-58 conversion eliminating math/big heap allocations.
func EncodeBase58(input []byte) string {
	if len(input) == 0 {
		return ""
	}

	zeros := 0
	for zeros < len(input) && input[zeros] == 0 {
		zeros++
	}

	size := (len(input)-zeros)*138/100 + 1
	var stackBuf [128]byte
	var buf []byte
	if size <= len(stackBuf) {
		buf = stackBuf[:size]
		for i := 0; i < size; i++ {
			buf[i] = 0
		}
	} else {
		buf = make([]byte, size)
	}

	var length int
	for _, b := range input[zeros:] {
		carry := int(b)
		i := 0
		for j := size - 1; (carry > 0 || i < length) && j >= 0; j-- {
			carry += int(buf[j]) * 256
			buf[j] = byte(carry % 58)
			carry /= 58
			i++
		}
		length = i
	}

	start := size - length
	for start < size && buf[start] == 0 {
		start++
	}

	out := make([]byte, zeros+(size-start))
	for i := 0; i < zeros; i++ {
		out[i] = b58Alphabet[0]
	}
	for i, b := range buf[start:] {
		out[zeros+i] = b58Alphabet[b]
	}

	return string(out)
}

// DecodeBase58 decodes a Bitcoin base58 encoded string.
// Optimized base-58 to base-256 conversion eliminating math/big heap allocations.
func DecodeBase58(input string) ([]byte, error) {
	if len(input) == 0 {
		return nil, nil
	}

	zeros := 0
	for zeros < len(input) && input[zeros] == b58Alphabet[0] {
		zeros++
	}

	size := (len(input)-zeros)*733/1000 + 1
	var stackBuf [128]byte
	var buf []byte
	if size <= len(stackBuf) {
		buf = stackBuf[:size]
		for i := 0; i < size; i++ {
			buf[i] = 0
		}
	} else {
		buf = make([]byte, size)
	}

	var length int
	for i := zeros; i < len(input); i++ {
		idx := b58Indexes[input[i]]
		if idx == -1 {
			return nil, fmt.Errorf("invalid base58 character: %c", input[i])
		}
		carry := idx
		iCount := 0
		for j := size - 1; (carry > 0 || iCount < length) && j >= 0; j-- {
			carry += int(buf[j]) * 58
			buf[j] = byte(carry & 0xff)
			carry >>= 8
			iCount++
		}
		length = iCount
	}

	start := size - length
	for start < size && buf[start] == 0 {
		start++
	}

	result := make([]byte, zeros+(size-start))
	for i, b := range buf[start:] {
		result[zeros+i] = b
	}
	return result, nil
}

// FromVerifyingKey constructs a did:key string from an Ed25519 public key.
func FromVerifyingKey(pubKey ed25519.PublicKey) string {
	var prefixed [34]byte
	copy(prefixed[:], ed25519Multicodec)
	copy(prefixed[len(ed25519Multicodec):], pubKey)

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
