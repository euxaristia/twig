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
// Optimized base conversion without math/big to avoid heap allocations and big integer arithmetic overhead.
func EncodeBase58(input []byte) string {
	if len(input) == 0 {
		return ""
	}

	zeros := 0
	for zeros < len(input) && input[zeros] == 0 {
		zeros++
	}

	// log(256) / log(58) ≈ 1.3656
	size := (len(input)-zeros)*138/100 + 1
	var buf [128]byte
	var b58 []byte
	if size <= len(buf) {
		b58 = buf[:size]
	} else {
		b58 = make([]byte, size)
	}

	length := 0
	for _, b := range input[zeros:] {
		carry := uint32(b)
		i := 0
		for it := size - 1; (carry != 0 || i < length) && it >= 0; it-- {
			carry += 256 * uint32(b58[it])
			b58[it] = byte(carry % 58)
			carry /= 58
			i++
		}
		length = i
	}

	it := size - length
	for it < size && b58[it] == 0 {
		it++
	}

	result := make([]byte, zeros+(size-it))
	for i := 0; i < zeros; i++ {
		result[i] = b58Alphabet[0]
	}
	p := zeros
	for ; it < size; it++ {
		result[p] = b58Alphabet[b58[it]]
		p++
	}

	return string(result)
}

// DecodeBase58 decodes a Bitcoin base58 encoded string.
// Optimized base conversion without math/big to avoid heap allocations and big integer arithmetic overhead.
func DecodeBase58(input string) ([]byte, error) {
	if len(input) == 0 {
		return nil, nil
	}

	zeros := 0
	for zeros < len(input) && input[zeros] == b58Alphabet[0] {
		zeros++
	}

	// log(58) / log(256) ≈ 0.7324
	size := (len(input)-zeros)*733/1000 + 1
	var buf [128]byte
	var bin []byte
	if size <= len(buf) {
		bin = buf[:size]
	} else {
		bin = make([]byte, size)
	}

	length := 0
	for i := zeros; i < len(input); i++ {
		idx := b58Indexes[input[i]]
		if idx == -1 {
			return nil, fmt.Errorf("invalid base58 character: %c", input[i])
		}

		carry := uint32(idx)
		j := 0
		for it := size - 1; (carry != 0 || j < length) && it >= 0; it-- {
			carry += 58 * uint32(bin[it])
			bin[it] = byte(carry & 0xff)
			carry >>= 8
			j++
		}
		length = j
	}

	it := size - length
	for it < size && bin[it] == 0 {
		it++
	}

	result := make([]byte, zeros+(size-it))
	copy(result[zeros:], bin[it:])
	return result, nil
}

// FromVerifyingKey constructs a did:key string from an Ed25519 public key.
func FromVerifyingKey(pubKey ed25519.PublicKey) string {
	if len(pubKey) == ed25519.PublicKeySize {
		var prefixed [34]byte
		copy(prefixed[:], ed25519Multicodec)
		copy(prefixed[len(ed25519Multicodec):], pubKey)
		return "did:key:z" + EncodeBase58(prefixed[:])
	}
	prefixed := make([]byte, 0, len(ed25519Multicodec)+len(pubKey))
	prefixed = append(prefixed, ed25519Multicodec...)
	prefixed = append(prefixed, pubKey...)
	return "did:key:z" + EncodeBase58(prefixed)
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
