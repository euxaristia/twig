package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Twigpine/twig/internal/did"
)

// Keypair represents an Ed25519 keypair for Twigpine identity.
type Keypair struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
}

// GenerateKeypair creates a new random Ed25519 keypair.
func GenerateKeypair() (*Keypair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ed25519 key: %w", err)
	}
	return &Keypair{
		PrivateKey: priv,
		PublicKey:  pub,
	}, nil
}

// FromSeed creates a Keypair from a 32-byte seed.
func FromSeed(seed []byte) (*Keypair, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("seed must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return &Keypair{
		PrivateKey: priv,
		PublicKey:  pub,
	}, nil
}

// DID returns the did:key representation of the public key.
func (k *Keypair) DID() string {
	return did.FromVerifyingKey(k.PublicKey)
}

// Sign signs arbitrary message bytes using Ed25519.
func (k *Keypair) Sign(msg []byte) []byte {
	return ed25519.Sign(k.PrivateKey, msg)
}

// SignB64 signs arbitrary bytes and returns a base64url-encoded string without padding.
func (k *Keypair) SignB64(msg []byte) string {
	sig := k.Sign(msg)
	return base64.RawURLEncoding.EncodeToString(sig)
}

// ToPEM encodes the private key into a PKCS#8 PEM block.
func (k *Keypair) ToPEM() ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}
	return pem.EncodeToMemory(block), nil
}

// FromPEM parses a Keypair from a PKCS#8 PEM string or byte slice.
func FromPEM(data []byte) (*Keypair, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to find valid PEM block in data")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#8 private key: %w", err)
	}

	privKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("key in PEM is not an Ed25519 private key")
	}

	pubKey := privKey.Public().(ed25519.PublicKey)
	return &Keypair{
		PrivateKey: privKey,
		PublicKey:  pubKey,
	}, nil
}

// Verify checks an Ed25519 signature over a message using the given public key.
func Verify(pub ed25519.PublicKey, msg, sig []byte) bool {
	if len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, msg, sig)
}

// DefaultDir returns the resolved configuration directory for Twigpine.
// If an override is provided, it is returned.
// Otherwise, checks if ~/.twigpine exists. If not, checks if ~/.gitlawb exists (legacy).
// If neither exists, defaults to ~/.twigpine.
func DefaultDir(override string) (string, error) {
	if override != "" {
		return override, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("could not determine home directory: %w", err)
	}

	twigpineDir := filepath.Join(home, ".twigpine")
	if info, err := os.Stat(twigpineDir); err == nil && info.IsDir() {
		return twigpineDir, nil
	}

	gitlawbDir := filepath.Join(home, ".gitlawb")
	if info, err := os.Stat(gitlawbDir); err == nil && info.IsDir() {
		return gitlawbDir, nil
	}

	return twigpineDir, nil
}

// KeyPath returns the full path to identity.pem in the given directory.
func KeyPath(dir string) string {
	return filepath.Join(dir, "identity.pem")
}

// LoadKeypair loads the identity Keypair from the specified or default directory.
func LoadKeypair(dirOverride string) (*Keypair, error) {
	dir, err := DefaultDir(dirOverride)
	if err != nil {
		return nil, err
	}

	path := KeyPath(dir)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("no identity found at %s\nRun `twig identity new` to create one", path)
	}

	return FromPEM(data)
}

// SaveKeypair writes the identity Keypair to identity.pem in the specified directory.
func SaveKeypair(dir string, keypair *Keypair) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	pemBytes, err := keypair.ToPEM()
	if err != nil {
		return err
	}

	path := KeyPath(dir)
	// Write with restricted permissions (0600)
	if err := os.WriteFile(path, pemBytes, 0600); err != nil {
		return fmt.Errorf("failed to write key file: %w", err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		return fmt.Errorf("failed to enforce key file permissions: %w", err)
	}
	return nil
}
