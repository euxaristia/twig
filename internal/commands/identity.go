package commands

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Twigpine/twig/internal/did"
	"github.com/Twigpine/twig/internal/identity"
)

// confirmOverwrite prompts before replacing an existing identity key.
// Confirmation is required even when force is set: replacing a key can
// permanently lose access to the original DID. An empty or negative answer
// aborts the operation. Returns true when the caller may proceed.
func confirmOverwrite(in io.Reader, keyPath string, force bool, verb string) bool {
	if force {
		fmt.Printf("warning: --force specified. Overwriting existing identity at %s.\nThis will permanently destroy your current DID. Continue? [y/N] ", keyPath)
	} else {
		fmt.Printf("identity already exists at %s.\n%s will permanently replace your current DID. Continue? [y/N] ", keyPath, verb)
	}
	reader := bufio.NewReader(in)
	ans, _ := reader.ReadString('\n')
	ans = strings.TrimSpace(strings.ToLower(ans))
	if ans != "y" && ans != "yes" {
		fmt.Println("Aborted.")
		return false
	}
	return true
}

// IdentityNew generates a new Ed25519 identity key and saves it to identity.pem.
func IdentityNew(dirOverride string, force bool, in io.Reader) error {
	dir, err := identity.DefaultDir(dirOverride)
	if err != nil {
		return err
	}

	keyPath := identity.KeyPath(dir)
	if _, err := os.Stat(keyPath); err == nil {
		if !confirmOverwrite(in, keyPath, force, "This") {
			return nil
		}
	}

	kp, err := identity.GenerateKeypair()
	if err != nil {
		return fmt.Errorf("generating keypair: %w", err)
	}

	if err := identity.SaveKeypair(dir, kp); err != nil {
		return fmt.Errorf("saving keypair: %w", err)
	}

	d := kp.DID()
	fmt.Println("✓ Generated new identity")
	fmt.Printf("  DID:  %s\n", d)
	fmt.Printf("  Key:  %s\n\n", keyPath)
	fmt.Println("  Your DID is your identity on the Twigpine network.")
	fmt.Println("  Keep your key file safe — it cannot be recovered if lost.")
	return nil
}

// IdentityShow prints the current DID to stdout.
func IdentityShow(dirOverride string) error {
	kp, err := identity.LoadKeypair(dirOverride)
	if err != nil {
		return err
	}
	fmt.Println(kp.DID())
	return nil
}

// IdentityExport exports the W3C DID Document as pretty JSON.
func IdentityExport(dirOverride string) error {
	kp, err := identity.LoadKeypair(dirOverride)
	if err != nil {
		return err
	}

	doc := did.NewDIDDocument(kp.DID())
	return PrintJSON(doc)
}

// IdentitySign signs a message string and outputs the base64url signature.
func IdentitySign(dirOverride, message string) error {
	kp, err := identity.LoadKeypair(dirOverride)
	if err != nil {
		return err
	}

	sig := kp.SignB64([]byte(message))
	fmt.Println(sig)
	return nil
}

// IdentityBackup copies identity.pem to the target destination.
func IdentityBackup(dirOverride, outDest string) error {
	dir, err := identity.DefaultDir(dirOverride)
	if err != nil {
		return err
	}

	src := identity.KeyPath(dir)
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("no identity found at %s — run `twig identity new` first", src)
	}

	// Validate PEM
	if _, err := identity.FromPEM(data); err != nil {
		return fmt.Errorf("identity.pem is corrupted: %w", err)
	}

	if outDest == "" {
		outDest = "identity.pem.bak"
	}

	if err := os.WriteFile(outDest, data, 0600); err != nil {
		return fmt.Errorf("writing backup file: %w", err)
	}

	abs, _ := filepath.Abs(outDest)
	fmt.Printf("✓ Identity backed up to %s\n", abs)
	return nil
}

// IdentityRestore restores identity.pem from a backup file.
func IdentityRestore(dirOverride, srcPath string, force bool, in io.Reader) error {
	if srcPath == "" {
		return errors.New("must specify backup source path")
	}

	data, err := os.ReadFile(srcPath)
	if err != nil {
		return fmt.Errorf("reading backup: %w", err)
	}

	kp, err := identity.FromPEM(data)
	if err != nil {
		return fmt.Errorf("invalid backup PEM file: %w", err)
	}

	dir, err := identity.DefaultDir(dirOverride)
	if err != nil {
		return err
	}

	dest := identity.KeyPath(dir)
	if _, err := os.Stat(dest); err == nil {
		if !confirmOverwrite(in, dest, force, "Restoring") {
			return nil
		}
	}

	if err := identity.SaveKeypair(dir, kp); err != nil {
		return fmt.Errorf("saving restored key: %w", err)
	}

	fmt.Printf("✓ Identity restored from %s\n", srcPath)
	fmt.Printf("  DID: %s\n", kp.DID())
	return nil
}
