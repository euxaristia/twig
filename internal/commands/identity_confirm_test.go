package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Twigpine/twig/internal/identity"
)

func testIdentityDID(t *testing.T, dir string) string {
	t.Helper()
	kp, err := identity.LoadKeypair(dir)
	if err != nil {
		t.Fatalf("LoadKeypair failed: %v", err)
	}
	return kp.DID()
}

func testIdentityKeyBytes(t *testing.T, dir string) []byte {
	t.Helper()
	b, err := os.ReadFile(identity.KeyPath(dir))
	if err != nil {
		t.Fatalf("reading key file failed: %v", err)
	}
	return b
}

func newIdentityIn(t *testing.T, dir string) {
	t.Helper()
	if err := IdentityNew(dir, false, strings.NewReader("")); err != nil {
		t.Fatalf("IdentityNew failed: %v", err)
	}
}

// TestIdentityNewForceStillConfirms verifies that --force does not skip the
// replacement confirmation: declining or EOF keeps the original key and DID.
func TestIdentityNewForceStillConfirms(t *testing.T) {
	dir := t.TempDir()
	newIdentityIn(t, dir)
	origDID := testIdentityDID(t, dir)
	origKey := testIdentityKeyBytes(t, dir)

	for name, input := range map[string]string{
		"decline": "n\n",
		"eof":     "",
	} {
		t.Run(name, func(t *testing.T) {
			if err := IdentityNew(dir, true, strings.NewReader(input)); err != nil {
				t.Fatalf("IdentityNew failed: %v", err)
			}
			if got := testIdentityDID(t, dir); got != origDID {
				t.Fatalf("DID changed after %s: %s != %s", name, got, origDID)
			}
			if got := string(testIdentityKeyBytes(t, dir)); got != string(origKey) {
				t.Fatalf("key file changed after %s", name)
			}
		})
	}
}

// TestIdentityNewConfirmReplaces verifies an affirmative answer replaces the key.
func TestIdentityNewConfirmReplaces(t *testing.T) {
	dir := t.TempDir()
	newIdentityIn(t, dir)
	origDID := testIdentityDID(t, dir)

	if err := IdentityNew(dir, true, strings.NewReader("y\n")); err != nil {
		t.Fatalf("IdentityNew failed: %v", err)
	}
	if got := testIdentityDID(t, dir); got == origDID {
		t.Fatalf("DID unchanged after confirming replacement")
	}
}

// TestIdentityRestoreForceStillConfirms verifies restore honors confirmation
// even with --force.
func TestIdentityRestoreForceStillConfirms(t *testing.T) {
	dir := t.TempDir()
	newIdentityIn(t, dir)
	origDID := testIdentityDID(t, dir)

	// Build a backup file holding a different key.
	other, err := identity.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}
	pem, err := other.ToPEM()
	if err != nil {
		t.Fatalf("ToPEM failed: %v", err)
	}
	backup := filepath.Join(t.TempDir(), "backup.pem")
	if err := os.WriteFile(backup, pem, 0600); err != nil {
		t.Fatalf("writing backup failed: %v", err)
	}

	for name, input := range map[string]string{
		"decline": "n\n",
		"eof":     "",
	} {
		t.Run(name, func(t *testing.T) {
			if err := IdentityRestore(dir, backup, true, strings.NewReader(input)); err != nil {
				t.Fatalf("IdentityRestore failed: %v", err)
			}
			if got := testIdentityDID(t, dir); got != origDID {
				t.Fatalf("DID changed after %s: %s != %s", name, got, origDID)
			}
		})
	}

	t.Run("confirm", func(t *testing.T) {
		if err := IdentityRestore(dir, backup, true, strings.NewReader("yes\n")); err != nil {
			t.Fatalf("IdentityRestore failed: %v", err)
		}
		if got := testIdentityDID(t, dir); got != other.DID() {
			t.Fatalf("DID not restored: %s != %s", got, other.DID())
		}
	})
}
