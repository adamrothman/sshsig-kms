package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// newSSHKey generates an unencrypted key pair with ssh-keygen and returns
// the private key's path; the public key is at that path plus ".pub".
// keyType is an ssh-keygen -t type: "ed25519", "ecdsa" (P-256) or "rsa".
func newSSHKey(t *testing.T, keyType string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "id_"+keyType)
	args := []string{"-q", "-t", keyType, "-N", "", "-C", "test", "-f", path}
	if keyType == "ecdsa" {
		args = append(args, "-b", "256")
	}
	if out, err := exec.Command("ssh-keygen", args...).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v\n%s", err, out)
	}
	return path
}

// writeFile writes data to path, failing the test if it can't.
func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
