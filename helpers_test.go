package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
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

// testKMS returns a localKMS signing with the private key at keyPath, and
// that key's public half.
func testKMS(t *testing.T, keyPath string) (localKMS, ssh.PublicKey) {
	t.Helper()
	l, err := loadLocalKMS(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(l.key.Public())
	if err != nil {
		t.Fatal(err)
	}
	return l, pub
}

// sshKeygenVerify checks with ssh-keygen -Y verify that sig, an armored
// signature, is pub's signature of message in namespace.
func sshKeygenVerify(t *testing.T, pub ssh.PublicKey, namespace string, message, sig []byte) {
	t.Helper()
	dir := t.TempDir()
	allowed := filepath.Join(dir, "allowed_signers")
	sigFile := filepath.Join(dir, "message.sig")
	writeFile(t, allowed, fmt.Appendf(nil, "test namespaces=%q %s", namespace, ssh.MarshalAuthorizedKey(pub)))
	writeFile(t, sigFile, sig)
	cmd := exec.Command("ssh-keygen", "-Y", "verify", "-f", allowed, "-I", "test", "-n", namespace, "-s", sigFile)
	cmd.Stdin = bytes.NewReader(message)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen -Y verify: %v\n%s", err, out)
	}
}
