package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
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

// isolateGit gives git an empty global config of its own and no system
// config, so the developer's git config can't affect the test, and moves
// the test to an empty directory outside any repository. It returns the
// global config file's path.
func isolateGit(t *testing.T) string {
	t.Helper()
	global := filepath.Join(t.TempDir(), "gitconfig")
	writeFile(t, global, nil)
	t.Setenv("GIT_CONFIG_GLOBAL", global)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Chdir(t.TempDir())
	return global
}

// tryGit runs git in dir and returns its combined output.
func tryGit(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// runGit runs git in dir and returns its combined output, failing the test
// if git fails.
func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := tryGit(dir, args...)
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

// sourceDir is the package's source directory: the working directory go
// test starts in, before any test moves elsewhere.
var sourceDir, _ = os.Getwd()

var testBin struct {
	once sync.Once
	dir  string
	err  error
}

// testBinary builds sshsig-kms with the fakekms tag, once per test run, and
// returns the binary's path.
func testBinary(t *testing.T) string {
	t.Helper()
	testBin.once.Do(func() {
		testBin.dir, testBin.err = os.MkdirTemp("", "sshsig-kms-test")
		if testBin.err != nil {
			return
		}
		cmd := exec.Command("go", "build", "-tags", "fakekms", "-buildvcs=false",
			"-o", filepath.Join(testBin.dir, "sshsig-kms"), ".")
		cmd.Dir = sourceDir
		if out, err := cmd.CombinedOutput(); err != nil {
			testBin.err = fmt.Errorf("go build: %v\n%s", err, out)
		}
	})
	if testBin.err != nil {
		t.Fatal(testBin.err)
	}
	return filepath.Join(testBin.dir, "sshsig-kms")
}

func TestMain(m *testing.M) {
	code := m.Run()
	if testBin.dir != "" {
		os.RemoveAll(testBin.dir)
	}
	os.Exit(code)
}
