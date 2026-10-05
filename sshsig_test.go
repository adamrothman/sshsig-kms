package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestSignedDataLength(t *testing.T) {
	// The design counts on 95 bytes for the namespace "git", far under
	// KMS's 4,096-byte limit for raw messages.
	digest := sha512.Sum512([]byte("message"))
	if n := len(signedData("git", digest[:])); n != 95 {
		t.Errorf("signed data is %d bytes, want 95", n)
	}
}

// Ed25519 signatures are deterministic, so a signature by the same key over
// the same message must match ssh-keygen's byte for byte.
func TestArmorMatchesSSHKeygen(t *testing.T) {
	keyPath := newSSHKey(t, "ed25519")
	pemBytes, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\ncommit message\n")
	digest := sha512.Sum512(message)

	// With the namespace "git" the base64 is 232 characters. A 40-character
	// namespace makes it exactly 280, four full lines; 41 spills onto a fifth.
	for _, tt := range []struct{ name, namespace string }{
		{"git", "git"},
		{"file", "file"},
		{"ends on a full line", strings.Repeat("n", 40)},
		{"one past a full line", strings.Repeat("n", 41)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			msgPath := filepath.Join(t.TempDir(), "message")
			writeFile(t, msgPath, message)
			cmd := exec.Command("ssh-keygen", "-Y", "sign", "-n", tt.namespace, "-f", keyPath, msgPath)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("ssh-keygen -Y sign: %v\n%s", err, out)
			}
			want, err := os.ReadFile(msgPath + ".sig")
			if err != nil {
				t.Fatal(err)
			}

			sig, err := signer.Sign(rand.Reader, signedData(tt.namespace, digest[:]))
			if err != nil {
				t.Fatal(err)
			}
			if got := armor(signer.PublicKey(), tt.namespace, sig); !bytes.Equal(got, want) {
				t.Errorf("armor differs from ssh-keygen\ngot:\n%s\nwant:\n%s", got, want)
			}
		})
	}
}
