package main

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"golang.org/x/crypto/ssh"
)

func TestIsSign(t *testing.T) {
	for _, args := range [][]string{
		{"-Y", "sign", "-n", "git", "-f", "key.pub", "payload"},
		{"-n", "git", "-Y", "sign"},
	} {
		if !isSign(args) {
			t.Errorf("isSign(%q) = false", args)
		}
	}
	for _, args := range [][]string{
		{"-Y", "verify", "-n", "git", "-s", "payload.sig"},
		{"-Y", "find-principals", "-f", "allowed", "-s", "payload.sig"},
		{"-l", "-f", "key.pub"},
		{"-Y"},
		{"sign"},
		{},
	} {
		if isSign(args) {
			t.Errorf("isSign(%q) = true", args)
		}
	}
}

func TestParseSignArgs(t *testing.T) {
	want := signRequest{namespace: "git", keyFile: "key.pub", file: "payload"}
	for _, args := range [][]string{
		{"-Y", "sign", "-n", "git", "-f", "key.pub", "payload"},
		{"-Y", "sign", "-n", "git", "-f", "key.pub", "-U", "payload"}, // git's form for inline keys
		{"-f", "key.pub", "-U", "-n", "git", "-Y", "sign", "payload"},
	} {
		got, err := parseSignArgs(args)
		if err != nil || got != want {
			t.Errorf("parseSignArgs(%q) = %+v, %v; want %+v", args, got, err, want)
		}
	}
}

func TestParseSignArgsRefuses(t *testing.T) {
	for _, tt := range []struct {
		args []string
		want string
	}{
		{[]string{"-Y", "sign", "-n", "git", "-f", "key.pub", "-O", "hashalg=sha256", "payload"}, `unexpected argument "-O"`},
		{[]string{"-Y", "sign", "-n", "git", "-f", "key.pub", "a", "b"}, `unexpected argument "b"`},
		{[]string{"-Y", "sign", "-f", "key.pub", "payload"}, "missing -n <namespace>"},
		{[]string{"-Y", "sign", "-n", "git", "payload"}, "missing -f <keyfile>"},
		{[]string{"-Y", "sign", "-n", "git", "-f", "key.pub"}, "missing the file to sign"},
		{[]string{"-Y", "sign", "-n", "git", "-f"}, "-f needs a value"},
		{[]string{"-Y", "sign", "-n", "git", "-n", "file", "-f", "key.pub", "payload"}, "-n given more than once"},
	} {
		_, err := parseSignArgs(tt.args)
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("parseSignArgs(%q): got error %v, want one containing %q", tt.args, err, tt.want)
			continue
		}
		// git adds a hint that OpenSSH is too old when a failed signer's
		// stderr says "usage:".
		if strings.Contains(err.Error(), "usage:") {
			t.Errorf("parseSignArgs(%q): error %q says usage:", tt.args, err)
		}
	}
}

func TestReadPublicKey(t *testing.T) {
	key := newSSHKey(t, "ed25519")
	line, err := os.ReadFile(key + ".pub") // as ssh-keygen writes it: "ssh-ed25519 AAAA… test\n"
	if err != nil {
		t.Fatal(err)
	}
	want, _, _, _, err := ssh.ParseAuthorizedKey(line)
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(line))
	bare := fields[0] + " " + fields[1]
	for name, content := range map[string]string{
		"as ssh-keygen writes it":                          string(line),
		"no comment or newline, as git writes inline keys": bare,
		"CRLF line ending":                                 bare + " comment\r\n",
		"blank line and comment first":                     "\n# signing key\n" + bare + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "key.pub")
			writeFile(t, path, []byte(content))
			got, err := readPublicKey(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got.Marshal(), want.Marshal()) {
				t.Errorf("read %s, want %s", ssh.MarshalAuthorizedKey(got), ssh.MarshalAuthorizedKey(want))
			}
		})
	}
}

func TestReadPublicKeyRefuses(t *testing.T) {
	key := newSSHKey(t, "ed25519")
	rsaKey := newSSHKey(t, "rsa")
	for _, tt := range []struct{ name, path, want string }{
		{"private key", key, "holds no SSH public key (user.signingkey must name the public key)"},
		{"RSA key", rsaKey + ".pub", "key type ssh-rsa is not supported"},
		{"missing file", key + ".missing", "no such file or directory"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := readPublicKey(tt.path)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("got error %v, want one containing %q", err, tt.want)
			}
		})
	}
}

// signFixture isolates git, sets sshsig-kms.key to keyID unless it's "",
// and writes message to a file to sign, whose path it returns.
func signFixture(t *testing.T, keyID string, message []byte) string {
	t.Helper()
	isolateGit(t)
	if keyID != "" {
		runGit(t, ".", "config", "--global", "sshsig-kms.key", keyID)
	}
	file := filepath.Join(t.TempDir(), "payload")
	writeFile(t, file, message)
	return file
}

func TestRunSign(t *testing.T) {
	for _, keyType := range []string{"ed25519", "ecdsa"} {
		t.Run(keyType, func(t *testing.T) {
			key := newSSHKey(t, keyType)
			message := []byte("tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\nsigned\n")
			file := signFixture(t, key, message)

			args := []string{"-Y", "sign", "-n", "git", "-f", key + ".pub", file}
			if err := runSign(args, connectLocal, time.Minute); err != nil {
				t.Fatal(err)
			}

			sig, err := os.ReadFile(file + ".sig")
			if err != nil {
				t.Fatal(err)
			}
			pub, err := readPublicKey(key + ".pub")
			if err != nil {
				t.Fatal(err)
			}
			sshKeygenVerify(t, pub, "git", message, sig)
		})
	}
}

func TestRunSignUsesProfile(t *testing.T) {
	key := newSSHKey(t, "ed25519")
	file := signFixture(t, key, []byte("payload\n"))
	runGit(t, ".", "config", "--global", "sshsig-kms.profile", "signing")
	var profile string
	connect := func(ctx context.Context, keyID, p string) (kmsAPI, error) {
		profile = p
		return connectLocal(ctx, keyID, p)
	}
	if err := runSign([]string{"-Y", "sign", "-n", "git", "-f", key + ".pub", file}, connect, time.Minute); err != nil {
		t.Fatal(err)
	}
	if profile != "signing" {
		t.Errorf("connected with profile %q, want %q", profile, "signing")
	}
}

func TestRunSignFails(t *testing.T) {
	key := newSSHKey(t, "ed25519")
	other := newSSHKey(t, "ed25519")
	rsaKey := newSSHKey(t, "rsa")
	for _, tt := range []struct {
		name    string
		keyID   string // sshsig-kms.key, or "" to leave it unset
		keyFile string // -f
		want    string // in the error
	}{
		{"key in git config is another key", other, key + ".pub", "KMS key " + other + " did not produce a signature for the key in user.signingkey"},
		{"no key in git config", "", key + ".pub", "no KMS key configured: set sshsig-kms.key in git config"},
		{"unsupported key type", key, rsaKey + ".pub", "key type ssh-rsa is not supported"},
		{"key file holds a private key", key, key, "holds no SSH public key"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			file := signFixture(t, tt.keyID, []byte("payload\n"))
			args := []string{"-Y", "sign", "-n", "git", "-f", tt.keyFile, file}
			err := runSign(args, connectLocal, time.Minute)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("got error %v, want one containing %q", err, tt.want)
			}
			if _, err := os.Stat(file + ".sig"); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("%s.sig exists after a failed signing", file)
			}
		})
	}
}

// hangingKMS never answers, like KMS behind a broken network: Sign returns
// only when its context ends.
type hangingKMS struct{ kmsAPI }

func (hangingKMS) Sign(ctx context.Context, _ *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestRunSignTimeLimit(t *testing.T) {
	key := newSSHKey(t, "ed25519")
	file := signFixture(t, key, []byte("payload\n"))
	connect := func(context.Context, string, string) (kmsAPI, error) { return hangingKMS{}, nil }

	start := time.Now()
	err := runSign([]string{"-Y", "sign", "-n", "git", "-f", key + ".pub", file}, connect, 100*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "no signature within 100ms") {
		t.Fatalf("got error %v, want one saying time ran out", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("took %v to give up", elapsed)
	}
	if _, err := os.Stat(file + ".sig"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("%s.sig exists after a failed signing", file)
	}
}
