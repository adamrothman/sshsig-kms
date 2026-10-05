package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestVersion(t *testing.T) {
	old := version
	version = "1.2.3"
	t.Cleanup(func() { version = old })

	var out bytes.Buffer
	if err := run([]string{"version"}, &out); err != nil {
		t.Fatal(err)
	}
	if out.String() != "1.2.3\n" {
		t.Errorf("printed %q, want %q", out.String(), "1.2.3\n")
	}
	if err := run([]string{"version", "extra"}, &out); err == nil {
		t.Error("version with an argument succeeded")
	}
}

func TestErrorLine(t *testing.T) {
	err := errors.New("operation error KMS: Sign,\n\thttps response error StatusCode: 400,\n\tapi error AccessDeniedException: denied\n")
	want := "sshsig-kms: operation error KMS: Sign, https response error StatusCode: 400, api error AccessDeniedException: denied"
	if got := errorLine(err); got != want {
		t.Errorf("errorLine = %q, want %q", got, want)
	}
}

// fakeSSHKeygen stands in for ssh-keygen: it prints its arguments and its
// standard input, then exits with status 3.
const fakeSSHKeygen = `#!/bin/sh
echo "args: $*"
cat
exit 3
`

func TestPassThrough(t *testing.T) {
	bin := testBinary(t)
	dir := t.TempDir()
	script := filepath.Join(dir, "ssh-keygen")
	writeFile(t, script, []byte(fakeSSHKeygen))
	if err := os.Chmod(script, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	cmd := exec.Command(bin, "-Y", "verify", "-n", "git", "-s", "commit.sig")
	cmd.Stdin = strings.NewReader("payload\n")
	out, err := cmd.Output()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 3 {
		t.Fatalf("got %v, want exit status 3", err)
	}
	if want := "args: -Y verify -n git -s commit.sig\npayload\n"; string(out) != want {
		t.Errorf("stdout = %q, want %q", out, want)
	}
}

func TestPassThroughRefusesItself(t *testing.T) {
	bin := testBinary(t)
	dir := t.TempDir()
	if err := os.Symlink(bin, filepath.Join(dir, "ssh-keygen")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	out, err := exec.Command(bin, "-l", "-f", "key.pub").CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
		t.Fatalf("got %v, want exit status 1\n%s", err, out)
	}
	if !strings.HasPrefix(string(out), "sshsig-kms: ") || !strings.Contains(string(out), "is sshsig-kms itself") {
		t.Errorf("output %q doesn't say that ssh-keygen is sshsig-kms", out)
	}
}

func TestRunDispatchesSign(t *testing.T) {
	// Without -f, the call fails while parsing, before it could reach AWS.
	err := run([]string{"-Y", "sign", "-n", "git", "payload"}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "missing -f <keyfile>") {
		t.Errorf("got error %v", err)
	}
}

func TestRunPublicKey(t *testing.T) {
	isolateGit(t)
	for _, keyType := range []string{"ed25519", "ecdsa"} {
		t.Run(keyType, func(t *testing.T) {
			key := newSSHKey(t, keyType)
			var out bytes.Buffer
			if err := runPublicKey(key, connectLocal, time.Minute, &out); err != nil {
				t.Fatal(err)
			}
			pub, err := os.ReadFile(key + ".pub") // "<type> <base64> test\n"
			if err != nil {
				t.Fatal(err)
			}
			if want := strings.Join(strings.Fields(string(pub))[:2], " ") + "\n"; out.String() != want {
				t.Errorf("printed %q, want %q", out.String(), want)
			}
		})
	}
}

func TestRunPublicKeyUsesProfile(t *testing.T) {
	isolateGit(t)
	runGit(t, ".", "config", "--global", "sshsig-kms.profile", "signing")
	var profile string
	connect := func(ctx context.Context, keyID, p string) (kmsAPI, error) {
		profile = p
		return connectLocal(ctx, keyID, p)
	}
	if err := runPublicKey(newSSHKey(t, "ed25519"), connect, time.Minute, io.Discard); err != nil {
		t.Fatal(err)
	}
	if profile != "signing" {
		t.Errorf("connected with profile %q, want %q", profile, "signing")
	}
}

func TestRunPublicKeyArguments(t *testing.T) {
	for _, args := range [][]string{{"public-key"}, {"public-key", "a", "b"}} {
		err := run(args, io.Discard)
		if err == nil || !strings.Contains(err.Error(), "public-key takes one argument") {
			t.Errorf("run(%q): got error %v", args, err)
		}
	}
}
