package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
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
