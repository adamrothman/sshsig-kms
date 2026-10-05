package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// signingRepo creates a repository whose git config signs with a fakekms
// build of sshsig-kms and the public key at key+".pub", and accepts that
// key's signatures from test@example.com. Each test sets sshsig-kms.key
// itself. It returns the repository's path.
func signingRepo(t *testing.T, key string) string {
	t.Helper()
	global := isolateGit(t)
	pub, err := os.ReadFile(key + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	allowed := filepath.Join(t.TempDir(), "allowed_signers")
	writeFile(t, allowed, append([]byte("test@example.com "), pub...))
	writeFile(t, global, fmt.Appendf(nil, `[user]
	name = Test
	email = test@example.com
	signingkey = "%s"
[gpg]
	format = ssh
[gpg "ssh"]
	program = "%s"
	allowedSignersFile = "%s"
[init]
	defaultBranch = main
`, key+".pub", testBinary(t), allowed))
	repo := t.TempDir()
	runGit(t, repo, "init", "-q")
	return repo
}

// verifyGood runs one of git's verification commands and checks that it
// reports a good signature by test@example.com.
func verifyGood(t *testing.T, repo string, args ...string) {
	t.Helper()
	out := runGit(t, repo, args...)
	if !strings.Contains(out, `Good "git" signature for test@example.com`) {
		t.Errorf("git %s didn't report a good signature:\n%s", strings.Join(args, " "), out)
	}
}

func TestGitSignsAndVerifies(t *testing.T) {
	for _, keyType := range []string{"ed25519", "ecdsa"} {
		t.Run(keyType, func(t *testing.T) {
			key := newSSHKey(t, keyType)
			repo := signingRepo(t, key)
			runGit(t, repo, "config", "sshsig-kms.key", key)

			runGit(t, repo, "commit", "--allow-empty", "-S", "-m", "signed commit")
			verifyGood(t, repo, "verify-commit", "HEAD")
			verifyGood(t, repo, "log", "--show-signature", "-1")

			runGit(t, repo, "tag", "-s", "-m", "signed tag", "v1")
			verifyGood(t, repo, "verify-tag", "v1")
		})
	}
}

// For an inline key (key::…), git writes the key to a temporary file and
// adds -U.
func TestGitInlineKey(t *testing.T) {
	key := newSSHKey(t, "ed25519")
	repo := signingRepo(t, key)
	pub, err := os.ReadFile(key + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	runGit(t, repo, "config", "user.signingkey", "key::"+strings.TrimSpace(string(pub)))
	runGit(t, repo, "config", "sshsig-kms.key", key)
	runGit(t, repo, "commit", "--allow-empty", "-S", "-m", "inline key")
	verifyGood(t, repo, "verify-commit", "HEAD")
}

// sshsig-kms reads its settings with git's scoping: repository config over
// global config, and git -c over both.
func TestGitConfigScopes(t *testing.T) {
	key := newSSHKey(t, "ed25519")
	other := newSSHKey(t, "ed25519")
	repo := signingRepo(t, key)

	runGit(t, repo, "config", "--global", "sshsig-kms.key", other)
	runGit(t, repo, "config", "sshsig-kms.key", key)
	runGit(t, repo, "commit", "--allow-empty", "-S", "-m", "repository config")
	verifyGood(t, repo, "verify-commit", "HEAD")

	runGit(t, repo, "config", "sshsig-kms.key", other)
	runGit(t, repo, "-c", "sshsig-kms.key="+key, "commit", "--allow-empty", "-S", "-m", "git -c")
	verifyGood(t, repo, "verify-commit", "HEAD")
}

func TestGitSigningFails(t *testing.T) {
	key := newSSHKey(t, "ed25519")
	other := newSSHKey(t, "ed25519")
	for _, tt := range []struct {
		name  string
		keyID string // sshsig-kms.key, or "" to leave it unset
		want  string
	}{
		{"another key in git config", other, "sshsig-kms: KMS key " + other + " did not produce a signature for the key in user.signingkey"},
		{"no key in git config", "", "sshsig-kms: no KMS key configured: set sshsig-kms.key in git config"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			repo := signingRepo(t, key)
			if tt.keyID != "" {
				runGit(t, repo, "config", "sshsig-kms.key", tt.keyID)
			}
			out, err := tryGit(repo, "commit", "--allow-empty", "-S", "-m", "unsigned")
			if err == nil {
				t.Fatal("commit succeeded")
			}
			if !strings.Contains(out, tt.want) {
				t.Errorf("git's output doesn't contain %q:\n%s", tt.want, out)
			}
			// git blames an old OpenSSH when a failed signer's stderr says
			// "usage:".
			if strings.Contains(out, "openssh version") {
				t.Errorf("git hinted that OpenSSH is too old:\n%s", out)
			}
			if _, err := tryGit(repo, "rev-parse", "--verify", "-q", "HEAD"); err == nil {
				t.Error("a commit was made")
			}
		})
	}
}

func TestBinaryPublicKey(t *testing.T) {
	isolateGit(t)
	key := newSSHKey(t, "ed25519")
	out, err := exec.Command(testBinary(t), "public-key", key).Output()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := os.ReadFile(key + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	if want := strings.Join(strings.Fields(string(pub))[:2], " ") + "\n"; string(out) != want {
		t.Errorf("printed %q, want %q", out, want)
	}
}
