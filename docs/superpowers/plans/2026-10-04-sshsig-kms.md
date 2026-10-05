# sshsig-kms Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `sshsig-kms`, the `gpg.ssh.program` that signs git commits and tags with an SSH key held in AWS KMS, with its tests, CI, release workflow and README.

**Architecture:** One Go `main` package at the repository root. `run` dispatches: a `-Y sign` call is signed here (parse the arguments, read the public key, read git config, hash the file, call KMS `Sign`, convert the answer to an SSH signature, verify it, armor it, write `<file>.sig`); `public-key` and `version` are commands of its own; anything else replaces the process with `ssh-keygen`. KMS sits behind a two-method `kmsAPI` interface, so tests feed it local keys and malformed answers, and a `fakekms` build tag swaps the real client for a local key so the end-to-end test can run real git against the real binary.

**Tech Stack:** Go 1.27.1; AWS SDK for Go v2 (`config`, `service/kms`, and `aws`, `aws/arn` from the core module); `golang.org/x/crypto/ssh`; OpenSSH's `ssh-keygen` and git as test oracles; GitHub Actions.

**Spec:** `docs/design.md`. Read it before starting any task.

## Global Constraints

- Go module `github.com/adamrothman/sshsig-kms`, `go 1.27.1` in `go.mod`. CI and releases take Go's version from `go.mod` (`go-version-file: go.mod`).
- Direct dependencies: the AWS SDK for Go v2 (`config`, `service/kms`, `aws`, `aws/arn`) and `golang.org/x/crypto/ssh`. No others, not even in tests.
- git's call: `sshsig-kms -Y sign -n <namespace> -f <keyfile> [-U] <file>`. `-U` is accepted and ignored. Any other argument to `-Y sign` fails, naming it.
- Every call that isn't `-Y sign` replaces the process (`execve`) with the `ssh-keygen` found on `PATH`, arguments unchanged. If that `ssh-keygen` is `sshsig-kms` itself, fail instead of looping.
- Supported keys, and nothing else: `ssh-ed25519` ↔ `ECC_NIST_EDWARDS25519` signed with `ED25519_SHA_512`; `ecdsa-sha2-nistp256` ↔ `ECC_NIST_P256` signed with `ECDSA_SHA_256`. Always `MessageType: RAW`.
- Signed data: `"SSHSIG" ‖ string(namespace) ‖ string("") ‖ string("sha512") ‖ string(SHA-512(file))`. Blob: `"SSHSIG" ‖ uint32(1) ‖ string(public key) ‖ string(namespace) ‖ string("") ‖ string("sha512") ‖ string(signature)`, base64 wrapped at 70 columns between `-----BEGIN SSH SIGNATURE-----` and `-----END SSH SIGNATURE-----`.
- Fail closed: verify every signature against the public key in `<keyfile>` before writing it. Write nothing but `<file>.sig`; print nothing to stdout when signing.
- Settings: `sshsig-kms.key` (required: a key ARN or alias ARN, which also gives the region) and `sshsig-kms.profile` (optional), read with `git config --get`.
- Time limit: 8 seconds for the whole signing.
- Errors: exit status 1 and one line on stderr beginning `sshsig-kms: `. No message contains `usage:`.
- Never print, cache or store credentials. Talk to nothing but AWS.
- The local-key stand-in for KMS is reachable only in builds with the `fakekms` tag. The real-KMS test is behind the `integration` tag.
- Every test that runs git sets `GIT_CONFIG_GLOBAL` to a file of its own and `GIT_CONFIG_NOSYSTEM=1` (the `isolateGit` helper, Task 3).
- Platforms: Linux and macOS, amd64 and arm64. CI runners: `ubuntu-latest` (amd64), `ubuntu-24.04-arm` (arm64), `macos-latest`.
- Release files are named `sshsig-kms_<version>_<os>_<arch>`, alongside `SHA256SUMS`, where `<version>` is the tag minus its leading `v` (`v0.1.0` → `0.1.0`); `sshsig-kms version` prints the same. Never push a `v*` tag: v0.1.0 waits for Adam's go-ahead.
- Work on branch `implement`. Adam's git config signs every commit (1Password's `op-ssh-sign`, which may ask him to approve each one). Keep history linear. End every commit message with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Code is `gofmt`-clean and `go vet`-clean under the default, `fakekms` and `integration` tags.
- Tests need `git` and `ssh-keygen` (OpenSSH 8.2p1 or later) on `PATH`.

## Decisions beyond the design

Where the design leaves room, this plan decides:

1. `ssh-keygen` is exec'd with `argv[0]` set to `ssh-keygen`. Every argument after it is passed unchanged.
2. `-Y sign`'s flags may come in any order, as ssh-keygen's getopt allows, but the set is strict: `-Y sign`, `-n` and `-f` once each, optionally `-U`, and exactly one file.
3. The key file's first key line counts: `ssh.ParseAuthorizedKey` skips blank lines and `#` comments and tolerates CRLF.
4. `public-key` honours `sshsig-kms.profile` too (Adam, 2026-10-04), and has the same 8-second limit.
5. `version` falls back to the module version `go install` records when the build didn't stamp one.
6. `localKMS` lives in an untagged file because unit tests use it. Only `fakekms.go` wires it into `newKMS`, so a release binary can't reach it (and the linker drops it).
7. Running out of time reads `sshsig-kms: no signature within 8s: …`.

## Review Focus

Inputs the design implies but doesn't spell out, most likely to bite first. Each has a test in the task named:

1. **An inline signing key** (`user.signingkey = key::ssh-ed25519 …`): git writes it to a temporary file with no trailing newline and adds `-U`. Signing must work. → Task 7, `TestGitInlineKey`.
2. **Settings from anywhere git reads them**: repository config overrides global config, and `git -c` overrides both, because git passes `-c` values to the programs it runs. → Task 7, `TestGitConfigScopes`.
3. **Key files as people write them**: with or without a comment, with CRLF, with no trailing newline, with a blank line or `#` comment first. All must parse. A private key or an RSA key fails with one line saying what to fix. → Task 5, `TestReadPublicKey` and `TestReadPublicKeyRefuses`.
4. **AWS errors over several lines**: they must still reach the user as one stderr line with the prefix. → Task 4, `TestErrorLine`.
5. **`ssh-keygen` on `PATH` being `sshsig-kms` itself** (say, someone symlinks it as `ssh-keygen`): fail with a clear message rather than exec'ing itself forever. → Task 4, `TestPassThroughRefusesItself`.

## File map

| File | Responsibility | Task |
|---|---|---|
| `go.mod`, `go.sum` | module and dependencies | 1, then each task's `go mod tidy` |
| `LICENSE`, `.gitignore` | MIT licence; ignore local build outputs | 1 |
| `sshsig.go` | SSHSIG encoding: the signed data and the armored signature | 1 |
| `kms.go` | `kmsAPI`, `connectFunc`, the key-type table, `kmsSign`, `kmsPublicKey` | 2, 6 |
| `localkms.go` | `localKMS`: a local private key answering as KMS does | 2, 6 |
| `config.go` | `gitConfig`, `keyRegion` | 3 |
| `aws.go` | `newKMS` for real KMS (`!fakekms`) | 3 |
| `fakekms.go` | `newKMS` signing with a local key file (`fakekms`) | 3 |
| `main.go` | `main`, `run` dispatch, `version`, `public-key`, `errorLine`, `timeLimit` | 4, 5, 6 |
| `passthrough.go` | `execSSHKeygen` | 4 |
| `sign.go` | `-Y sign`: `isSign`, `parseSignArgs`, `readPublicKey`, `hashFile`, `runSign` | 5 |
| `helpers_test.go` | shared test helpers and `TestMain` | 1, 2, 3, 4 |
| `sshsig_test.go`, `kms_test.go`, `config_test.go`, `aws_test.go`, `main_test.go`, `sign_test.go` | unit tests | 1–6 |
| `e2e_test.go` | git end to end against a `fakekms` binary | 7 |
| `integration_test.go` | real KMS (`integration`) | 8 |
| `.github/workflows/ci.yml`, `.github/dependabot.yml` | CI, dependency updates | 9 |
| `.github/workflows/release.yml` | release on `v*` tags | 10 |
| `README.md` | user documentation | 11 |

---

### Task 1: Module and SSHSIG encoding

**Files:**
- Create: `go.mod`, `go.sum`, `LICENSE`, `.gitignore`, `sshsig.go`
- Test: `sshsig_test.go`, `helpers_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `func signedData(namespace string, digest []byte) []byte`: the bytes a signature covers; `digest` is the file's SHA-512.
  - `func armor(pub ssh.PublicKey, namespace string, sig *ssh.Signature) []byte`: the complete `<file>.sig` contents.
  - Test helpers: `func newSSHKey(t *testing.T, keyType string) string` (returns the private key path; public key at path + `.pub`; `keyType` is `"ed25519"`, `"ecdsa"` (P-256) or `"rsa"`) and `func writeFile(t *testing.T, path string, data []byte)`.

- [ ] **Step 1: Create the module, licence and .gitignore**

```bash
go mod init github.com/adamrothman/sshsig-kms
go get golang.org/x/crypto/ssh@latest
grep '^go ' go.mod   # expect: go 1.27.1
```

`LICENSE`:

```
MIT License

Copyright (c) 2026 Adam Rothman

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

`.gitignore`:

```
/sshsig-kms
/dist/
```

- [ ] **Step 2: Write the test helpers**

`helpers_test.go`:

```go
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
```

- [ ] **Step 3: Write the failing tests**

`sshsig_test.go`:

```go
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
```

- [ ] **Step 4: Run the tests to see them fail**

Run: `go test ./...`
Expected: FAIL to build, with `undefined: signedData` and `undefined: armor`.

- [ ] **Step 5: Write the encoding**

`sshsig.go`:

```go
package main

import (
	"bytes"
	"encoding/base64"

	"golang.org/x/crypto/ssh"
)

// The SSH signature format, as ssh-keygen -Y sign writes it:
// https://github.com/openssh/openssh-portable/blob/V_10_0_P1/PROTOCOL.sshsig
const (
	sigMagic   = "SSHSIG"
	sigVersion = 1
	sigHashAlg = "sha512" // ssh-keygen's default
)

// signedData returns the bytes an SSH signature covers: the magic preamble,
// then the namespace, the reserved field, the hash algorithm and the
// message's hash.
func signedData(namespace string, digest []byte) []byte {
	return append([]byte(sigMagic), ssh.Marshal(struct {
		Namespace, Reserved, HashAlg string
		Hash                         []byte
	}{namespace, "", sigHashAlg, digest})...)
}

// armor encodes sig, made by pub over signedData(namespace, …), as the
// armored signature ssh-keygen writes to <file>.sig.
func armor(pub ssh.PublicKey, namespace string, sig *ssh.Signature) []byte {
	blob := append([]byte(sigMagic), ssh.Marshal(struct {
		Version                      uint32
		PublicKey                    []byte
		Namespace, Reserved, HashAlg string
		Signature                    []byte
	}{sigVersion, pub.Marshal(), namespace, "", sigHashAlg, ssh.Marshal(sig)})...)

	b64 := base64.StdEncoding.EncodeToString(blob)
	var out bytes.Buffer
	out.WriteString("-----BEGIN SSH SIGNATURE-----\n")
	for len(b64) > 70 {
		out.WriteString(b64[:70] + "\n")
		b64 = b64[70:]
	}
	out.WriteString(b64 + "\n")
	out.WriteString("-----END SSH SIGNATURE-----\n")
	return out.Bytes()
}
```

- [ ] **Step 6: Run the tests to see them pass**

Run: `go mod tidy && go test ./... && go vet ./... && gofmt -l .`
Expected: `ok  github.com/adamrothman/sshsig-kms`, no vet output, no gofmt output.

- [ ] **Step 7: Commit**

```bash
git add go.mod go.sum LICENSE .gitignore sshsig.go sshsig_test.go helpers_test.go
git commit -m "Encode SSH signatures as ssh-keygen does" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Signing with KMS

**Files:**
- Create: `kms.go`, `localkms.go`
- Modify: `helpers_test.go` (add `testKMS`, `sshKeygenVerify`)
- Test: `kms_test.go`

**Interfaces:**
- Consumes (Task 1): `signedData`, `armor`, `newSSHKey`, `writeFile`.
- Produces:
  - `type kmsAPI interface { Sign(context.Context, *kms.SignInput, ...func(*kms.Options)) (*kms.SignOutput, error) }` (Task 6 adds `GetPublicKey`).
  - `type connectFunc func(ctx context.Context, keyID, profile string) (kmsAPI, error)`.
  - `type keyType struct { spec types.KeySpec; algorithm types.SigningAlgorithmSpec; decode func([]byte) ([]byte, error) }` and `var keyTypes map[string]keyType`, keyed by SSH key type name.
  - `func lookupKeyType(name string) (keyType, error)`: error text `key type <name> is not supported (ecdsa-sha2-nistp256, ssh-ed25519)`.
  - `func kmsSign(ctx context.Context, client kmsAPI, keyID string, pub ssh.PublicKey, data []byte) (*ssh.Signature, error)`. Error texts: `KMS key <keyID> returned a malformed signature: …` and `KMS key <keyID> did not produce a signature for the key in user.signingkey`.
  - `type localKMS struct { key crypto.Signer; keyType keyType }`, `func loadLocalKMS(path string) (localKMS, error)`, and `func connectLocal(ctx context.Context, keyID, profile string) (kmsAPI, error)`, where `keyID` is a private key file.
  - Test helpers: `func testKMS(t *testing.T, keyPath string) (localKMS, ssh.PublicKey)` and `func sshKeygenVerify(t *testing.T, pub ssh.PublicKey, namespace string, message, sig []byte)`.

- [ ] **Step 1: Add the KMS SDK**

```bash
go get github.com/aws/aws-sdk-go-v2/service/kms@latest
```

- [ ] **Step 2: Add the test helpers**

Add to `helpers_test.go`, making its imports `bytes`, `fmt`, `os`, `os/exec`, `path/filepath`, `testing` and `golang.org/x/crypto/ssh`:

```go
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
```

- [ ] **Step 3: Write the failing tests**

`kms_test.go`:

```go
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/asn1"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"slices"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"golang.org/x/crypto/ssh"
)

// stubKMS answers Sign with a fixed signature, or a fixed error.
type stubKMS struct {
	kmsAPI
	sig []byte
	err error
}

func (s stubKMS) Sign(context.Context, *kms.SignInput, ...func(*kms.Options)) (*kms.SignOutput, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &kms.SignOutput{Signature: s.sig}, nil
}

// testData returns the data sshsig-kms signs for message in namespace.
func testData(namespace string, message []byte) []byte {
	digest := sha512.Sum512(message)
	return signedData(namespace, digest[:])
}

func TestKMSSign(t *testing.T) {
	for _, keyType := range []string{"ed25519", "ecdsa"} {
		t.Run(keyType, func(t *testing.T) {
			client, pub := testKMS(t, newSSHKey(t, keyType))
			message := []byte("message\n")
			sig, err := kmsSign(context.Background(), client, "test-key", pub, testData("git", message))
			if err != nil {
				t.Fatal(err)
			}
			sshKeygenVerify(t, pub, "git", message, armor(pub, "git", sig))
		})
	}
}

// ECDSA's r and s are random 256-bit numbers. As SSH mpints, one with its
// high bit set gains a leading zero byte, and one under 2^248 is a byte
// shorter. Sign until each case has turned up, and check that ssh-keygen
// accepts it.
func TestKMSSignECDSAEncodings(t *testing.T) {
	client, pub := testKMS(t, newSSHKey(t, "ecdsa"))
	cases := map[string]func(r, s *big.Int) bool{
		"r has its high bit set":    func(r, _ *big.Int) bool { return r.BitLen() == 256 },
		"s has its high bit set":    func(_, s *big.Int) bool { return s.BitLen() == 256 },
		"r has a leading zero byte": func(r, _ *big.Int) bool { return r.BitLen() <= 248 },
		"s has a leading zero byte": func(_, s *big.Int) bool { return s.BitLen() <= 248 },
	}
	for i := 0; len(cases) > 0 && i < 100_000; i++ {
		message := fmt.Appendf(nil, "message %d\n", i)
		sig, err := kmsSign(context.Background(), client, "test-key", pub, testData("git", message))
		if err != nil {
			t.Fatal(err)
		}
		var rs struct{ R, S *big.Int }
		if err := ssh.Unmarshal(sig.Blob, &rs); err != nil {
			t.Fatal(err)
		}
		for name, match := range cases {
			if match(rs.R, rs.S) {
				t.Logf("%s after %d signatures", name, i+1)
				sshKeygenVerify(t, pub, "git", message, armor(pub, "git", sig))
				delete(cases, name)
			}
		}
	}
	if len(cases) > 0 {
		t.Errorf("never signed with: %s", strings.Join(slices.Sorted(maps.Keys(cases)), "; "))
	}
}

func TestKMSSignRefuses(t *testing.T) {
	data := testData("git", []byte("message\n"))
	_, edPub := testKMS(t, newSSHKey(t, "ed25519"))
	ecKMS, ecPub := testKMS(t, newSSHKey(t, "ecdsa"))
	otherEd, _ := testKMS(t, newSSHKey(t, "ed25519"))
	otherEC, _ := testKMS(t, newSSHKey(t, "ecdsa"))

	// What KMS returns for ECDSA: DER-encoded (r, s).
	der := func(r, s int64) []byte {
		b, err := asn1.Marshal(struct{ R, S *big.Int }{big.NewInt(r), big.NewInt(s)})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	valid, err := ecKMS.Sign(context.Background(), &kms.SignInput{
		Message:          data,
		MessageType:      types.MessageTypeRaw,
		SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256,
	})
	if err != nil {
		t.Fatal(err)
	}

	const wrongKey = "KMS key test-key did not produce a signature for the key in user.signingkey"
	for _, tt := range []struct {
		name   string
		client kmsAPI
		pub    ssh.PublicKey
		want   string // in the error
	}{
		{"Ed25519 signature by another key", otherEd, edPub, wrongKey},
		{"ECDSA signature by another key", otherEC, ecPub, wrongKey},
		{"Ed25519 signature of zeros", stubKMS{sig: make([]byte, 64)}, edPub, wrongKey},
		{"Ed25519 signature too short", stubKMS{sig: make([]byte, 63)}, edPub, "KMS key test-key returned a malformed signature: signature is 63 bytes, not 64"},
		{"Ed25519 signature too long", stubKMS{sig: make([]byte, 65)}, edPub, "signature is 65 bytes, not 64"},
		{"Ed25519 signature empty", stubKMS{}, edPub, "signature is 0 bytes, not 64"},
		{"ECDSA signature not DER", stubKMS{sig: []byte("not DER")}, ecPub, "KMS key test-key returned a malformed signature"},
		{"ECDSA signature with trailing data", stubKMS{sig: append(valid.Signature, 0)}, ecPub, "trailing data after the DER signature"},
		{"ECDSA r of zero", stubKMS{sig: der(0, 1)}, ecPub, "r and s must be positive"},
		{"ECDSA negative s", stubKMS{sig: der(1, -1)}, ecPub, "r and s must be positive"},
		{"ECDSA signature that doesn't verify", stubKMS{sig: der(1, 1)}, ecPub, wrongKey},
		{"KMS error", stubKMS{err: errors.New("AccessDeniedException: not allowed")}, edPub, "AccessDeniedException: not allowed"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			sig, err := kmsSign(context.Background(), tt.client, "test-key", tt.pub, data)
			if err == nil {
				t.Fatalf("got signature %x, want an error", sig.Blob)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q does not contain %q", err, tt.want)
			}
		})
	}
}

func TestKMSSignUnsupportedKeyType(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	_, err = kmsSign(context.Background(), stubKMS{}, "test-key", pub, testData("git", nil))
	want := "key type ssh-rsa is not supported (ecdsa-sha2-nistp256, ssh-ed25519)"
	if err == nil || err.Error() != want {
		t.Errorf("got error %v, want %q", err, want)
	}
}
```

- [ ] **Step 4: Run the tests to see them fail**

Run: `go test ./...`
Expected: FAIL to build, with `undefined: kmsAPI`, `undefined: kmsSign`, `undefined: localKMS`, `undefined: loadLocalKMS`.

- [ ] **Step 5: Write the KMS signing**

`kms.go`:

```go
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/asn1"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"golang.org/x/crypto/ssh"
)

// kmsAPI is the part of the KMS client sshsig-kms uses.
type kmsAPI interface {
	Sign(context.Context, *kms.SignInput, ...func(*kms.Options)) (*kms.SignOutput, error)
}

// connectFunc returns a KMS client for the key keyID, with credentials from
// the AWS profile, or the SDK's default chain if profile is "".
type connectFunc func(ctx context.Context, keyID, profile string) (kmsAPI, error)

// keyType says how KMS signs for one SSH key type.
type keyType struct {
	spec      types.KeySpec
	algorithm types.SigningAlgorithmSpec
	// decode turns the signature KMS returns into an SSH signature blob.
	decode func(kmsSig []byte) ([]byte, error)
}

// keyTypes are the SSH key types sshsig-kms signs with, by name.
var keyTypes = map[string]keyType{
	ssh.KeyAlgoED25519: {
		spec:      types.KeySpecEccNistEdwards25519,
		algorithm: types.SigningAlgorithmSpecEd25519Sha512, // PureEdDSA over the message
		decode:    decodeEd25519,
	},
	ssh.KeyAlgoECDSA256: {
		spec:      types.KeySpecEccNistP256,
		algorithm: types.SigningAlgorithmSpecEcdsaSha256, // KMS hashes the message with SHA-256
		decode:    decodeECDSA,
	},
}

// lookupKeyType returns how to sign for the SSH key type name.
func lookupKeyType(name string) (keyType, error) {
	kt, ok := keyTypes[name]
	if !ok {
		return keyType{}, fmt.Errorf("key type %s is not supported (%s)",
			name, strings.Join(slices.Sorted(maps.Keys(keyTypes)), ", "))
	}
	return kt, nil
}

// kmsSign asks KMS to sign data with the key keyID and returns the SSH
// signature. It fails unless the signature verifies against pub, so it
// never returns a signature by any other key.
func kmsSign(ctx context.Context, client kmsAPI, keyID string, pub ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	kt, err := lookupKeyType(pub.Type())
	if err != nil {
		return nil, err
	}
	out, err := client.Sign(ctx, &kms.SignInput{
		KeyId:            aws.String(keyID),
		Message:          data,
		MessageType:      types.MessageTypeRaw,
		SigningAlgorithm: kt.algorithm,
	})
	if err != nil {
		return nil, err
	}
	blob, err := kt.decode(out.Signature)
	if err != nil {
		return nil, fmt.Errorf("KMS key %s returned a malformed signature: %v", keyID, err)
	}
	sig := &ssh.Signature{Format: pub.Type(), Blob: blob}
	if err := pub.Verify(data, sig); err != nil {
		return nil, fmt.Errorf("KMS key %s did not produce a signature for the key in user.signingkey", keyID)
	}
	return sig, nil
}

// decodeEd25519 checks an Ed25519 signature from KMS. KMS returns the 64
// bytes of the signature, which are also SSH's encoding of it.
func decodeEd25519(sig []byte) ([]byte, error) {
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("signature is %d bytes, not %d", len(sig), ed25519.SignatureSize)
	}
	return sig, nil
}

// decodeECDSA converts an ECDSA signature from KMS, DER-encoded (r, s),
// to SSH's encoding: r and s as mpints.
func decodeECDSA(der []byte) ([]byte, error) {
	var rs struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &rs)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, errors.New("trailing data after the DER signature")
	}
	if rs.R.Sign() <= 0 || rs.S.Sign() <= 0 {
		return nil, errors.New("r and s must be positive")
	}
	return ssh.Marshal(rs), nil
}
```

`localkms.go`:

```go
package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"golang.org/x/crypto/ssh"
)

// localKMS stands in for KMS with a local private key, and answers as KMS
// does: an Ed25519 signature as its 64 bytes, an ECDSA signature
// DER-encoded. Tests use it, and so does newKMS in a fakekms build; release
// builds never reach it.
type localKMS struct {
	key     crypto.Signer
	keyType keyType
}

// loadLocalKMS reads an unencrypted OpenSSH private key file to sign with.
func loadLocalKMS(path string) (localKMS, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return localKMS{}, err
	}
	raw, err := ssh.ParseRawPrivateKey(data)
	if err != nil {
		return localKMS{}, fmt.Errorf("%s: %v", path, err)
	}
	// Ed25519 keys come back as *ed25519.PrivateKey, ECDSA keys as
	// *ecdsa.PrivateKey; both are crypto.Signers.
	key, ok := raw.(crypto.Signer)
	if !ok {
		return localKMS{}, fmt.Errorf("%s: unsupported private key %T", path, raw)
	}
	pub, err := ssh.NewPublicKey(key.Public())
	if err != nil {
		return localKMS{}, err
	}
	kt, err := lookupKeyType(pub.Type())
	if err != nil {
		return localKMS{}, err
	}
	return localKMS{key: key, keyType: kt}, nil
}

// connectLocal is a connectFunc for localKMS: keyID names an OpenSSH
// private key file, and profile is ignored.
func connectLocal(_ context.Context, keyID, _ string) (kmsAPI, error) {
	l, err := loadLocalKMS(keyID)
	if err != nil {
		return nil, err
	}
	return l, nil
}

func (l localKMS) Sign(_ context.Context, in *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	if in.SigningAlgorithm != l.keyType.algorithm || in.MessageType != types.MessageTypeRaw {
		return nil, fmt.Errorf("local key signs %s messages with %s, not %s messages with %s",
			types.MessageTypeRaw, l.keyType.algorithm, in.MessageType, in.SigningAlgorithm)
	}
	message, opts := in.Message, crypto.Hash(0) // Ed25519 signs the message itself
	if l.keyType.spec == types.KeySpecEccNistP256 {
		digest := sha256.Sum256(in.Message)
		message, opts = digest[:], crypto.SHA256
	}
	sig, err := l.key.Sign(rand.Reader, message, opts)
	if err != nil {
		return nil, err
	}
	return &kms.SignOutput{KeyId: in.KeyId, Signature: sig, SigningAlgorithm: in.SigningAlgorithm}, nil
}
```

- [ ] **Step 6: Run the tests to see them pass**

Run: `go mod tidy && go test -v -run 'TestKMS' ./... && go test ./... && go vet ./... && gofmt -l .`
Expected: PASS; `TestKMSSignECDSAEncodings` logs the four cases (the leading-zero ones after a few hundred signatures). No vet or gofmt output.

- [ ] **Step 7: Commit**

```bash
git add go.mod go.sum kms.go localkms.go kms_test.go helpers_test.go
git commit -m "Sign with KMS and verify before trusting the answer" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Configuration and connecting to KMS

**Files:**
- Create: `config.go`, `aws.go`, `fakekms.go`
- Modify: `helpers_test.go` (add `isolateGit`, `tryGit`, `runGit`)
- Test: `config_test.go`, `aws_test.go`

**Interfaces:**
- Consumes (Task 2): `kmsAPI`, `connectLocal`. (Task 1): `writeFile`.
- Produces:
  - `func gitConfig(name string) (string, error)`: `""` if unset; failures read `reading <name> from git config: <git's message>`.
  - `func keyRegion(keyID string) (string, error)`: failures read `<keyID> is not a KMS key ARN or alias ARN (arn:aws:kms:<region>:<account>:key/<key-id>)`.
  - `func newKMS(ctx context.Context, keyID, profile string) (kmsAPI, error)`, a `connectFunc`: real KMS in `aws.go` (`//go:build !fakekms`), a local key file in `fakekms.go` (`//go:build fakekms`).
  - Test helpers: `func isolateGit(t *testing.T) string` (returns the global config path, and moves the test to an empty temporary directory), `func tryGit(dir string, args ...string) (string, error)` and `func runGit(t *testing.T, dir string, args ...string) string` (combined output).

- [ ] **Step 1: Add the SDK's config module**

```bash
go get github.com/aws/aws-sdk-go-v2/config@latest
```

- [ ] **Step 2: Add the git test helpers**

Add to `helpers_test.go`, adding `strings` to its imports:

```go
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
```

- [ ] **Step 3: Write the failing tests**

`config_test.go`:

```go
package main

import (
	"strings"
	"testing"
)

func TestGitConfig(t *testing.T) {
	isolateGit(t)
	check := func(want string) {
		t.Helper()
		got, err := gitConfig("sshsig-kms.key")
		if err != nil || got != want {
			t.Fatalf("gitConfig = %q, %v; want %q", got, err, want)
		}
	}
	check("")

	runGit(t, ".", "config", "--global", "sshsig-kms.key", "global-key")
	check("global-key")

	runGit(t, ".", "init", "-q")
	runGit(t, ".", "config", "sshsig-kms.key", "repository-key")
	check("repository-key")
}

func TestGitConfigBrokenFile(t *testing.T) {
	global := isolateGit(t)
	writeFile(t, global, []byte("[broken\n"))
	_, err := gitConfig("sshsig-kms.key")
	if err == nil || !strings.Contains(err.Error(), "reading sshsig-kms.key from git config: fatal: bad config line 1") {
		t.Errorf("got error %v", err)
	}
}

func TestKeyRegion(t *testing.T) {
	for _, tt := range []struct{ arn, region string }{
		{"arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab", "us-west-2"},
		{"arn:aws:kms:eu-central-1:111122223333:alias/git-signing", "eu-central-1"},
		{"arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab", "us-gov-west-1"},
	} {
		region, err := keyRegion(tt.arn)
		if err != nil || region != tt.region {
			t.Errorf("keyRegion(%q) = %q, %v; want %q", tt.arn, region, err, tt.region)
		}
	}
	for _, keyID := range []string{
		"1234abcd-12ab-34cd-56ef-1234567890ab", // a key ID: no region
		"alias/git-signing",                    // an alias name: no region
		"arn:aws:s3:::bucket",
		"arn:aws:kms::111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
		"arn:aws:kms:us-west-2:111122223333:grant/1234",
	} {
		_, err := keyRegion(keyID)
		if err == nil || !strings.Contains(err.Error(), "is not a KMS key ARN or alias ARN") {
			t.Errorf("keyRegion(%q): got error %v", keyID, err)
		}
	}
}
```

`aws_test.go`:

```go
//go:build !fakekms

package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
)

func TestNewKMS(t *testing.T) {
	// Keep the developer's own AWS config out of the test.
	empty := filepath.Join(t.TempDir(), "empty")
	writeFile(t, empty, nil)
	t.Setenv("AWS_CONFIG_FILE", empty)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", empty)
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_REGION", "ap-southeast-2") // the key's region must win

	const keyARN = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
	client, err := newKMS(context.Background(), keyARN, "")
	if err != nil {
		t.Fatal(err)
	}
	if region := client.(*kms.Client).Options().Region; region != "us-west-2" {
		t.Errorf("client region is %s, want us-west-2", region)
	}

	_, err = newKMS(context.Background(), keyARN, "no-such-profile")
	if err == nil || !strings.Contains(err.Error(), "no-such-profile") {
		t.Errorf("with a missing profile: got error %v", err)
	}

	_, err = newKMS(context.Background(), "alias/git-signing", "")
	if err == nil || !strings.Contains(err.Error(), "is not a KMS key ARN or alias ARN") {
		t.Errorf("with an alias name: got error %v", err)
	}
}
```

- [ ] **Step 4: Run the tests to see them fail**

Run: `go test ./...`
Expected: FAIL to build, with `undefined: gitConfig`, `undefined: keyRegion`, `undefined: newKMS`.

- [ ] **Step 5: Write the configuration and connection code**

`config.go`:

```go
package main

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
)

// gitConfig returns the value of the git config setting name, or "" if it
// isn't set. It reads with git config --get, so it has git's scoping:
// global or per repository, conditional includes, and git -c.
func gitConfig(name string) (string, error) {
	out, err := exec.Command("git", "config", "--get", name).Output()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if exitErr.ExitCode() == 1 { // the setting isn't set
			return "", nil
		}
		if msg := strings.TrimSpace(string(exitErr.Stderr)); msg != "" {
			err = errors.New(msg)
		}
	}
	if err != nil {
		return "", fmt.Errorf("reading %s from git config: %v", name, err)
	}
	return strings.TrimSpace(string(out)), nil
}

// keyRegion returns the AWS region of a KMS key ARN or alias ARN.
func keyRegion(keyID string) (string, error) {
	a, err := arn.Parse(keyID)
	if err != nil || a.Service != "kms" || a.Region == "" ||
		!(strings.HasPrefix(a.Resource, "key/") || strings.HasPrefix(a.Resource, "alias/")) {
		return "", fmt.Errorf("%s is not a KMS key ARN or alias ARN (arn:aws:kms:<region>:<account>:key/<key-id>)", keyID)
	}
	return a.Region, nil
}
```

`aws.go`:

```go
//go:build !fakekms

package main

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

// newKMS returns a KMS client in the region of the key keyID, with
// credentials from the AWS profile, or the SDK's default chain if profile
// is "".
func newKMS(ctx context.Context, keyID, profile string) (kmsAPI, error) {
	region, err := keyRegion(keyID)
	if err != nil {
		return nil, err
	}
	opts := []func(*config.LoadOptions) error{config.WithRegion(region)}
	if profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(profile))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return kms.NewFromConfig(cfg), nil
}
```

`fakekms.go`:

```go
//go:build fakekms

package main

import "context"

// newKMS, in a fakekms build, signs with a local key instead of KMS:
// sshsig-kms.key names an OpenSSH private key file. Only tests make this
// build, to run git against the binary end to end.
func newKMS(ctx context.Context, keyID, profile string) (kmsAPI, error) {
	return connectLocal(ctx, keyID, profile)
}
```

- [ ] **Step 6: Run the tests to see them pass**

Run: `go mod tidy && go test ./... && go vet ./... && go vet -tags fakekms ./... && gofmt -l .`
Expected: PASS; no vet or gofmt output.

- [ ] **Step 7: Commit**

```bash
git add go.mod go.sum config.go aws.go fakekms.go config_test.go aws_test.go helpers_test.go
git commit -m "Read settings from git config and connect to the key's region" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: The command: dispatch, version, errors, hand-off to ssh-keygen

**Files:**
- Create: `main.go`, `passthrough.go`
- Modify: `helpers_test.go` (add `sourceDir`, `testBinary`, `TestMain`)
- Test: `main_test.go`

**Interfaces:**
- Consumes (Task 3): `fakekms.go`'s `newKMS` (so the `fakekms` binary builds). (Task 1): `writeFile`.
- Produces:
  - `var version string`, set with `-ldflags "-X main.version=…"`; `func buildVersion() string`.
  - `func run(args []string, stdout io.Writer) error`: `version`, else `execSSHKeygen`. Task 5 adds `-Y sign` and Task 6 adds `public-key`.
  - `func errorLine(err error) string`: `"sshsig-kms: "` plus the error with every run of whitespace collapsed to one space.
  - `func execSSHKeygen(args []string) error`.
  - Test helper: `func testBinary(t *testing.T) string`, the path of a `fakekms` build made once per test run.

- [ ] **Step 1: Add the binary-building test helper**

Add to `helpers_test.go`, adding `sync` to its imports:

```go
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
```

- [ ] **Step 2: Write the failing tests**

`main_test.go`:

```go
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
```

- [ ] **Step 3: Run the tests to see them fail**

Run: `go test ./...`
Expected: FAIL to build, with `undefined: run`, `undefined: version`, `undefined: errorLine`.

- [ ] **Step 4: Write the command**

`main.go`:

```go
// Command sshsig-kms signs git commits and tags with an SSH key held in
// AWS KMS. git runs it as gpg.ssh.program, in place of ssh-keygen: it
// makes -Y sign calls' signatures itself and hands every other call to
// ssh-keygen. See docs/design.md.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strings"
)

// version is the version sshsig-kms was built as, which the release build
// sets with -ldflags "-X main.version=0.1.0".
var version string

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, errorLine(err))
		os.Exit(1)
	}
}

// run carries out the command in args, writing any output to stdout.
func run(args []string, stdout io.Writer) error {
	switch {
	case len(args) > 0 && args[0] == "version":
		if len(args) > 1 {
			return errors.New("version takes no arguments")
		}
		_, err := fmt.Fprintln(stdout, buildVersion())
		return err
	default:
		return execSSHKeygen(args)
	}
}

// buildVersion returns the version sshsig-kms was built as.
func buildVersion() string {
	if version != "" {
		return version
	}
	// go install records the version of the module it built.
	if info, ok := debug.ReadBuildInfo(); ok {
		return strings.TrimPrefix(info.Main.Version, "v")
	}
	return "unknown"
}

// errorLine formats err as the one line sshsig-kms prints when it fails,
// which git shows the user. AWS's errors can run over several lines.
func errorLine(err error) string {
	return "sshsig-kms: " + strings.Join(strings.Fields(err.Error()), " ")
}
```

`passthrough.go`:

```go
package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// execSSHKeygen replaces sshsig-kms with the ssh-keygen on PATH, run with
// the same arguments, so stdin, stdout and the exit status are
// ssh-keygen's. It returns only if that fails.
func execSSHKeygen(args []string) error {
	path, err := exec.LookPath("ssh-keygen")
	if err != nil {
		return fmt.Errorf("finding ssh-keygen: %v", err)
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if sameFile(path, self) {
		return fmt.Errorf("ssh-keygen on PATH (%s) is sshsig-kms itself; put OpenSSH's ssh-keygen ahead of it on PATH", path)
	}
	return syscall.Exec(path, append([]string{"ssh-keygen"}, args...), os.Environ())
}

// sameFile reports whether the paths a and b name the same file.
func sameFile(a, b string) bool {
	fa, errA := os.Stat(a)
	fb, errB := os.Stat(b)
	return errA == nil && errB == nil && os.SameFile(fa, fb)
}
```

- [ ] **Step 5: Run the tests to see them pass**

Run: `go test ./... && go vet ./... && go vet -tags fakekms ./... && gofmt -l .`
Expected: PASS; no vet or gofmt output.

- [ ] **Step 6: Try the binary by hand**

```bash
dir=$(mktemp -d)
go build -o "$dir/sshsig-kms" . && "$dir/sshsig-kms" version
ssh-keygen -q -t ed25519 -N '' -f "$dir/key" && "$dir/sshsig-kms" -l -f "$dir/key.pub"
rm -rf "$dir"
```
Expected: a version line (a pseudo-version such as `0.0.0-…`, or `(devel)`), then the key's fingerprint, printed by ssh-keygen.

- [ ] **Step 7: Commit**

```bash
git add main.go passthrough.go main_test.go helpers_test.go
git commit -m "Hand calls other than -Y sign to ssh-keygen" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: The -Y sign call

**Files:**
- Create: `sign.go`
- Modify: `main.go` (add `timeLimit` and the `-Y sign` case in `run`)
- Test: `sign_test.go`, `main_test.go` (add `TestRunDispatchesSign`)

**Interfaces:**
- Consumes: (Task 1) `signedData`, `armor`; (Task 2) `kmsSign`, `lookupKeyType`, `connectFunc`, `connectLocal`, `kmsAPI`; (Task 3) `gitConfig`, `newKMS`, `isolateGit`, `runGit`; test helpers `newSSHKey`, `writeFile`, `sshKeygenVerify`.
- Produces:
  - `const timeLimit = 8 * time.Second` (in `main.go`).
  - `type signRequest struct { namespace, keyFile, file string }`.
  - `func isSign(args []string) bool`, `func parseSignArgs(args []string) (signRequest, error)`, `func readPublicKey(keyFile string) (ssh.PublicKey, error)`, `func hashFile(path string) ([]byte, error)`.
  - `func runSign(args []string, connect connectFunc, timeout time.Duration) error`.
  - Error texts: `-Y sign: unexpected argument "<arg>"`, `-Y sign: missing -n <namespace>`, `-Y sign: missing -f <keyfile>`, `-Y sign: missing the file to sign`, `-Y sign: <flag> needs a value`, `-Y sign: <flag> given more than once`, `<keyFile> holds no SSH public key (user.signingkey must name the public key)`, `no KMS key configured: set sshsig-kms.key in git config`, `no signature within <timeout>: …`.

- [ ] **Step 1: Write the failing tests**

`sign_test.go`:

```go
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
```

Add to `main_test.go`, adding `io` to its imports:

```go
func TestRunDispatchesSign(t *testing.T) {
	// Without -f, the call fails while parsing, before it could reach AWS.
	err := run([]string{"-Y", "sign", "-n", "git", "payload"}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "missing -f <keyfile>") {
		t.Errorf("got error %v", err)
	}
}
```

- [ ] **Step 2: Run the tests to see them fail**

Run: `go test ./...`
Expected: FAIL to build, with `undefined: isSign`, `undefined: parseSignArgs`, `undefined: signRequest`, `undefined: readPublicKey`, `undefined: runSign`.

- [ ] **Step 3: Write the -Y sign call**

`sign.go`:

```go
package main

import (
	"context"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// signRequest is a -Y sign call, as git makes it:
//
//	sshsig-kms -Y sign -n <namespace> -f <keyfile> [-U] <file>
type signRequest struct {
	namespace string
	keyFile   string // holds the public key from user.signingkey
	file      string // the file to sign
}

// isSign reports whether args are a -Y sign call.
func isSign(args []string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "-Y" && args[i+1] == "sign" {
			return true
		}
	}
	return false
}

// parseSignArgs parses a -Y sign call strictly: the flags git passes, each
// once, and one file to sign.
func parseSignArgs(args []string) (signRequest, error) {
	var req signRequest
	var mode string
	flags := map[string]*string{"-Y": &mode, "-n": &req.namespace, "-f": &req.keyFile}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-U" {
			// git adds -U for inline keys, telling ssh-keygen the private
			// key is in an agent. It means nothing here.
			continue
		}
		if value, ok := flags[arg]; ok {
			if i+1 == len(args) {
				return signRequest{}, fmt.Errorf("-Y sign: %s needs a value", arg)
			}
			if *value != "" {
				return signRequest{}, fmt.Errorf("-Y sign: %s given more than once", arg)
			}
			i++
			*value = args[i]
			continue
		}
		if strings.HasPrefix(arg, "-") || req.file != "" {
			return signRequest{}, fmt.Errorf("-Y sign: unexpected argument %q", arg)
		}
		req.file = arg
	}
	switch {
	case mode != "sign":
		return signRequest{}, errors.New("not a -Y sign call")
	case req.namespace == "":
		return signRequest{}, errors.New("-Y sign: missing -n <namespace>")
	case req.keyFile == "":
		return signRequest{}, errors.New("-Y sign: missing -f <keyfile>")
	case req.file == "":
		return signRequest{}, errors.New("-Y sign: missing the file to sign")
	}
	return req, nil
}

// readPublicKey reads the public key in keyFile, in authorized_keys format,
// ignoring its comment.
func readPublicKey(keyFile string) (ssh.PublicKey, error) {
	data, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return nil, fmt.Errorf("%s holds no SSH public key (user.signingkey must name the public key)", keyFile)
	}
	if _, err := lookupKeyType(pub.Type()); err != nil {
		return nil, err
	}
	return pub, nil
}

// hashFile returns the SHA-512 hash of the file at path.
func hashFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha512.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// runSign carries out a -Y sign call: it signs the file with the KMS key in
// git config, connecting with connect, and writes the signature to
// <file>.sig. It gives up after timeout.
func runSign(args []string, connect connectFunc, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := parseSignArgs(args)
	if err != nil {
		return err
	}
	pub, err := readPublicKey(req.keyFile)
	if err != nil {
		return err
	}
	keyID, err := gitConfig("sshsig-kms.key")
	if err != nil {
		return err
	}
	if keyID == "" {
		return errors.New("no KMS key configured: set sshsig-kms.key in git config")
	}
	profile, err := gitConfig("sshsig-kms.profile")
	if err != nil {
		return err
	}
	digest, err := hashFile(req.file)
	if err != nil {
		return err
	}

	client, err := connect(ctx, keyID, profile)
	if err != nil {
		return err
	}
	sig, err := kmsSign(ctx, client, keyID, pub, signedData(req.namespace, digest))
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("no signature within %v: %w", timeout, err)
		}
		return err
	}
	return os.WriteFile(req.file+".sig", armor(pub, req.namespace, sig), 0o666)
}
```

In `main.go`, add `"time"` to the imports, add the constant below `version`, and add the `-Y sign` case to `run`:

```go
// timeLimit bounds each run's work, from loading credentials to writing its
// output, so a broken network fails a commit promptly instead of hanging it.
const timeLimit = 8 * time.Second
```

```go
func run(args []string, stdout io.Writer) error {
	switch {
	case len(args) > 0 && args[0] == "version":
		if len(args) > 1 {
			return errors.New("version takes no arguments")
		}
		_, err := fmt.Fprintln(stdout, buildVersion())
		return err
	case isSign(args):
		return runSign(args, newKMS, timeLimit)
	default:
		return execSSHKeygen(args)
	}
}
```

- [ ] **Step 4: Run the tests to see them pass**

Run: `go test ./... && go vet ./... && go vet -tags fakekms ./... && gofmt -l .`
Expected: PASS; no vet or gofmt output.

- [ ] **Step 5: Commit**

```bash
git add sign.go sign_test.go main.go main_test.go
git commit -m "Sign git's -Y sign calls with the KMS key in git config" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6: The public-key command

**Files:**
- Modify: `kms.go` (add `GetPublicKey` to `kmsAPI`, add `supportedSpecs` and `kmsPublicKey`), `localkms.go` (add `GetPublicKey`), `main.go` (add `runPublicKey` and the `public-key` case)
- Test: `kms_test.go`, `main_test.go`

**Interfaces:**
- Consumes: (Task 2) `kmsAPI`, `keyTypes`, `localKMS`, `connectLocal`, `testKMS`; (Task 3) `gitConfig`, `newKMS`, `isolateGit`, `runGit`; (Task 5) `timeLimit`.
- Produces:
  - `kmsAPI` gains `GetPublicKey(context.Context, *kms.GetPublicKeyInput, ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)`.
  - `func kmsPublicKey(ctx context.Context, client kmsAPI, keyID string) (ssh.PublicKey, error)`. Error texts: `KMS key <keyID> has key usage <usage>, not SIGN_VERIFY`, `KMS key <keyID> has key spec <spec>, which is not supported (ECC_NIST_EDWARDS25519, ECC_NIST_P256)`, `KMS key <keyID>: <parse error>`.
  - `func runPublicKey(keyID string, connect connectFunc, timeout time.Duration, stdout io.Writer) error`.

- [ ] **Step 1: Write the failing tests**

Add to `kms_test.go`, adding `bytes` to its imports:

```go
// publicKeyStub answers GetPublicKey with a fixed answer.
type publicKeyStub struct {
	kmsAPI
	out *kms.GetPublicKeyOutput
}

func (s publicKeyStub) GetPublicKey(context.Context, *kms.GetPublicKeyInput, ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	return s.out, nil
}

func TestKMSPublicKey(t *testing.T) {
	for _, keyType := range []string{"ed25519", "ecdsa"} {
		t.Run(keyType, func(t *testing.T) {
			client, want := testKMS(t, newSSHKey(t, keyType))
			got, err := kmsPublicKey(context.Background(), client, "test-key")
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got.Marshal(), want.Marshal()) {
				t.Errorf("got %s, want %s", ssh.MarshalAuthorizedKey(got), ssh.MarshalAuthorizedKey(want))
			}
		})
	}
}

func TestKMSPublicKeyRefuses(t *testing.T) {
	for _, tt := range []struct {
		name string
		out  *kms.GetPublicKeyOutput
		want string
	}{
		{
			"encryption key",
			&kms.GetPublicKeyOutput{KeySpec: types.KeySpecRsa2048, KeyUsage: types.KeyUsageTypeEncryptDecrypt},
			"KMS key test-key has key usage ENCRYPT_DECRYPT, not SIGN_VERIFY",
		},
		{
			"RSA signing key",
			&kms.GetPublicKeyOutput{KeySpec: types.KeySpecRsa2048, KeyUsage: types.KeyUsageTypeSignVerify},
			"KMS key test-key has key spec RSA_2048, which is not supported (ECC_NIST_EDWARDS25519, ECC_NIST_P256)",
		},
		{
			"malformed public key",
			&kms.GetPublicKeyOutput{KeySpec: types.KeySpecEccNistP256, KeyUsage: types.KeyUsageTypeSignVerify, PublicKey: []byte("not DER")},
			"KMS key test-key: ",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := kmsPublicKey(context.Background(), publicKeyStub{out: tt.out}, "test-key")
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("got error %v, want one containing %q", err, tt.want)
			}
		})
	}
}
```

Add to `main_test.go`, adding `context` and `time` to its imports:

```go
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
```

- [ ] **Step 2: Run the tests to see them fail**

Run: `go test ./...`
Expected: FAIL to build, with `undefined: kmsPublicKey` and `undefined: runPublicKey`.

- [ ] **Step 3: Write the public-key command**

In `kms.go`, add `"crypto/x509"` to the imports, extend the interface, and add two functions:

```go
// kmsAPI is the part of the KMS client sshsig-kms uses.
type kmsAPI interface {
	Sign(context.Context, *kms.SignInput, ...func(*kms.Options)) (*kms.SignOutput, error)
	GetPublicKey(context.Context, *kms.GetPublicKeyInput, ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
}
```

```go
// supportedSpecs lists the KMS key specs sshsig-kms signs with.
func supportedSpecs() []string {
	var specs []string
	for _, kt := range keyTypes {
		specs = append(specs, string(kt.spec))
	}
	slices.Sort(specs)
	return specs
}

// kmsPublicKey returns the public half of the KMS key keyID as an SSH
// public key. The key must be for signing, with a supported key spec.
func kmsPublicKey(ctx context.Context, client kmsAPI, keyID string) (ssh.PublicKey, error) {
	out, err := client.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: aws.String(keyID)})
	if err != nil {
		return nil, err
	}
	if out.KeyUsage != types.KeyUsageTypeSignVerify {
		return nil, fmt.Errorf("KMS key %s has key usage %s, not %s", keyID, out.KeyUsage, types.KeyUsageTypeSignVerify)
	}
	if !slices.Contains(supportedSpecs(), string(out.KeySpec)) {
		return nil, fmt.Errorf("KMS key %s has key spec %s, which is not supported (%s)",
			keyID, out.KeySpec, strings.Join(supportedSpecs(), ", "))
	}
	// KMS returns a DER SubjectPublicKeyInfo.
	key, err := x509.ParsePKIXPublicKey(out.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("KMS key %s: %v", keyID, err)
	}
	pub, err := ssh.NewPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("KMS key %s: %v", keyID, err)
	}
	return pub, nil
}
```

In `localkms.go`, add `"crypto/x509"` to the imports and the method:

```go
func (l localKMS) GetPublicKey(_ context.Context, in *kms.GetPublicKeyInput, _ ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	der, err := x509.MarshalPKIXPublicKey(l.key.Public())
	if err != nil {
		return nil, err
	}
	return &kms.GetPublicKeyOutput{
		KeyId:             in.KeyId,
		KeySpec:           l.keyType.spec,
		KeyUsage:          types.KeyUsageTypeSignVerify,
		PublicKey:         der,
		SigningAlgorithms: []types.SigningAlgorithmSpec{l.keyType.algorithm},
	}, nil
}
```

In `main.go`, add `"context"` and `"golang.org/x/crypto/ssh"` to the imports, add the `public-key` case to `run`, and add `runPublicKey`:

```go
func run(args []string, stdout io.Writer) error {
	switch {
	case len(args) > 0 && args[0] == "version":
		if len(args) > 1 {
			return errors.New("version takes no arguments")
		}
		_, err := fmt.Fprintln(stdout, buildVersion())
		return err
	case len(args) > 0 && args[0] == "public-key":
		if len(args) != 2 {
			return errors.New("public-key takes one argument: the KMS key's ARN")
		}
		return runPublicKey(args[1], newKMS, timeLimit, stdout)
	case isSign(args):
		return runSign(args, newKMS, timeLimit)
	default:
		return execSSHKeygen(args)
	}
}

// runPublicKey prints the public half of the KMS key keyID as an SSH public
// key line, connecting with the AWS profile in sshsig-kms.profile if it's
// set. It gives up after timeout.
func runPublicKey(keyID string, connect connectFunc, timeout time.Duration, stdout io.Writer) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	profile, err := gitConfig("sshsig-kms.profile")
	if err != nil {
		return err
	}
	client, err := connect(ctx, keyID, profile)
	if err != nil {
		return err
	}
	pub, err := kmsPublicKey(ctx, client, keyID)
	if err != nil {
		return err
	}
	_, err = stdout.Write(ssh.MarshalAuthorizedKey(pub))
	return err
}
```

- [ ] **Step 4: Run the tests to see them pass**

Run: `go test ./... && go vet ./... && go vet -tags fakekms ./... && gofmt -l .`
Expected: PASS; no vet or gofmt output.

- [ ] **Step 5: Commit**

```bash
git add kms.go localkms.go main.go kms_test.go main_test.go
git commit -m "Print a KMS key's public half as an SSH public key" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 7: End to end with git

**Files:**
- Test: `e2e_test.go`

**Interfaces:**
- Consumes: (Task 3) `isolateGit`, `tryGit`, `runGit`; (Task 4) `testBinary`; (Task 1) `newSSHKey`, `writeFile`. In a `fakekms` build, `sshsig-kms.key` is the path of an OpenSSH private key file (Task 3's `fakekms.go`).
- Produces: nothing for later tasks.

This task adds tests only. If one fails, the bug is in earlier tasks' code: fix it there (with superpowers:systematic-debugging), and commit the fix with the tests.

- [ ] **Step 1: Write the tests**

`e2e_test.go`:

```go
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
```

- [ ] **Step 2: Run the tests**

Run: `go test -v -run 'TestGit|TestBinary' ./...`
Expected: PASS for every subtest. On failure, git's output in the message shows sshsig-kms's stderr line.

- [ ] **Step 3: Run the whole suite as CI will**

Run: `go test -race ./... && go vet ./... && go vet -tags fakekms ./... && gofmt -l .`
Expected: PASS; no vet or gofmt output.

- [ ] **Step 4: Commit**

```bash
git add e2e_test.go
git commit -m "Test signing end to end with git" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 8: Integration test against real KMS

**Files:**
- Test: `integration_test.go`

**Interfaces:**
- Consumes: (Task 3) `newKMS` from `aws.go`; (Task 6) `kmsPublicKey`; (Task 2) `kmsSign`, `sshKeygenVerify`; (Task 1) `signedData`, `armor`.
- Produces: nothing for later tasks. Task 12 runs it.

- [ ] **Step 1: Write the test**

`integration_test.go`:

```go
//go:build integration

package main

import (
	"context"
	"crypto/sha512"
	"os"
	"slices"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// TestKMS signs with a real KMS key. It confirms that KMS returns Ed25519
// signatures as their 64 raw bytes and measures KMS's latency. Run it by
// hand, with credentials from the environment:
//
//	SSHSIG_KMS_TEST_KEY=arn:aws:kms:… go test -tags integration -run TestKMS -v
func TestKMS(t *testing.T) {
	keyID := os.Getenv("SSHSIG_KMS_TEST_KEY")
	if keyID == "" {
		t.Skip("set SSHSIG_KMS_TEST_KEY to the ARN of a KMS signing key")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	client, err := newKMS(ctx, keyID, "")
	if err != nil {
		t.Fatal(err)
	}
	pub, err := kmsPublicKey(ctx, client, keyID)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("public key: %s", ssh.MarshalAuthorizedKey(pub))

	message := []byte("tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\nintegration test\n")
	digest := sha512.Sum512(message)
	data := signedData("git", digest[:])
	var sig *ssh.Signature
	var latencies []time.Duration
	for range 10 {
		start := time.Now()
		sig, err = kmsSign(ctx, client, keyID, pub, data)
		if err != nil {
			t.Fatal(err)
		}
		latencies = append(latencies, time.Since(start))
	}
	t.Logf("first signature: %v (includes loading credentials and connecting)", latencies[0])
	rest := slices.Sorted(slices.Values(latencies[1:]))
	t.Logf("next %d: median %v, slowest %v", len(rest), rest[len(rest)/2], rest[len(rest)-1])

	sshKeygenVerify(t, pub, "git", message, armor(pub, "git", sig))
}
```

- [ ] **Step 2: Check it builds and skips without a key**

Run: `go vet -tags integration ./... && go test -tags integration -run TestKMS -v ./...`
Expected: no vet output; `--- SKIP: TestKMS (… set SSHSIG_KMS_TEST_KEY …)`.

- [ ] **Step 3: Commit**

```bash
git add integration_test.go
git commit -m "Add an integration test against real KMS" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 9: CI and Dependabot

**Files:**
- Create: `.github/workflows/ci.yml`, `.github/dependabot.yml`

**Interfaces:**
- Consumes: the test suite and the build tags `fakekms` and `integration`.
- Produces: the `test` job, run on every push to `main` and every pull request.

Actions are pinned to full commit SHAs (looked up 2026-10-04); Dependabot keeps them current.

- [ ] **Step 1: Write the CI workflow**

`.github/workflows/ci.yml`:

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read

jobs:
  test:
    strategy:
      fail-fast: false
      matrix:
        runner: [ubuntu-latest, ubuntu-24.04-arm, macos-latest]
    runs-on: ${{ matrix.runner }}
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0
        with:
          go-version-file: go.mod
      - name: gofmt
        run: |
          unformatted=$(gofmt -l .)
          if [ -n "$unformatted" ]; then
            echo "Not gofmt-formatted:"
            echo "$unformatted"
            exit 1
          fi
      - name: go vet
        run: |
          go vet ./...
          go vet -tags fakekms ./...
          go vet -tags integration ./...
      - name: go test
        run: go test -race ./...
```

- [ ] **Step 2: Write the Dependabot config**

`.github/dependabot.yml`:

```yaml
version: 2
updates:
  - package-ecosystem: gomod
    directory: /
    schedule:
      interval: weekly
    groups:
      aws-sdk:
        patterns: ["github.com/aws/*"]
  - package-ecosystem: github-actions
    directory: /
    schedule:
      interval: weekly
```

- [ ] **Step 3: Lint the workflow**

Run: `go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12`
Expected: no output (actionlint checks `run:` scripts with shellcheck, which is on `PATH`).

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/ci.yml .github/dependabot.yml
git commit -m "Run tests in CI on Linux and macOS; keep dependencies current" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

CI runs for real when the pull request opens (Task 12).

---

### Task 10: Release workflow

**Files:**
- Create: `.github/workflows/release.yml`

**Interfaces:**
- Consumes: `main.version` (Task 4), which `-ldflags` sets.
- Produces: on a `v*` tag, a GitHub release carrying `sshsig-kms_<version>_<os>_<arch>` ×4, `SHA256SUMS`, and build-provenance attestations.

- [ ] **Step 1: Write the workflow**

`.github/workflows/release.yml`:

```yaml
name: Release

on:
  push:
    tags: ["v*"]

permissions: {}

jobs:
  release:
    runs-on: ubuntu-latest
    permissions:
      contents: write # create the release
      id-token: write # sign the attestations
      attestations: write # store the attestations
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0
        with:
          go-version-file: go.mod
          cache: false # build releases from a clean module cache
      - name: Test
        run: go test ./...
      - name: Build
        run: |
          version="${GITHUB_REF_NAME#v}"
          mkdir dist
          for os in linux darwin; do
            for arch in amd64 arm64; do
              CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath \
                -ldflags "-X main.version=$version" \
                -o "dist/sshsig-kms_${version}_${os}_${arch}" .
            done
          done
          (cd dist && sha256sum sshsig-kms_* > SHA256SUMS)
      - uses: actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8 # v4.2.2
        with:
          subject-path: dist/sshsig-kms_*
      - name: Publish the release
        env:
          GH_TOKEN: ${{ github.token }}
        run: >
          gh release create "$GITHUB_REF_NAME" dist/*
          --repo "$GITHUB_REPOSITORY" --verify-tag
          --title "$GITHUB_REF_NAME" --generate-notes
```

- [ ] **Step 2: Lint it**

Run: `go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12`
Expected: no output.

- [ ] **Step 3: Dry-run the build step locally**

```bash
GITHUB_REF_NAME=v0.0.0-dryrun bash -c '
  set -e
  version="${GITHUB_REF_NAME#v}"
  mkdir dist
  for os in linux darwin; do
    for arch in amd64 arm64; do
      CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath \
        -ldflags "-X main.version=$version" \
        -o "dist/sshsig-kms_${version}_${os}_${arch}" .
    done
  done
  (cd dist && sha256sum sshsig-kms_* > SHA256SUMS)
'
ls dist && cat dist/SHA256SUMS && file dist/sshsig-kms_*
./dist/sshsig-kms_0.0.0-dryrun_darwin_arm64 version
rm -rf dist
```
Expected: four binaries and `SHA256SUMS`; `file` reports the right OS and architecture for each (the Linux ones statically linked); `version` prints `0.0.0-dryrun`.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "Build, attest and publish releases from v* tags" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

Don't push a tag. v0.1.0 waits for Adam.

---

### Task 11: README

**Files:**
- Modify: `README.md` (replace), `docs/design.md:3` (status line)

**Interfaces:**
- Consumes: everything user-facing: commands, settings, messages, release file names.
- Produces: nothing for later tasks.

- [ ] **Step 1: Check the macOS checksum command**

Run: `sha256sum --help 2>&1 | grep -- --ignore-missing`
Expected: a line describing `--ignore-missing`, so the README's single `sha256sum --check --ignore-missing` line works on macOS as well as Linux. If it's missing, give macOS users `shasum -a 256 --check --ignore-missing SHA256SUMS` instead.

- [ ] **Step 2: Write the README**

`README.md`:

````markdown
# sshsig-kms

Sign git commits and tags with an SSH key held in AWS KMS.

git runs `sshsig-kms` as `gpg.ssh.program`, in place of `ssh-keygen`. Each
signature is one KMS `Sign` call: the private key never leaves KMS, and
there's no `ssh-agent`, socket or background process. The signatures are
exactly what `ssh-keygen -Y sign` makes, so git, OpenSSH and GitHub verify
them like any other SSH signature, and GitHub shows the commits as
**Verified**.

## Why

`ssh-keygen -Y sign`, which git runs to make SSH signatures, can only sign
with a key it can read from a file or reach through `ssh-agent`. A KMS key
can't be exported, which is the point: IAM decides who may sign, CloudTrail
logs every signature, and when access ends no copy of the key is left
behind. The existing ways to use a KMS key for SSH all go through an agent
socket, which sandboxes such as Claude Code's on Linux block. `sshsig-kms`
needs nothing but HTTPS to AWS, and honours `HTTPS_PROXY`.

## Install

Download the binary for your platform from the
[releases](https://github.com/adamrothman/sshsig-kms/releases), check it,
and put it on your `PATH`:

```sh
version=0.1.0
platform=linux_amd64   # or linux_arm64, darwin_amd64, darwin_arm64
file=sshsig-kms_${version}_${platform}
base=https://github.com/adamrothman/sshsig-kms/releases/download/v$version
curl -fsSLO "$base/$file" -O "$base/SHA256SUMS"
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify "$file" --repo adamrothman/sshsig-kms
install -m 0755 "$file" ~/.local/bin/sshsig-kms
```

`gh attestation verify` checks that this repository's release workflow
built the binary. Or build it yourself:

```sh
go install github.com/adamrothman/sshsig-kms@latest
```

git's verification calls (`git verify-commit`, `git log --show-signature`)
go through to OpenSSH, so `ssh-keygen` (OpenSSH 8.2p1 or later) must be on
your `PATH` too.

## Set up

1. Create the key:

   ```sh
   aws kms create-key --key-spec ECC_NIST_EDWARDS25519 --key-usage SIGN_VERIFY \
     --description "git commit signing"
   ```

   `ECC_NIST_P256` works too.

2. Allow whoever signs to call `kms:Sign` on the key, and allow
   `kms:GetPublicKey` for the next step. See [IAM policy](#iam-policy).

3. Save the public key:

   ```sh
   sshsig-kms public-key arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab \
     > ~/.ssh/kms-signing.pub
   ```

4. On GitHub, add that key as a **signing** key, not an authentication key
   (Settings → SSH and GPG keys → New SSH key → Key type: Signing Key), on
   the account whose email your commits use as committer.

5. Configure git:

   ```ini
   [gpg]
   	format = ssh
   [gpg "ssh"]
   	program = sshsig-kms
   [user]
   	signingkey = ~/.ssh/kms-signing.pub
   [commit]
   	gpgsign = true
   [sshsig-kms]
   	key = arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab
   	profile = signing
   ```

To verify signatures locally as well, add the key to an allowed-signers
file:

```sh
echo "you@example.com $(cat ~/.ssh/kms-signing.pub)" >> ~/.ssh/allowed_signers
git config --global gpg.ssh.allowedSignersFile ~/.ssh/allowed_signers
git verify-commit HEAD
```

## Configuration

`sshsig-kms` reads its settings with `git config --get`, so they have
git's scoping: global or per repository, conditional includes, and
`git -c`.

- `sshsig-kms.key` (required): the KMS key's ARN, or an alias ARN. The
  region comes from the ARN.
- `sshsig-kms.profile` (optional): an AWS profile for `sshsig-kms` alone.
  Without it, credentials come from the AWS SDK's default chain
  (environment, shared config and SSO, instance metadata). Setting
  `AWS_PROFILE` instead would redirect every other AWS tool too.

`user.signingkey` must be the KMS key's public key. Every signature is
checked against it before it's written, so a `sshsig-kms.key` naming a
different key fails the commit rather than producing a signature nobody
can verify.

A profile can get credentials any way the SDK supports. For example, a host
whose credentials another service refreshes into a file can use

```ini
[profile signing]
credential_process = /bin/cat /path/to/credentials.json
```

with the file in the `credential_process` JSON format.

## IAM policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SignGitCommits",
      "Effect": "Allow",
      "Action": "kms:Sign",
      "Resource": "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
      "Condition": {
        "StringEquals": {
          "kms:SigningAlgorithm": "ED25519_SHA_512",
          "kms:MessageType": "RAW"
        }
      }
    },
    {
      "Sid": "ReadSigningPublicKey",
      "Effect": "Allow",
      "Action": "kms:GetPublicKey",
      "Resource": "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
    }
  ]
}
```

For a P-256 key, the signing algorithm is `ECDSA_SHA_256`. The key's key
policy must let IAM policies grant access, as the default key policy does.
To grant access by alias instead of by key ARN, see AWS's
[Use aliases to control access to KMS keys](https://docs.aws.amazon.com/kms/latest/developerguide/alias-authorization.html).

## Limits

- Ed25519 and ECDSA P-256 keys only; no RSA.
- Linux and macOS.
- Only the signing git asks for (`-Y sign`). Every other call goes to
  `ssh-keygen` unchanged.
- Each signature has 8 seconds, from loading credentials to writing it, so
  a broken network fails a commit promptly instead of hanging it.
- `sshsig-kms` talks to nothing but AWS: KMS, and STS or SSO if your
  credentials need them. It never prints, caches or stores credentials.

## Development

```sh
go test ./...
```

The tests need `git` and `ssh-keygen`. The end-to-end test builds
`sshsig-kms` with the `fakekms` build tag, which signs with a local key in
place of KMS: in that build, `sshsig-kms.key` names a private key file. No
release binary can do that.

To test against real KMS, with credentials from the environment:

```sh
SSHSIG_KMS_TEST_KEY=arn:aws:kms:… go test -tags integration -run TestKMS -v
```

The design is in [docs/design.md](docs/design.md).

## License

MIT
````

- [ ] **Step 3: Update the design's status line**

In `docs/design.md`, line 3, replace `Status: proposed, 2026-10-04. Not built yet.` with:

```
Status: built, 2026-10-04; not yet released. The open questions at the end wait on the first run against real KMS.
```

- [ ] **Step 4: Check every command and name in the README against the code**

Run: `grep -n -E 'sshsig-kms\.(key|profile)|public-key|SSHSIG_KMS_TEST_KEY|fakekms|8 seconds' README.md`, and compare each against `main.go`, `sign.go`, `integration_test.go` and `.github/workflows/release.yml`. The release file name in the install snippet must match the workflow's `sshsig-kms_${version}_${os}_${arch}` with `version` lacking its `v`.

- [ ] **Step 5: Commit**

```bash
git add README.md docs/design.md
git commit -m "Document installing, setting up and configuring sshsig-kms" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 12: Pull request, signed-commit ruleset, first real-KMS run

**Files:**
- Modify: `docs/design.md` (open questions), only once the integration test has run.

**Interfaces:**
- Consumes: everything.
- Produces: the merged implementation on `main`, the ruleset, and answers to the design's open questions.

Every step here is outward-facing or needs AWS access, so each waits for Adam's go-ahead.

- [ ] **Step 1: Verify the whole branch**

```bash
test -z "$(gofmt -l .)" && go vet ./... && go vet -tags fakekms ./... && go vet -tags integration ./... && go test -race -count=1 ./... && go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
```
Expected: every command succeeds with no output except `go test`'s `ok`.

- [ ] **Step 2: Open the pull request (after Adam's go-ahead)**

```bash
git push -u origin implement
gh pr create --base main --title "Implement sshsig-kms" --body "$(cat <<'EOF'
Implements docs/design.md, following docs/superpowers/plans/2026-10-04-sshsig-kms.md.

- `-Y sign` signs with the KMS key in git config, verifies the signature against `user.signingkey`, and writes `<file>.sig`; every other call execs `ssh-keygen`.
- `public-key` and `version` commands.
- Tests: byte-for-byte against `ssh-keygen -Y sign` (Ed25519), ECDSA mpint edge cases through `ssh-keygen -Y verify`, malformed KMS answers, and git end to end against a `fakekms` build.
- CI on Linux amd64/arm64 and macOS; release workflow for `v*` tags (no tag pushed); Dependabot.

Not yet done: the integration test against real KMS (needs a key), and the signed-commit ruleset (after merge).

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 3: Watch CI**

Run: `gh pr checks --watch`
Expected: `test (ubuntu-latest)`, `test (ubuntu-24.04-arm)` and `test (macos-latest)` all pass. On a failure, read the log with `gh run view --log-failed`, then fix it on the branch.

- [ ] **Step 4: Merge (Adam's call)**

When Adam approves: `gh pr merge --rebase` (or `--squash`, as he prefers). Never `--merge`: history stays linear.

- [ ] **Step 5: Create the signed-commit ruleset (after confirming the payload with Adam)**

First check GitHub's documentation on how required signatures interact with rebase merges, since Adam merges by rebase or squash, and tell him what you find. Then show him this payload, and apply it only once he approves:

```bash
gh api --method POST repos/adamrothman/sshsig-kms/rulesets --input - <<'EOF'
{
  "name": "Signed commits",
  "target": "branch",
  "enforcement": "active",
  "conditions": {"ref_name": {"include": ["~ALL"], "exclude": []}},
  "rules": [{"type": "required_signatures"}]
}
EOF
gh api repos/adamrothman/sshsig-kms/rulesets --jq '.[] | {name, target, enforcement}'
```
Expected: `{"name":"Signed commits","target":"branch","enforcement":"active"}`.

- [ ] **Step 6: Run the integration test (with a key Adam provides or approves creating)**

Ask Adam for the ARN of an Ed25519 KMS key and the AWS profile to use, or for approval to create one (`aws kms create-key --key-spec ECC_NIST_EDWARDS25519 --key-usage SIGN_VERIFY`). Then:

```bash
SSHSIG_KMS_TEST_KEY=<arn> AWS_PROFILE=<profile> go test -tags integration -run TestKMS -v ./...
```
Expected: PASS, logging the public key, the first signature's latency, and the median and slowest of the next nine.

- [ ] **Step 7: Record the answers**

Update "Open questions" in `docs/design.md` with the results: the Ed25519 format confirmed (or not), and the measured latencies against the 8-second limit. Commit on a new branch and open a PR for it, as in Steps 2–4.
