# sshsig-kms design

Status: built, 2026-10-04; not yet released. The open questions at the end wait on the first run against real KMS.

`sshsig-kms` signs git commits and tags with an SSH key held in AWS KMS.
git runs it as `gpg.ssh.program`, in place of `ssh-keygen`. The private
key never leaves KMS, and nothing about it runs as a server: no
`ssh-agent`, no socket, just one KMS call per signature.

## Why

GitHub shows a commit as Verified when its signature checks out against a
signing key registered on the committer's account. SSH signatures are the
simplest kind to make, but `ssh-keygen -Y sign`, which git runs to make
them, can only sign with a private key it can read from a file or reach
through `ssh-agent`.

A key in KMS fits neither. It can't be exported, which is the point: who
may sign is decided by IAM, every signature is logged by CloudTrail, and
access ends when IAM says so, with no copy of the key left behind. The
existing ways to use one for SSH all go through an agent socket
([glassechidna/go-kms-signer](https://github.com/glassechidna/go-kms-signer)'s
`kms-ssh-agent`, or the
[aws-kms-pkcs11](https://github.com/JackOfMostTrades/aws-kms-pkcs11)
provider loaded into an agent; `ssh-keygen -Y sign` can't use a PKCS#11
provider directly). A socket rules them out wherever commands run
sandboxed, such as Claude Code's sandbox on Linux, which blocks Unix
sockets but lets commands reach allowed HTTPS hosts through a proxy.

The first user is a set of Claude Code agents on a Linux host, whose
commits are signed for a GitHub machine account with a key in KMS
(adamrothman/personal-infra, `docs/agent-github-identity.md`). Nothing in
the tool is specific to that.

## Goals

- Sign with a KMS key wherever git runs `gpg.ssh.program`, including in
  a sandbox that allows only HTTPS to AWS.
- Produce exactly what `ssh-keygen -Y sign` produces, so git, OpenSSH
  and GitHub verify it like any other SSH signature.
- Configure through git, in one place.
- Fail closed: never write a signature that doesn't verify against the
  key git asked for.

Not goals: RSA keys, an `ssh-agent`, key providers other than AWS KMS,
and signing outside git's `gpg.ssh.program` contract.

## Interface

### Signing

git signs by running ([git
gpg-interface.c](https://github.com/git/git/blob/v2.47.0/gpg-interface.c#L1072-L1100),
unchanged in substance through v2.56):

    sshsig-kms -Y sign -n <namespace> -f <keyfile> [-U] <file>

- `<keyfile>` holds the public key from `user.signingkey`: the file it
  names, or, for an inline key (`key::ssh-ed25519 AAAA…`), a temporary
  file git writes the value to. git adds `-U` for inline keys, telling
  `ssh-keygen` the private half is in an agent. `sshsig-kms` accepts and
  ignores it.
- `<namespace>` is `git` for commits and tags.
- The signature goes to `<file>.sig`, which git reads and deletes. git
  ignores stdout, and shows stderr if the exit status isn't zero.

A `-Y sign` call with any other arguments fails, naming the argument it
doesn't understand. Every call that isn't `-Y sign` is handed on:
`sshsig-kms` replaces itself with `ssh-keygen` (`execve`, argv
unchanged), so stdin, stdout and the exit status are `ssh-keygen`'s. That covers git's verification calls
(`-Y find-principals`, `-Y check-novalidate` and `-Y verify`, with the
payload on stdin), so `git verify-commit` and `git log --show-signature`
work as usual. `ssh-keygen` is found on `PATH`; if that resolves to
`sshsig-kms` itself, it fails instead of looping. The one exception is a
call with no arguments, which git never makes: instead of starting
`ssh-keygen`'s interactive key generation, it fails with one line naming
its own commands and pointing to the README.

### Commands of its own

- `sshsig-kms public-key <arn>` prints the KMS key's public half as an
  SSH public key line (`ssh-ed25519 AAAA…`). It checks the key is
  `SIGN_VERIFY` with a supported key spec, and is what you register on
  GitHub and point `user.signingkey` at. It needs `kms:GetPublicKey`.
- `sshsig-kms version` prints the version it was built as.

## Configuration

Everything is in git config, in a section of its own, read with `git
config --get`, so it has git's scoping: global or per repository,
conditional includes, and `git -c` (which git passes on to commands it
runs):

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

- `sshsig-kms.key` (required): the KMS key's ARN, or an alias ARN. The
  region comes from the ARN, so there's no region setting.
- `sshsig-kms.profile` (optional): an AWS profile for `sshsig-kms`
  alone. Without it, credentials come from the AWS SDK's default chain
  (environment, shared config and SSO, IMDS). `AWS_PROFILE` would also
  redirect every other AWS tool, which this avoids.

`user.signingkey` and `sshsig-kms.key` can't silently disagree: every
signature is checked against `user.signingkey` before it's written
(below), so a key ARN naming a different key fails the signing.

A profile can supply credentials any way the SDK supports. For example,
a host whose credentials are refreshed into a file by another service
can use `credential_process = /bin/cat <file>`, with the file in the
`credential_process` JSON format.

## Signing in detail

1. Parse the arguments strictly: exactly the signing form above, with
   one file to sign.
2. Read the public key from `<keyfile>` (the first line, in
   `authorized_keys` format; the comment is ignored). It must be one of
   the supported types.
3. Read `sshsig-kms.key` and `sshsig-kms.profile`.
4. Build the data to sign, as OpenSSH does ([PROTOCOL.sshsig](https://github.com/openssh/openssh-portable/blob/V_10_0_P1/PROTOCOL.sshsig)):

       "SSHSIG" ‖ string(namespace) ‖ string("") ‖ string("sha512") ‖ string(SHA-512(file))

   SHA-512 is `ssh-keygen`'s default. For the namespace `git` this is 95
   bytes, well within KMS's 4,096-byte limit for raw messages.
5. Ask KMS to sign it (`Sign`, `MessageType: RAW`), with the algorithm
   the key type calls for (table below).
6. Encode KMS's output as an SSH signature.
7. Verify that signature against the public key from `<keyfile>`. If it
   doesn't verify, fail: the ARN names a different key, or KMS returned
   something unexpected.
8. Write the signature blob, armored, to `<file>.sig`:

       "SSHSIG" ‖ uint32(1) ‖ string(public key) ‖ string(namespace) ‖ string("") ‖ string("sha512") ‖ string(signature)

   base64 wrapped at 70 columns between `-----BEGIN SSH SIGNATURE-----`
   and `-----END SSH SIGNATURE-----`, as `ssh-keygen` writes it.

| SSH key type | KMS key spec | KMS signing algorithm | KMS returns | SSH signature |
|---|---|---|---|---|
| `ssh-ed25519` | `ECC_NIST_EDWARDS25519` | `ED25519_SHA_512` (PureEdDSA over the message) | the 64-byte signature | `string("ssh-ed25519") ‖ string(64 bytes)` |
| `ecdsa-sha2-nistp256` | `ECC_NIST_P256` | `ECDSA_SHA_256` (KMS hashes the message with SHA-256) | DER `(r, s)` | `string("ecdsa-sha2-nistp256") ‖ string(mpint(r) ‖ mpint(s))` |

KMS has signed with Ed25519 since 2025-11-07. AWS documents the DER
encoding of ECDSA signatures (ANSI X9.62, RFC 3279) but not the format of
Ed25519 ones; the 64 raw bytes are an inference, which step 7 checks on
every signature and the integration test confirms.

The SSHSIG encoding is written here, about fifty lines on top of
`golang.org/x/crypto/ssh`, rather than taken from a library: the format
is small, fixed, and the part most worth testing directly.

### Time limit

The whole signing, from loading credentials to writing the file, has 8
seconds. KMS should answer in well under one; the margin covers fetching
credentials, a cold connection through a proxy, and the SDK's retries of
throttling and transient errors. A broken network then fails a commit
promptly instead of hanging it.

### Errors

Every failure exits with status 1 and one line on stderr, beginning
`sshsig-kms:` and saying what to fix, for example:

- `sshsig-kms: no KMS key configured: set sshsig-kms.key in git config`
- `sshsig-kms: key type ssh-rsa is not supported (ssh-ed25519, ecdsa-sha2-nistp256)`
- `sshsig-kms: KMS key arn:aws:kms:…:key/… did not produce a signature for the key in user.signingkey`
- AWS's own errors (expired credentials, access denied, a disabled key),
  passed through after the prefix.

No message contains the text `usage:`: when git sees it in a failed
signer's stderr, it adds a hint that OpenSSH is too old, which would
mislead here.

### What it never does

- Write anything but `<file>.sig`, or print anything to stdout when
  signing.
- Print, cache or store credentials.
- Talk to anything but AWS: KMS, and whatever the credential chain uses
  (STS, SSO).
- Write a signature it hasn't verified.

## Setting it up

The README walks through this; in outline:

1. Create the key: `aws kms create-key --key-spec ECC_NIST_EDWARDS25519
   --key-usage SIGN_VERIFY`.
2. Allow whoever signs `kms:Sign` on it, ideally with a
   `kms:SigningAlgorithm` condition, and allow `kms:GetPublicKey` for
   setup.
3. `sshsig-kms public-key <arn> > ~/.ssh/kms-signing.pub`.
4. Add that key on GitHub as a **signing** key (not an authentication
   key), on the account whose email the commits use as committer.
5. Set the git config above. To verify locally too, add the key to an
   allowed-signers file (`gpg.ssh.allowedSignersFile`).

## Testing

- **Against OpenSSH as the reference.** With a local key standing in for
  KMS, Ed25519 output must be byte-identical to `ssh-keygen -Y sign`'s:
  Ed25519 is deterministic, so any encoding mistake shows. ECDSA output
  must pass `ssh-keygen -Y verify`, including signatures whose `r` or `s`
  has leading zero bytes or its high bit set, which the mpint encoding
  must handle.
- **KMS behind an interface.** Tests feed it what KMS returns (DER for
  ECDSA, 64 bytes for Ed25519) and malformed variants, and check that a
  signature from a different key is refused.
- **End to end with git.** A temporary repository, a real `git commit
  -S`, then `git verify-commit` and `git log --show-signature`. The
  binary under test signs with a local key, a substitution compiled in
  only under a test build tag (`fakekms`), so no released binary can be
  pointed at a local key.
- **Against real KMS.** An integration test behind the `integration`
  build tag, run by hand with a key ARN and credentials from the
  environment. It confirms the Ed25519 format and measures latency. CI
  has no AWS access.

## CI

On every push to `main` and every pull request, on Linux (amd64 and
arm64 runners) and macOS: `gofmt` check, `go vet`, and `go test -race
./...`, including the end-to-end git test. Go's version comes from
`go.mod`, so CI and releases use the same toolchain.

## Releases

A `v*` tag builds the release:

- static binaries (`CGO_ENABLED=0`, `-trimpath`, the version stamped in
  with `-ldflags`) for Linux and macOS, amd64 and arm64, as plain files
  named `sshsig-kms_<version>_<os>_<arch>`;
- `SHA256SUMS`;
- GitHub artifact attestations (`actions/attest-build-provenance`), so
  anyone can check with `gh attestation verify` that a binary was built
  by this repository's workflow;
- a GitHub release carrying them.

Consumers pin a version and its checksum. Versions follow semver. The
first tag, v0.1.0, waits for Adam's go-ahead.

## Repository

- `README.md`: what it is and why, setup, configuration, an example IAM
  policy, and limits.
- `LICENSE`: MIT.
- Dependabot for Go modules and GitHub Actions.
- Signed commits required on every branch.
- Go module `github.com/adamrothman/sshsig-kms`. Dependencies: the AWS
  SDK for Go v2 (`config`, `service/kms`) and `golang.org/x/crypto/ssh`.
  The SDK's HTTP client honours `HTTPS_PROXY`, which a sandbox's proxy
  relies on.

## Implementation notes

Found while designing, for whoever builds it:

- **Tests must isolate git from the developer's own configuration.** A
  global `gpg.ssh.program`, such as 1Password's signer, takes precedence
  in ways a test repository's local config doesn't undo: in one trial it
  received the test's throwaway key and refused it. Every test that runs
  git sets `GIT_CONFIG_GLOBAL` to a file of its own and
  `GIT_CONFIG_NOSYSTEM=1`, so tests behave the same on a laptop as in CI.
- **Converting KMS's public key.** `GetPublicKey` returns a DER
  SubjectPublicKeyInfo. `x509.ParsePKIXPublicKey`, then
  `ssh.NewPublicKey`, then `ssh.MarshalAuthorizedKey` turn it into the
  SSH public key line, for Ed25519 and P-256 alike (checked offline).
  Don't rely on `ssh-keygen -i -m PKCS8` instead: OpenSSH 10.3 on macOS
  can't import an Ed25519 key in that form.

## Alternatives considered

- **An `ssh-agent` backed by KMS**, so `ssh-keygen` itself signs. Needs a
  socket, which sandboxes block, and a process to keep running.
- **A PKCS#11 provider for KMS.** `ssh-keygen -Y sign` doesn't load
  PKCS#11 providers (`-D` only applies to other operations), so it would
  still go through an agent.
- **Sigstore's gitsign**, which signs without a long-lived key. GitHub
  doesn't trust Sigstore's certificate authority, so its commits show as
  Unverified.
- **The key's ARN as the comment on the public key**, so that
  `user.signingkey` alone configures it. It works, including for inline
  keys, but a comment is free text by convention, and a harmless-looking
  edit would break signing. A section of git config says what it is.
- **Environment variables for configuration.** They have to reach every
  process that runs git, including long-running ones that would need a
  restart to see a change; git config is read fresh on every run.
- **An SSHSIG library** (`github.com/hiddeco/sshsig`). It would work; the
  encoding is small enough, and central enough, to own and test here.

## Open questions

- The format of KMS's Ed25519 signatures, settled by the first
  integration test run (step 7 of signing guards it meanwhile).
- KMS's latency from where it runs, which the integration test measures;
  the 8-second limit changes if the numbers call for it.
