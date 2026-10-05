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
