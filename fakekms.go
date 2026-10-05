//go:build fakekms

package main

import "context"

// newKMS, in a fakekms build, signs with a local key instead of KMS:
// sshsig-kms.key names an OpenSSH private key file. Only tests make this
// build, to run git against the binary end to end.
func newKMS(ctx context.Context, keyID, profile string) (kmsAPI, error) {
	return connectLocal(ctx, keyID, profile)
}
