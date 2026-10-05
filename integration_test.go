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
