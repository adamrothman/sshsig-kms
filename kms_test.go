package main

import (
	"bytes"
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
