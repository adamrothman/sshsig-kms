package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
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
