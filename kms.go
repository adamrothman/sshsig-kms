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
