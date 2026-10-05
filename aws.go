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
