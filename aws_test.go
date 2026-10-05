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
