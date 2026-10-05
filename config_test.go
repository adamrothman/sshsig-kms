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
