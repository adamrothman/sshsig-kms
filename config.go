package main

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
)

// gitConfig returns the value of the git config setting name, or "" if it
// isn't set. It reads with git config --get, so it has git's scoping:
// global or per repository, conditional includes, and git -c.
func gitConfig(name string) (string, error) {
	out, err := exec.Command("git", "config", "--get", name).Output()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if exitErr.ExitCode() == 1 { // the setting isn't set
			return "", nil
		}
		if msg := strings.TrimSpace(string(exitErr.Stderr)); msg != "" {
			err = errors.New(msg)
		}
	}
	if err != nil {
		return "", fmt.Errorf("reading %s from git config: %v", name, err)
	}
	return strings.TrimSpace(string(out)), nil
}

// keyRegion returns the AWS region of a KMS key ARN or alias ARN.
func keyRegion(keyID string) (string, error) {
	a, err := arn.Parse(keyID)
	if err != nil || a.Service != "kms" || a.Region == "" ||
		!(strings.HasPrefix(a.Resource, "key/") || strings.HasPrefix(a.Resource, "alias/")) {
		return "", fmt.Errorf("%s is not a KMS key ARN or alias ARN (arn:aws:kms:<region>:<account>:key/<key-id>)", keyID)
	}
	return a.Region, nil
}
