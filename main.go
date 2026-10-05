// Command sshsig-kms signs git commits and tags with an SSH key held in
// AWS KMS. git runs it as gpg.ssh.program, in place of ssh-keygen: it
// makes -Y sign calls' signatures itself and hands every other call to
// ssh-keygen. See docs/design.md.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// version is the version sshsig-kms was built as, which the release build
// sets with -ldflags "-X main.version=0.1.0".
var version string

// timeLimit bounds each run's work, from loading credentials to writing its
// output, so a broken network fails a commit promptly instead of hanging it.
const timeLimit = 8 * time.Second

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, errorLine(err))
		os.Exit(1)
	}
}

// run carries out the command in args, writing any output to stdout.
func run(args []string, stdout io.Writer) error {
	switch {
	case len(args) == 0:
		// ssh-keygen with no arguments would start generating a key.
		return errors.New("no command given: git runs sshsig-kms as gpg.ssh.program, " +
			"and its own commands are public-key <arn> and version; see https://github.com/adamrothman/sshsig-kms")
	case args[0] == "version":
		if len(args) > 1 {
			return errors.New("version takes no arguments")
		}
		_, err := fmt.Fprintln(stdout, buildVersion())
		return err
	case args[0] == "public-key":
		if len(args) != 2 {
			return errors.New("public-key takes one argument: the KMS key's ARN")
		}
		return runPublicKey(args[1], newKMS, timeLimit, stdout)
	case isSign(args):
		return runSign(args, newKMS, timeLimit)
	default:
		return execSSHKeygen(args)
	}
}

// buildVersion returns the version sshsig-kms was built as.
func buildVersion() string {
	if version != "" {
		return version
	}
	// go install records the version of the module it built.
	if info, ok := debug.ReadBuildInfo(); ok {
		return strings.TrimPrefix(info.Main.Version, "v")
	}
	return "unknown"
}

// errorLine formats err as the one line sshsig-kms prints when it fails,
// which git shows the user. AWS's errors can run over several lines.
func errorLine(err error) string {
	return "sshsig-kms: " + strings.Join(strings.Fields(err.Error()), " ")
}

// runPublicKey prints the public half of the KMS key keyID as an SSH public
// key line, connecting with the AWS profile in sshsig-kms.profile if it's
// set. It gives up after timeout.
func runPublicKey(keyID string, connect connectFunc, timeout time.Duration, stdout io.Writer) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	profile, err := gitConfig("sshsig-kms.profile")
	if err != nil {
		return err
	}
	client, err := connect(ctx, keyID, profile)
	if err != nil {
		return err
	}
	pub, err := kmsPublicKey(ctx, client, keyID)
	if err != nil {
		return err
	}
	_, err = stdout.Write(ssh.MarshalAuthorizedKey(pub))
	return err
}
