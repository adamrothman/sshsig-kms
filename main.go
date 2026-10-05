// Command sshsig-kms signs git commits and tags with an SSH key held in
// AWS KMS. git runs it as gpg.ssh.program, in place of ssh-keygen: it
// makes -Y sign calls' signatures itself and hands every other call to
// ssh-keygen. See docs/design.md.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strings"
)

// version is the version sshsig-kms was built as, which the release build
// sets with -ldflags "-X main.version=0.1.0".
var version string

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, errorLine(err))
		os.Exit(1)
	}
}

// run carries out the command in args, writing any output to stdout.
func run(args []string, stdout io.Writer) error {
	switch {
	case len(args) > 0 && args[0] == "version":
		if len(args) > 1 {
			return errors.New("version takes no arguments")
		}
		_, err := fmt.Fprintln(stdout, buildVersion())
		return err
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
