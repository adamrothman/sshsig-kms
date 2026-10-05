package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// execSSHKeygen replaces sshsig-kms with the ssh-keygen on PATH, run with
// the same arguments, so stdin, stdout and the exit status are
// ssh-keygen's. It returns only if that fails.
func execSSHKeygen(args []string) error {
	path, err := exec.LookPath("ssh-keygen")
	if err != nil {
		return fmt.Errorf("finding ssh-keygen: %v", err)
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if sameFile(path, self) {
		return fmt.Errorf("ssh-keygen on PATH (%s) is sshsig-kms itself; put OpenSSH's ssh-keygen ahead of it on PATH", path)
	}
	return syscall.Exec(path, append([]string{"ssh-keygen"}, args...), os.Environ())
}

// sameFile reports whether the paths a and b name the same file.
func sameFile(a, b string) bool {
	fa, errA := os.Stat(a)
	fb, errB := os.Stat(b)
	return errA == nil && errB == nil && os.SameFile(fa, fb)
}
