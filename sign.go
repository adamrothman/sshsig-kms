package main

import (
	"context"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// signRequest is a -Y sign call, as git makes it:
//
//	sshsig-kms -Y sign -n <namespace> -f <keyfile> [-U] <file>
type signRequest struct {
	namespace string
	keyFile   string // holds the public key from user.signingkey
	file      string // the file to sign
}

// isSign reports whether args are a -Y sign call.
func isSign(args []string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "-Y" && args[i+1] == "sign" {
			return true
		}
	}
	return false
}

// parseSignArgs parses a -Y sign call strictly: the flags git passes, each
// once, and one file to sign.
func parseSignArgs(args []string) (signRequest, error) {
	var req signRequest
	var mode string
	flags := map[string]*string{"-Y": &mode, "-n": &req.namespace, "-f": &req.keyFile}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-U" {
			// git adds -U for inline keys, telling ssh-keygen the private
			// key is in an agent. It means nothing here.
			continue
		}
		if value, ok := flags[arg]; ok {
			if i+1 == len(args) {
				return signRequest{}, fmt.Errorf("-Y sign: %s needs a value", arg)
			}
			if *value != "" {
				return signRequest{}, fmt.Errorf("-Y sign: %s given more than once", arg)
			}
			i++
			*value = args[i]
			continue
		}
		if strings.HasPrefix(arg, "-") || req.file != "" {
			return signRequest{}, fmt.Errorf("-Y sign: unexpected argument %q", arg)
		}
		req.file = arg
	}
	switch {
	case mode != "sign":
		return signRequest{}, errors.New("not a -Y sign call")
	case req.namespace == "":
		return signRequest{}, errors.New("-Y sign: missing -n <namespace>")
	case req.keyFile == "":
		return signRequest{}, errors.New("-Y sign: missing -f <keyfile>")
	case req.file == "":
		return signRequest{}, errors.New("-Y sign: missing the file to sign")
	}
	return req, nil
}

// readPublicKey reads the public key in keyFile, in authorized_keys format,
// ignoring its comment.
func readPublicKey(keyFile string) (ssh.PublicKey, error) {
	data, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return nil, fmt.Errorf("%s holds no SSH public key (user.signingkey must name the public key)", keyFile)
	}
	if _, err := lookupKeyType(pub.Type()); err != nil {
		return nil, err
	}
	return pub, nil
}

// hashFile returns the SHA-512 hash of the file at path.
func hashFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha512.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// runSign carries out a -Y sign call: it signs the file with the KMS key in
// git config, connecting with connect, and writes the signature to
// <file>.sig. It gives up after timeout.
func runSign(args []string, connect connectFunc, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := parseSignArgs(args)
	if err != nil {
		return err
	}
	pub, err := readPublicKey(req.keyFile)
	if err != nil {
		return err
	}
	keyID, err := gitConfig("sshsig-kms.key")
	if err != nil {
		return err
	}
	if keyID == "" {
		return errors.New("no KMS key configured: set sshsig-kms.key in git config")
	}
	profile, err := gitConfig("sshsig-kms.profile")
	if err != nil {
		return err
	}
	digest, err := hashFile(req.file)
	if err != nil {
		return err
	}

	client, err := connect(ctx, keyID, profile)
	if err != nil {
		return err
	}
	sig, err := kmsSign(ctx, client, keyID, pub, signedData(req.namespace, digest))
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("no signature within %v: %w", timeout, err)
		}
		return err
	}
	return os.WriteFile(req.file+".sig", armor(pub, req.namespace, sig), 0o666)
}
