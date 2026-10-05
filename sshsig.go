package main

import (
	"bytes"
	"encoding/base64"

	"golang.org/x/crypto/ssh"
)

// The SSH signature format, as ssh-keygen -Y sign writes it:
// https://github.com/openssh/openssh-portable/blob/V_10_0_P1/PROTOCOL.sshsig
const (
	sigMagic   = "SSHSIG"
	sigVersion = 1
	sigHashAlg = "sha512" // ssh-keygen's default
)

// signedData returns the bytes an SSH signature covers: the magic preamble,
// then the namespace, the reserved field, the hash algorithm and the
// message's hash.
func signedData(namespace string, digest []byte) []byte {
	return append([]byte(sigMagic), ssh.Marshal(struct {
		Namespace, Reserved, HashAlg string
		Hash                         []byte
	}{namespace, "", sigHashAlg, digest})...)
}

// armor encodes sig, made by pub over signedData(namespace, …), as the
// armored signature ssh-keygen writes to <file>.sig.
func armor(pub ssh.PublicKey, namespace string, sig *ssh.Signature) []byte {
	blob := append([]byte(sigMagic), ssh.Marshal(struct {
		Version                      uint32
		PublicKey                    []byte
		Namespace, Reserved, HashAlg string
		Signature                    []byte
	}{sigVersion, pub.Marshal(), namespace, "", sigHashAlg, ssh.Marshal(sig)})...)

	b64 := base64.StdEncoding.EncodeToString(blob)
	var out bytes.Buffer
	out.WriteString("-----BEGIN SSH SIGNATURE-----\n")
	for len(b64) > 70 {
		out.WriteString(b64[:70] + "\n")
		b64 = b64[70:]
	}
	out.WriteString(b64 + "\n")
	out.WriteString("-----END SSH SIGNATURE-----\n")
	return out.Bytes()
}
