package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// Import an existing PFX/P12 as well as the separate PEM files.
// OpenSSL is called with the import password only in an environment variable;
// plaintext temporary files are not created (the output stays in memory).
func manualParsePFX(content []byte, password string) (certInput, error) {
	var empty certInput
	if len(content) == 0 || len(content) > 2<<20 {
		return empty, errors.New("PFX-Datei fehlt oder ist zu groß")
	}
	scratch, err := os.MkdirTemp(os.TempDir(), "certwatch-pfx-")
	if err != nil {
		return empty, err
	}
	defer os.RemoveAll(scratch)
	file := filepath.Join(scratch, "import.pfx")
	if err := os.WriteFile(file, content, 0600); err != nil {
		return empty, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	run := func(legacy bool) ([]byte, error) {
		args := []string{"pkcs12", "-in", file, "-nodes", "-passin", "env:CERTWATCH_IMPORT_PASSWORD"}
		if legacy {
			args = append(args, "-legacy")
		}
		cmd := exec.CommandContext(ctx, "openssl", args...)
		cmd.Env = append(os.Environ(), "CERTWATCH_IMPORT_PASSWORD="+password)
		var output bytes.Buffer
		// Never include command output in errors, as output contains private keys.
		cmd.Stdout = &output
		cmd.Stderr = nil
		if err := cmd.Run(); err != nil {
			return nil, errors.New("PFX konnte nicht entschlüsselt werden (Passwort/Format prüfen)")
		}
		if output.Len() > 8<<20 {
			return nil, errors.New("PFX-Ausgabe zu groß")
		}
		return output.Bytes(), nil
	}
	decoded, err := run(false)
	if err != nil && ctx.Err() == nil {
		decoded, err = run(true)
	}
	if err != nil {
		return empty, err
	}
	var certs []*x509.Certificate
	var keyPEM []byte
	for len(decoded) > 0 {
		b, rest := pem.Decode(decoded)
		if b == nil {
			break
		}
		decoded = rest
		if b.Type == "CERTIFICATE" {
			c, e := x509.ParseCertificate(b.Bytes)
			if e != nil {
				return empty, e
			}
			certs = append(certs, c)
		} else if b.Type == "PRIVATE KEY" || b.Type == "RSA PRIVATE KEY" || b.Type == "EC PRIVATE KEY" {
			if len(keyPEM) > 0 {
				return empty, errors.New("PFX enthält mehr als einen Private Key")
			}
			keyPEM = pem.EncodeToMemory(b)
		}
	}
	if len(keyPEM) == 0 || len(certs) == 0 {
		return empty, errors.New("PFX benötigt einen Private Key und mindestens ein Zertifikat")
	}
	block, _ := pem.Decode(keyPEM)
	var key crypto.PrivateKey
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	}
	if err != nil {
		return empty, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return empty, errors.New("Private Key nicht unterstützt")
	}
	pub, e := x509.MarshalPKIXPublicKey(signer.Public())
	if e != nil {
		return empty, e
	}
	leafIndex := -1
	for i, c := range certs {
		candidate, e := x509.MarshalPKIXPublicKey(c.PublicKey)
		if e == nil && bytes.Equal(pub, candidate) {
			leafIndex = i
			break
		}
	}
	if leafIndex < 0 {
		return empty, errors.New("PFX-Zertifikat und Private Key stimmen nicht überein")
	}
	leaf := certs[leafIndex]
	remaining := append([]*x509.Certificate{}, certs[:leafIndex]...)
	remaining = append(remaining, certs[leafIndex+1:]...)
	current := leaf
	var chain, root []byte
	for len(remaining) > 0 {
		parentIndex := -1
		for i, c := range remaining {
			if current.CheckSignatureFrom(c) == nil && !bytes.Equal(current.Raw, c.Raw) {
				parentIndex = i
				break
			}
		}
		if parentIndex < 0 {
			return empty, fmt.Errorf("PFX-Zertifikatskette unvollständig oder unsortierbar (%d weitere Zertifikate)", len(remaining))
		}
		parent := remaining[parentIndex]
		remaining = append(remaining[:parentIndex], remaining[parentIndex+1:]...)
		cpem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: parent.Raw})
		if len(remaining) == 0 && parent.CheckSignatureFrom(parent) == nil {
			root = cpem
		} else {
			chain = append(chain, cpem...)
		}
		current = parent
	}
	return manualParseInput(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}), chain, keyPEM, root)
}
