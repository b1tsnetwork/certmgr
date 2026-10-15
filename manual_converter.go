// Derived from the user-provided UCNG Certificate Manager converter (AGPL-3.0).
// Original license and notices: third_party/ucng/.
package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type certInput struct {
	leaf   *x509.Certificate
	chain  []*x509.Certificate
	root   *x509.Certificate
	key    crypto.PrivateKey
	keyPEM []byte
}
type artifact struct {
	Name    string `json:"name"`
	SHA256  string `json:"sha256"`
	Size    int    `json:"size"`
	Private bool   `json:"private"`
}
type certMeta struct {
	Name        string     `json:"name"`
	Version     string     `json:"version"`
	Fingerprint string     `json:"fingerprint_sha256"`
	DNSNames    []string   `json:"dns_names"`
	Subject     string     `json:"subject"`
	Issuer      string     `json:"issuer"`
	NotBefore   time.Time  `json:"not_before"`
	NotAfter    time.Time  `json:"not_after"`
	Published   time.Time  `json:"published"`
	Artifacts   []artifact `json:"artifacts"`
}

func manualDecodeCerts(b []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for len(bytes.TrimSpace(b)) > 0 {
		block, rest := pem.Decode(b)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, errors.New("ungültige PEM-Zertifikatskette")
		}
		c, e := x509.ParseCertificate(block.Bytes)
		if e != nil {
			return nil, e
		}
		certs = append(certs, c)
		b = rest
	}
	return certs, nil
}
func manualParseInput(cert, chain, key, root []byte) (certInput, error) {
	var out certInput
	c, e := manualDecodeCerts(cert)
	if e != nil || len(c) != 1 {
		return out, errors.New("cert.pem muss exakt ein gültiges Leaf-Zertifikat enthalten")
	}
	out.leaf = c[0]
	out.chain, e = manualDecodeCerts(chain)
	if e != nil {
		return out, e
	}
	if len(root) > 0 {
		r, e := manualDecodeCerts(root)
		if e != nil || len(r) != 1 {
			return out, errors.New("Root-Datei muss exakt ein PEM-Zertifikat enthalten")
		}
		out.root = r[0]
	}
	block, rest := pem.Decode(key)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return out, errors.New("privkey.pem enthält kein einzelnes PEM-Key")
	}
	switch block.Type {
	case "PRIVATE KEY":
		out.key, e = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		out.key, e = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		out.key, e = x509.ParseECPrivateKey(block.Bytes)
	default:
		return out, fmt.Errorf("nicht unterstütztes Key-Format %q (Certbot muss unverschlüsselten Key liefern)", block.Type)
	}
	if e != nil {
		return out, e
	}
	signer, ok := out.key.(crypto.Signer)
	if !ok {
		return out, errors.New("Private Key unterstützt keine Public-Key-Ableitung")
	}
	pubA, e := x509.MarshalPKIXPublicKey(signer.Public())
	if e != nil {
		return out, e
	}
	pubB, e := x509.MarshalPKIXPublicKey(out.leaf.PublicKey)
	if e != nil {
		return out, e
	}
	if !bytes.Equal(pubA, pubB) {
		return out, errors.New("Private Key stimmt nicht mit Leaf-Zertifikat überein")
	}
	if time.Now().Before(out.leaf.NotBefore) {
		return out, errors.New("Zertifikat ist noch nicht gültig")
	}
	if time.Now().After(out.leaf.NotAfter) {
		return out, errors.New("Zertifikat ist abgelaufen; vorhandene letzte Version bleibt erhalten")
	}
	previous := out.leaf
	for i, ca := range out.chain {
		if time.Now().Before(ca.NotBefore) || time.Now().After(ca.NotAfter) {
			return out, fmt.Errorf("Intermediate %d außerhalb der Gültigkeit", i+1)
		}
		if !ca.IsCA {
			return out, fmt.Errorf("Intermediate %d ist keine CA", i+1)
		}
		if e := previous.CheckSignatureFrom(ca); e != nil {
			return out, fmt.Errorf("Zertifikatskette bei Intermediate %d ungültig: %w", i+1, e)
		}
		previous = ca
	}
	if out.root != nil {
		if time.Now().Before(out.root.NotBefore) || time.Now().After(out.root.NotAfter) {
			return out, errors.New("Root-Zertifikat außerhalb der Gültigkeit")
		}
		if e := previous.CheckSignatureFrom(out.root); e != nil {
			return out, fmt.Errorf("optionales Root passt nicht zur Kette: %w", e)
		}
	}
	out.keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustPKCS8(out.key)})
	return out, nil
}
func mustPKCS8(k any) []byte {
	b, e := x509.MarshalPKCS8PrivateKey(k)
	if e != nil {
		panic(e)
	}
	return b
}
func certPEM(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}
func joinPEM(parts ...[]byte) []byte {
	var b []byte
	for _, p := range parts {
		if len(p) > 0 {
			b = append(b, p...)
		}
	}
	return b
}
func callSSL(dir string, password string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "openssl", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "CERTMGR_PFX_PASSWORD="+password)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("OpenSSL %s fehlgeschlagen: %w (%s)", args[0], err, strings.TrimSpace(output.String()))
	}
	return nil
}
func manualConvert(scratch, name, id string, in certInput) (map[string][]byte, certMeta, error) {
	meta := certMeta{Name: name, Version: id, Fingerprint: manualHashHex(in.leaf.Raw), DNSNames: in.leaf.DNSNames, Subject: in.leaf.Subject.String(), Issuer: in.leaf.Issuer.String(), NotBefore: in.leaf.NotBefore, NotAfter: in.leaf.NotAfter, Published: time.Now().UTC()}
	files := map[string][]byte{}
	add := func(n string, b []byte, private bool) {
		files[n] = b
		meta.Artifacts = append(meta.Artifacts, artifact{Name: n, SHA256: manualHashHex(b), Size: len(b), Private: private})
	}
	leaf := certPEM(in.leaf)
	add("leaf.pem", leaf, false)
	add("cert.pem", leaf, false)
	add("leaf.der", in.leaf.Raw, false)
	add("leaf.crt", leaf, false)
	add("leaf.cer", in.leaf.Raw, false)
	add("leaf-base64.cer", leaf, false)
	pubDER, e := x509.MarshalPKIXPublicKey(in.leaf.PublicKey)
	if e != nil {
		return nil, meta, e
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	add("public-key.pem", pubPEM, false)
	add("public-key.der", pubDER, false)
	add("public.key", pubPEM, false)
	var intermediateParts [][]byte
	var info strings.Builder
	info.WriteString(certInfo("LEAF", in.leaf))
	for i, c := range in.chain {
		p := certPEM(c)
		intermediateParts = append(intermediateParts, p)
		add(fmt.Sprintf("intermediate-%02d.pem", i+1), p, false)
		add(fmt.Sprintf("intermediate-%02d.der", i+1), c.Raw, false)
		info.WriteString(certInfo(fmt.Sprintf("INTERMEDIATE %d", i+1), c))
	}
	chain := joinPEM(intermediateParts...)
	if len(chain) > 0 {
		add("chain-intermediates.pem", chain, false)
	}
	fullchain := joinPEM(leaf, chain)
	add("fullchain.pem", fullchain, false)
	add("chain.pem", chain, false)
	add("fullchain.crt", fullchain, false)
	var cabundle, fullroot []byte
	if in.root != nil {
		r := certPEM(in.root)
		add("root-ca.pem", r, false)
		add("root-ca.der", in.root.Raw, false)
		cabundle = joinPEM(chain, r)
		fullroot = joinPEM(fullchain, r)
		add("ca-bundle.pem", cabundle, false)
		add("fullchain-with-root.pem", fullroot, false)
		add("fullchain-with-root.crt", fullroot, false)
		info.WriteString(certInfo("ROOT CA", in.root))
	}
	add("certificate-info.txt", []byte(info.String()), false)
	add("chain-verification.txt", []byte("Schlüsselpaar und die angegebenen CA-Signaturen wurden geprüft. Die Vertrauenswürdigkeit einer Root-CA ist gesondert anhand des Client-Truststores zu prüfen.\n"), false)
	add("private-key.pem", in.keyPEM, true)
	add("privkey.pem", in.keyPEM, true)
	add("key-leaf.pem", joinPEM(in.keyPEM, leaf), true)
	add("key-fullchain.pem", joinPEM(in.keyPEM, fullchain), true)
	if in.root != nil {
		add("key-fullchain-with-root.pem", joinPEM(in.keyPEM, fullroot), true)
	}
	// Für OpenSSL werden Klartext-Zwischendateien nur im konfigurierten Scratch-Verzeichnis angelegt.
	// Im Docker-Deployment liegt dieses ausschließlich auf tmpfs.
	tmp, e := os.MkdirTemp(scratch, "cert-convert-")
	if e != nil {
		return nil, meta, e
	}
	defer os.RemoveAll(tmp)
	_ = os.Chmod(tmp, 0700)
	write := func(n string, b []byte) error { return os.WriteFile(filepath.Join(tmp, n), b, 0600) }
	read := func(n string) ([]byte, error) { return os.ReadFile(filepath.Join(tmp, n)) }
	if e = write("key.pem", in.keyPEM); e != nil {
		return nil, meta, e
	}
	if e = write("leaf.pem", leaf); e != nil {
		return nil, meta, e
	}
	if e = write("fullchain.pem", fullchain); e != nil {
		return nil, meta, e
	}
	if len(chain) > 0 {
		if e = write("chain.pem", chain); e != nil {
			return nil, meta, e
		}
	}
	if in.root != nil {
		if e = write("ca-bundle.pem", cabundle); e != nil {
			return nil, meta, e
		}
		if e = write("fullroot.pem", fullroot); e != nil {
			return nil, meta, e
		}
	}
	pwBytes := make([]byte, 32)
	if _, e = rand.Read(pwBytes); e != nil {
		return nil, meta, e
	}
	password := base64.RawURLEncoding.EncodeToString(pwBytes)
	add("pfx-password.txt", []byte(password+"\n"), true)
	pfx := func(basename, certfile string, certs string) error {
		args := []string{"pkcs12", "-export", "-inkey", "key.pem", "-in", certfile, "-out", basename + ".pfx", "-name", name, "-passout", "env:CERTMGR_PFX_PASSWORD"}
		if certs != "" {
			args = append(args, "-certfile", certs)
		}
		if os.Getenv("LEGACY_PFX") == "true" {
			args = append(args, "-legacy")
		}
		if e := callSSL(tmp, password, args...); e != nil {
			return e
		}
		b, e := read(basename + ".pfx")
		if e != nil {
			return e
		}
		add(basename+".pfx", b, true)
		add(basename+".p12", b, true)
		return nil
	}
	if e = pfx("leaf-only", "leaf.pem", ""); e != nil {
		return nil, meta, e
	}
	if len(chain) > 0 {
		if e = pfx("leaf-chain", "leaf.pem", "chain.pem"); e != nil {
			return nil, meta, e
		}
	}
	if in.root != nil {
		if e = pfx("leaf-fullchain-with-root", "leaf.pem", "ca-bundle.pem"); e != nil {
			return nil, meta, e
		}
	}
	p7 := func(basename, input string) error {
		for _, v := range []struct{ format, filename string }{{"DER", basename + ".p7b"}, {"PEM", basename + ".pkcs7.pem"}} {
			if e := callSSL(tmp, password, "crl2pkcs7", "-nocrl", "-certfile", input, "-outform", v.format, "-out", v.filename); e != nil {
				return e
			}
			b, e := read(v.filename)
			if e != nil {
				return e
			}
			add(v.filename, b, false)
			if v.format == "DER" {
				add(basename+".p7c", b, false)
			}
		}
		return nil
	}
	if e = p7("leaf-chain", "fullchain.pem"); e != nil {
		return nil, meta, e
	}
	if in.root != nil {
		if e = p7("leaf-fullchain-with-root", "fullroot.pem"); e != nil {
			return nil, meta, e
		}
	}
	for _, f := range []string{"PEM", "DER"} {
		fn := "private-key-pkcs8-encrypted." + strings.ToLower(f)
		if e := callSSL(tmp, password, "pkcs8", "-topk8", "-in", "key.pem", "-outform", f, "-v2", "aes-256-cbc", "-passout", "env:CERTMGR_PFX_PASSWORD", "-out", fn); e != nil {
			return nil, meta, e
		}
		b, e := read(fn)
		if e != nil {
			return nil, meta, e
		}
		add(fn, b, true)
		if os.Getenv("EXPORT_UNENCRYPTED_KEYS") == "true" {
			fn = "private-key-pkcs8-UNENCRYPTED." + strings.ToLower(f)
			if e := callSSL(tmp, password, "pkcs8", "-topk8", "-nocrypt", "-in", "key.pem", "-outform", f, "-out", fn); e != nil {
				return nil, meta, e
			}
			b, e := read(fn)
			if e != nil {
				return nil, meta, e
			}
			add(fn, b, true)
		}
	}
	sort.Slice(meta.Artifacts, func(i, j int) bool { return meta.Artifacts[i].Name < meta.Artifacts[j].Name })
	var sums strings.Builder
	for _, a := range meta.Artifacts {
		sums.WriteString(a.SHA256 + "  " + a.Name + "\n")
	}
	add("SHA256SUMS.txt", []byte(sums.String()), true)
	sort.Slice(meta.Artifacts, func(i, j int) bool { return meta.Artifacts[i].Name < meta.Artifacts[j].Name })
	return files, meta, nil
}
func certInfo(label string, c *x509.Certificate) string {
	fingerprint := sha256.Sum256(c.Raw)
	return fmt.Sprintf("========== %s ==========\nSubject: %s\nIssuer: %s\nSerial: %s\nNotBefore: %s\nNotAfter: %s\nSHA256: %s\n\n", label, c.Subject.String(), c.Issuer.String(), c.SerialNumber.Text(16), c.NotBefore.Format(time.RFC3339), c.NotAfter.Format(time.RFC3339), strings.ToUpper(hex.EncodeToString(fingerprint[:])))
}

func manualHashHex(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
