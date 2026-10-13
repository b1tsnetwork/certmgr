package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type uploadFile struct {
	field, name string
	body        []byte
}

func testLogin(t *testing.T, s *server) (*http.Cookie, string) {
	t.Helper()
	form := url.Values{"username": {"admin"}, "password": {"very-long-test-password"}}
	req := httptest.NewRequest("POST", "/admin/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.routes().ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther || len(w.Result().Cookies()) == 0 {
		t.Fatalf("login: %d", w.Code)
	}
	cookie := w.Result().Cookies()[0]
	next := httptest.NewRequest("GET", "/admin", nil)
	next.AddCookie(cookie)
	ss, ok := s.auth.session(next)
	if !ok {
		t.Fatal("cookie nicht gültig")
	}
	return cookie, ss.CSRF
}

func sendUpload(t *testing.T, s *server, cookie *http.Cookie, csrf string, files ...uploadFile) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	if csrf != "" {
		if err := w.WriteField("csrf", csrf); err != nil {
			t.Fatal(err)
		}
	}
	for _, item := range files {
		part, err := w.CreateFormFile(item.field, item.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = part.Write(item.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/admin/certificates/wildcard-test/upload", &body)
	req.Header.Set("Content-Type", w.FormDataContentType())
	if cookie != nil {
		req.AddCookie(cookie)
	}
	result := httptest.NewRecorder()
	s.routes().ServeHTTP(result, req)
	return result
}

func derFromPEM(t *testing.T, b []byte) []byte {
	t.Helper()
	block, rest := pem.Decode(b)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatal("bad PEM in test")
	}
	return block.Bytes
}

func TestBrowserUploadConvertAndPreventLegacyOverwrite(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("OpenSSL fehlt")
	}
	s, _ := testServer(t)
	original, err := s.vault.load("wildcard-test", "")
	if err != nil {
		t.Fatal(err)
	}
	cookie, csrf := testLogin(t, s)
	req := httptest.NewRequest("GET", "/admin/certificates/wildcard-test", nil)
	req.AddCookie(cookie)
	screen := httptest.NewRecorder()
	s.routes().ServeHTTP(screen, req)
	if screen.Code != 200 || !strings.Contains(screen.Body.String(), "enctype=\"multipart/form-data\"") {
		t.Fatal("Kein sichtbares Uploadformular")
	}
	leaf, chain, key, root := testChain(t)
	uploaded := []uploadFile{
		{"leaf", "certificate.cer", derFromPEM(t, leaf)},
		{"private_key", "private.key", key},
		{"intermediates", "intermediate.crt", chain},
		{"root", "root.der", derFromPEM(t, root)},
	}
	result := sendUpload(t, s, cookie, csrf, uploaded...)
	if result.Code != http.StatusSeeOther {
		t.Fatalf("Upload: %d %s", result.Code, result.Body.String())
	}
	now, err := s.vault.load("wildcard-test", "")
	if err != nil {
		t.Fatal(err)
	}
	if now.Version == original.Version {
		t.Fatal("Upload erzeugte keine neue Version")
	}
	def, _ := s.catalog.certificate("wildcard-test")
	if def.Source != "manual" {
		t.Fatalf("Importmodus: %q", def.Source)
	}
	for _, file := range []string{"leaf-chain.pfx", "root-ca.der", "fullchain.pem", "private-key.pem"} {
		if _, err := s.vault.read("wildcard-test", now.Version, file); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
	}
	raw, err := s.vault.read("wildcard-test", now.Version, "leaf.der")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(raw)
	if err != nil || parsed.Subject.CommonName != "*.example.test" {
		t.Fatal("DER normalization failed")
	}
	// Existing handoff points to another certificate. It must not undo the web upload.
	s.syncAll()
	after, err := s.vault.load("wildcard-test", "")
	if err != nil || after.Version != now.Version {
		t.Fatal("Background importer replaced manual upload")
	}
	// Manual flag persists across app restart.
	restored, err := newCatalog(filepath.Join(s.cfg.dataDir, "catalog.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	saved, _ := restored.certificate("wildcard-test")
	if saved.Source != "manual" {
		t.Fatal("manual upload mode wasn't persisted")
	}
	// Encrypted artifacts do not contain plaintext private-key delimiters.
	sealed, err := os.ReadFile(filepath.Join(s.vault.root("wildcard-test"), now.Version, "private-key.pem.sealed"))
	if err != nil || bytes.Contains(sealed, []byte("BEGIN PRIVATE KEY")) {
		t.Fatal("plaintext key in vault")
	}
}

func TestUploadRejectedWithoutAuthOrCSRFAndOnBadInput(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("OpenSSL fehlt")
	}
	s, _ := testServer(t)
	leaf, chain, key, _ := testChain(t)
	files := []uploadFile{{"leaf", "leaf.crt", leaf}, {"private_key", "secret.key", key}, {"intermediates", "ca.pem", chain}}
	cookie, csrf := testLogin(t, s)
	if r := sendUpload(t, s, nil, csrf, files...); r.Code != 401 {
		t.Fatalf("Unauthenticated: %d", r.Code)
	}
	if r := sendUpload(t, s, cookie, "invalid", files...); r.Code != 403 {
		t.Fatalf("CSRF: %d", r.Code)
	}
	_, _, otherKey, _ := testChain(t)
	badFiles := []uploadFile{{"leaf", "leaf.crt", leaf}, {"private_key", "key.pem", otherKey}, {"intermediates", "ca.pem", chain}}
	if r := sendUpload(t, s, cookie, csrf, badFiles...); r.Code != 400 || !strings.Contains(r.Body.String(), "Private Key") {
		t.Fatalf("Wrong key: %d", r.Code)
	}
	def, _ := s.catalog.certificate("wildcard-test")
	def.DNSNames = []string{"another.example.test"}
	if err := s.catalog.upsertCertificate(def); err != nil {
		t.Fatal(err)
	}
	if r := sendUpload(t, s, cookie, csrf, files...); r.Code != 400 || !strings.Contains(r.Body.String(), "SAN") {
		t.Fatalf("Unexpected SAN accepted: %d", r.Code)
	}
	def.DNSNames = []string{"*.example.test", "example.test"}
	def.Profile = "letsencrypt"
	if err := s.catalog.upsertCertificate(def); err != nil {
		t.Fatal(err)
	}
	if r := sendUpload(t, s, cookie, csrf, files...); r.Code != 400 || !strings.Contains(r.Body.String(), "ACME") {
		t.Fatalf("ACME-managed cert accepted: %d", r.Code)
	}
	// Oversized requests are rejected at the HTTP boundary.
	large := []uploadFile{{"leaf", "leaf.pem", bytes.Repeat([]byte("A"), maxUploadRequest)}}
	if r := sendUpload(t, s, cookie, csrf, large...); r.Code != 413 {
		t.Fatalf("Oversized form: %d", r.Code)
	}
}

func TestUploadFullchainAndNoIntermediates(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("OpenSSL fehlt")
	}
	s, _ := testServer(t)
	cookie, csrf := testLogin(t, s)
	leaf, chain, key, _ := testChain(t)
	result := sendUpload(t, s, cookie, csrf,
		uploadFile{"leaf", "fullchain.pem", append(append([]byte{}, leaf...), chain...)},
		uploadFile{"private_key", "private.pem", key},
	)
	if result.Code != 303 {
		t.Fatalf("fullchain upload: %d %s", result.Code, result.Body.String())
	}
	meta, err := s.vault.load("wildcard-test", "")
	if err != nil {
		t.Fatal(err)
	}
	pemChain, err := s.vault.read("wildcard-test", meta.Version, "chain-intermediates.pem")
	if err != nil || len(pemChain) == 0 {
		t.Fatal("intermediates lost from combined fullchain")
	}
	if _, err := s.vault.read("wildcard-test", meta.Version, "leaf-chain.pfx"); err != nil {
		t.Fatal(err)
	}
	_ = io.Discard
}
