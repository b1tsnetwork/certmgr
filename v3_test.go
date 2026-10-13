package main

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestENVUsersAndSingleSecret(t *testing.T) {
	t.Setenv("USERS_JSON", `{"admin":"correct-long-password-A","operator":"correct-long-password-B"}`)
	t.Setenv("APP_SECRET", "test-only-APP_SECRET-abcdefghijklmnopqrstuvwxyz-0123456789")
	t.Setenv("MASTER_KEY", "")
	t.Setenv("MASTER_KEY_FILE", "")
	t.Setenv("ADMIN_PASSWORD", "")
	c, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if len(c.users) != 2 || len(c.masterKey) != 32 {
		t.Fatal("ENV was not parsed")
	}
	a, err := newAuthStateUsers(filepath.Join(t.TempDir(), "tokens.json"), c.users, false)
	if err != nil {
		t.Fatal(err)
	}
	s := &server{auth: a, cfg: c}
	// Login handler uses template, use a test server for complete flow instead.
	_ = s
	t.Setenv("USERS_JSON", `{"bad":"short"}`)
	if _, err = loadConfig(); err == nil {
		t.Fatal("Accepted too-short password")
	}
	t.Setenv("USERS_JSON", `{"ops":"correct-long-password-B"}`)
	old := make([]byte, 32)
	for i := range old {
		old[i] = byte(i)
	}
	t.Setenv("MASTER_KEY", base64.StdEncoding.EncodeToString(old))
	c, err = loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if string(c.masterKey) != string(old) {
		t.Fatal("legacy key is not identical")
	}
}
func TestProfileValidationAndCatalog(t *testing.T) {
	dir := t.TempDir()
	c, err := newCatalog(filepath.Join(dir, "catalog.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.snapshot().Profiles) != 2 {
		t.Fatal("Expected default Let's Encrypt profiles")
	}
	p := acmeProfile{ID: "internal", Label: "Internal ACME", DirectoryURL: "https://acme.internal.test/directory", Challenge: "manual-dns-hooks", AuthHook: "/hooks/create.sh", CleanupHook: "/hooks/remove.sh", EABKidEnv: "ACME_INTERNAL_KID", EABHMACEnv: "ACME_INTERNAL_HMAC"}
	if err = c.upsertProfile(p); err != nil {
		t.Fatal(err)
	}
	cert := certificateDefinition{Name: "wildcard", Enabled: true, Profile: p.ID, DNSNames: []string{"*.example.test"}}
	if err = c.upsertCertificate(cert); err != nil {
		t.Fatal(err)
	}
	if err = c.deleteProfile(p.ID); err == nil {
		t.Fatal("Deleted an in-use profile")
	}
	cert.Profile = "missing"
	if err = c.upsertCertificate(cert); err == nil {
		t.Fatal("Allowed non-existing profile")
	}
	p.DirectoryURL = "http://non-tls-acme.internal/"
	if err = c.upsertProfile(p); err == nil {
		t.Fatal("Accepted insecure URL")
	}
	p.DirectoryURL = "https://acme.internal.test/directory"
	p.AuthHook = "/hooks/../../etc/passwd"
	if err = c.upsertProfile(p); err == nil {
		t.Fatal("Accepted path traversal")
	}
	c2, err := newCatalog(filepath.Join(dir, "catalog.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if def, ok := c2.certificate("wildcard"); !ok || def.Profile != "internal" {
		t.Fatal("Profile assignment did not persist")
	}
}
func TestPublicDownloadsNeverContainPrivate(t *testing.T) {
	s, _ := testServer(t)
	mux := s.routes()
	index := httptest.NewRecorder()
	mux.ServeHTTP(index, httptest.NewRequest("GET", "http://example.test/public", nil))
	if index.Code != 200 || !strings.Contains(index.Body.String(), "wildcard-test") {
		t.Fatalf("public index: %d %s", index.Code, index.Body.String())
	}
	detail := httptest.NewRecorder()
	mux.ServeHTTP(detail, httptest.NewRequest("GET", "http://example.test/public/wildcard-test", nil))
	if detail.Code != 200 || strings.Contains(detail.Body.String(), "private-key.pem") || strings.Contains(detail.Body.String(), "leaf-chain.pfx") {
		t.Fatalf("private content in public HTML: %d %s", detail.Code, detail.Body.String())
	}
	pub := httptest.NewRecorder()
	mux.ServeHTTP(pub, httptest.NewRequest("GET", "http://example.test/api/v1/certificates/wildcard-test/artifacts/fullchain.pem", nil))
	if pub.Code != 200 || !strings.Contains(pub.Body.String(), "BEGIN CERTIFICATE") {
		t.Fatalf("Public PEM denied: %d", pub.Code)
	}
	priv := httptest.NewRecorder()
	mux.ServeHTTP(priv, httptest.NewRequest("GET", "http://example.test/api/v1/certificates/wildcard-test/artifacts/leaf-chain.pfx", nil))
	if priv.Code != 401 {
		t.Fatalf("Private PFX without token allowed: %d", priv.Code)
	}
}
func TestTwoENVUsersMayLogin(t *testing.T) {
	s, _ := testServer(t)
	s.auth.users = map[string][32]byte{}
	// Separate operators with independently configured passwords.
	a, err := newAuthStateUsers(filepath.Join(t.TempDir(), "tokens.json"), map[string]string{
		"admin": "a-very-long-secret-for-admin", "ops": "a-very-long-secret-for-ops",
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	s.auth = a
	for name, secret := range map[string]string{"admin": "a-very-long-secret-for-admin", "ops": "a-very-long-secret-for-ops"} {
		form := url.Values{"username": {name}, "password": {secret}}
		req := httptest.NewRequest(http.MethodPost, "http://localhost:8089/admin/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		s.routes().ServeHTTP(rec, req)
		if rec.Code != 303 || rec.Header().Get("Set-Cookie") == "" {
			t.Fatalf("%s login: %d", name, rec.Code)
		}
	}
	bad := url.Values{"username": {"ops"}, "password": {"a-very-long-secret-for-admin"}}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "http://localhost:8089/admin/login", strings.NewReader(bad.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.routes().ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatal("Cross-user password accepted")
	}
}
func TestAssignedProfileUsesSeparatedHandoff(t *testing.T) {
	s, _ := testServer(t)
	def, _ := s.catalog.certificate("wildcard-test")
	def.Profile = "letsencrypt"
	if err := s.catalog.upsertCertificate(def); err != nil {
		t.Fatal(err)
	}
	// Old flat handoff must NOT be silently consumed after profile assignment.
	if err := s.importCertificate("wildcard-test"); err == nil {
		t.Fatal("Accepted legacy source from wrong CA profile")
	}
	src := filepath.Join(s.cfg.sourceDir, "wildcard-test", "current")
	dest := filepath.Join(s.cfg.sourceDir, "letsencrypt", "wildcard-test", "current")
	if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(src, dest); err != nil {
		t.Fatal(err)
	}
	if err := s.importCertificate("wildcard-test"); err != nil {
		t.Fatal(err)
	}
}
