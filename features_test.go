package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLegacyAdminIsMigratedToNamedAccount(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	h, err := hashPassword("legacy-password-for-admin")
	if err != nil {
		t.Fatal(err)
	}
	legacy := State{Version: 1, Admin: &h, Settings: Settings{WarningDays: 30, CriticalDays: 14}}
	data, _ := json.Marshal(legacy)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	app, err := newApp(path, "")
	if err != nil {
		t.Fatal(err)
	}
	if app.state.Version != 3 || len(app.state.Users) != 1 || app.state.Users[0].Username != "admin" || !app.state.Users[0].Password.matches("legacy-password-for-admin") {
		t.Fatal("migration lost original password")
	}
	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(saved), `"admin":`) {
		t.Fatal("legacy admin field still saved")
	}
}

func TestUsersRoleAndSessionRevocation(t *testing.T) {
	app, err := newApp(filepath.Join(t.TempDir(), "state.json"), "secret-for-initial-admin")
	if err != nil {
		t.Fatal(err)
	}
	adminID := app.state.Users[0].ID
	app.mu.Lock()
	app.sessions["admin-token"] = session{csrf: "admin-csrf", userID: adminID, expires: time.Now().Add(time.Hour)}
	app.mu.Unlock()
	post := func(route, token string, v url.Values) int {
		req := httptest.NewRequest("POST", "http://localhost"+route, strings.NewReader(v.Encode()))
		req.AddCookie(&http.Cookie{Name: "certwatch_session", Value: token})
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		app.routes().ServeHTTP(rec, req)
		return rec.Code
	}
	user := url.Values{"csrf": {"admin-csrf"}, "username": {"reader"}, "role": {"viewer"}, "password": {"super-secret-reader-pass"}, "confirm_password": {"super-secret-reader-pass"}}
	if status := post("/users", "admin-token", user); status != 303 {
		t.Fatalf("create user: %d", status)
	}
	st := app.snapshot()
	if len(st.Users) != 2 {
		t.Fatalf("users: %v", st.Users)
	}
	viewerID := st.Users[1].ID
	app.mu.Lock()
	app.sessions["viewer-token"] = session{csrf: "viewer-csrf", userID: viewerID, expires: time.Now().Add(time.Hour)}
	app.mu.Unlock()
	if status := post("/targets", "viewer-token", url.Values{"csrf": {"viewer-csrf"}}); status != 403 {
		t.Errorf("viewer mutated target: %d", status)
	}
	if status := post("/settings/password", "viewer-token", url.Values{"csrf": {"viewer-csrf"}, "old_password": {"super-secret-reader-pass"}, "new_password": {"viewer-updated-secret"}, "confirm_password": {"viewer-updated-secret"}}); status != 303 {
		t.Errorf("viewer password change denied: %d", status)
	}
	if _, ok := app.sessionFor(func() *http.Request {
		r := httptest.NewRequest("GET", "/", nil)
		r.AddCookie(&http.Cookie{Name: "certwatch_session", Value: "viewer-token"})
		return r
	}()); ok {
		t.Error("old session not revoked")
	}
	app.mu.Lock()
	app.sessions["viewer-token-2"] = session{csrf: "viewer-csrf", userID: viewerID, expires: time.Now().Add(time.Hour)}
	app.mu.Unlock()
	if status := post("/logout", "viewer-token-2", url.Values{"csrf": {"viewer-csrf"}}); status != 303 {
		t.Errorf("viewer cannot logout: %d", status)
	}
	if status := post("/users/"+adminID+"/delete", "admin-token", url.Values{"csrf": {"admin-csrf"}}); status != 400 {
		t.Errorf("self-delete should fail: %d", status)
	}
	if status := post("/users/"+viewerID+"/delete", "admin-token", url.Values{"csrf": {"admin-csrf"}}); status != 303 {
		t.Errorf("admin delete viewer: %d", status)
	}
}

func TestACMEWorkerCatalogIsIsolated(t *testing.T) {
	a, err := newApp(filepath.Join(t.TempDir(), "private-state.json"), "long-private-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	a.acmeCatalogPath = filepath.Join(t.TempDir(), "public-catalog", "catalog.json")
	a.state.ACMEProfiles = []ACMEProfile{{ID: "staging", Label: "Staging", DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory", Email: "x@example.com", Challenge: "cloudflare", CredentialsFile: "/run/secrets/cf.ini"}}
	a.state.ACMECerts = []ACMECertificate{{Name: "test-cert", Label: "Test", Profile: "staging", DNSNames: []string{"test.example.com"}, Enabled: true}}
	a.acmeEnabled = false
	a.mu.Lock()
	err = a.saveLocked()
	a.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(a.acmeCatalogPath)
	if strings.Contains(string(b), "test-cert") {
		t.Fatal("ACME disabled but worker got cert")
	}
	a.acmeEnabled = true
	a.mu.Lock()
	err = a.saveLocked()
	a.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(a.acmeCatalogPath)
	if !strings.Contains(string(b), "test-cert") || strings.Contains(string(b), "password") || strings.Contains(string(b), "long-private-passphrase") || strings.Contains(string(b), "users") {
		t.Fatalf("catalog leak/invalid: %s", b)
	}
}

func TestACMEValidation(t *testing.T) {
	p := ACMEProfile{ID: "staging", Label: "Test", DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory", Email: "test@example.com", Challenge: "cloudflare", CredentialsFile: "/run/secrets/cloudflare.ini"}
	if err := validateProfile(p); err != nil {
		t.Fatal(err)
	}
	if err := validateCertificate(ACMECertificate{Name: "my-cert", Profile: "staging", DNSNames: []string{"*.example.org", "example.org"}}, []ACMEProfile{p}); err != nil {
		t.Fatal(err)
	}
	p.CredentialsFile = "/run/secrets/../../etc/shadow"
	if validateProfile(p) == nil {
		t.Fatal("path traversal accepted")
	}
	if validDomain("../../bad.com") || validDomain("test.com -e /etc") {
		t.Fatal("bad DNS name accepted")
	}
}

func TestRFC2136ProfileValidation(t *testing.T) {
	p := ACMEProfile{ID: "internal", Label: "Intern", DirectoryURL: "https://acme.example.com/directory", Email: "admin@example.com", Challenge: "rfc2136", CredentialsFile: "/run/secrets/dns.ini", DNSServer: "192.0.2.53", DNSPort: 53, DNSPropagationSeconds: 20}
	if err := validateProfile(p); err != nil {
		t.Fatalf("RFC2136 profile should be valid: %v", err)
	}
	for _, server := range []string{"", "dns.internal.example", "127.0.0.1;cat /etc/shadow", "0.0.0.0"} {
		invalid := p
		invalid.DNSServer = server
		if validateProfile(invalid) == nil {
			t.Fatalf("accepted invalid RFC2136 server %q", server)
		}
	}
	invalid := p
	invalid.DNSPort = 65536
	if validateProfile(invalid) == nil {
		t.Fatal("accepted invalid port")
	}
	invalid = p
	invalid.DNSPropagationSeconds = 3601
	if validateProfile(invalid) == nil {
		t.Fatal("accepted invalid propagation")
	}
	p.DNSServer = "2001:db8::53"
	p.DNSPort = 0
	p.DNSPropagationSeconds = 0
	if err := validateProfile(p); err != nil {
		t.Fatalf("IPv6/defaults should be valid: %v", err)
	}
}
