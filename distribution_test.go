package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func setupDistributionTest(t *testing.T) (*App, []byte, []byte, string) {
	t.Helper()
	root := t.TempDir()
	app, err := newApp(filepath.Join(root, "state.json"), "bootstrap-very-secret-123")
	if err != nil {
		t.Fatal(err)
	}
	app.handoffPath = filepath.Join(root, "handoff")
	app.privateExportEnabled = true
	app.state.ACMEProfiles = []ACMEProfile{{ID: "internal", Label: "Interne CA"}}
	app.state.ACMECerts = []ACMECertificate{{Name: "test", Label: "Test", Profile: "internal", Enabled: true}}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "test.example.org"}, DNSNames: []string{"test.example.org"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
	}, &x509.Certificate{SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "test.example.org"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	key := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	const version = "20261015090000-abcdefgh"
	target := filepath.Join(app.handoffPath, "internal", "test")
	dest := filepath.Join(target, "releases", version)
	if err = os.MkdirAll(dest, 0700); err != nil {
		t.Fatal(err)
	}
	for fn, content := range map[string][]byte{"cert.pem": cert, "chain.pem": cert, "fullchain.pem": cert, "privkey.pem": key} {
		if err = os.WriteFile(filepath.Join(dest, fn), content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err = os.Symlink(filepath.Join("releases", version), filepath.Join(target, "current")); err != nil {
		t.Fatal(err)
	}
	return app, cert, key, version
}
func createAPIKeyForTest(t *testing.T, app *App, secret string, private bool, expires time.Time) string {
	t.Helper()
	hash := sha256.Sum256([]byte(secret))
	id, _ := newID()
	app.state.DistributionTokens = append(app.state.DistributionTokens, DistributionToken{ID: id, Label: "client", Profile: "internal", Certificate: "test", Private: private,
		Hash: hex.EncodeToString(hash[:]), CreatedAt: time.Now(), ExpiresAt: expires})
	return id
}
func callAPI(app *App, url, token string) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	r := httptest.NewRequest("GET", url, nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	app.routes().ServeHTTP(rr, r)
	return rr
}
func TestDistributionPermissionsVersionAndManifest(t *testing.T) {
	app, cert, key, version := setupDistributionTest(t)
	expiry := time.Now().Add(time.Hour)
	createAPIKeyForTest(t, app, "cw_public", false, expiry)
	createAPIKeyForTest(t, app, "cw_private", true, expiry)
	base := "/api/v1/distribution/internal/test"
	cases := []struct {
		path, token string
		status      int
		body        string
	}{
		{base + "/manifest", "", 401, ""},
		{base + "/manifest", "cw_public", 200, ""},
		{base + "/artifacts/fullchain.pem", "cw_public", 200, string(cert)},
		{base + "/artifacts/privkey.pem", "cw_public", 401, ""},
		{base + "/artifacts/privkey.pem", "cw_private", 200, string(key)},
		{base + "/versions/" + version + "/artifacts/privkey.pem", "cw_private", 200, string(key)},
		{base + "/versions/20261015090000-foobar12/artifacts/privkey.pem", "cw_private", 404, ""},
		{"/api/v1/distribution/other/test/artifacts/fullchain.pem", "cw_private", 401, ""},
		{"/api/v1/distribution/internal/other/artifacts/fullchain.pem", "cw_private", 401, ""},
		{base + "/artifacts/.env", "cw_private", 404, ""},
	}
	for _, c := range cases {
		rr := callAPI(app, c.path, c.token)
		if rr.Code != c.status {
			t.Errorf("%s as %s: status %d, want %d body=%s", c.path, c.token, rr.Code, c.status, rr.Body.String())
		}
		if c.body != "" && rr.Body.String() != c.body {
			t.Errorf("%s wrong content", c.path)
		}
	}
	var manifest struct {
		Version   string   `json:"version"`
		SHA       string   `json:"version_sha256"`
		Artifacts []string `json:"artifacts"`
	}
	rr := callAPI(app, base+"/manifest", "cw_public")
	if err := json.Unmarshal(rr.Body.Bytes(), &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Version != version || len(manifest.Artifacts) != 3 {
		t.Errorf("manifest: %+v", manifest)
	}
	sum := sha256.Sum256(cert)
	if manifest.SHA != hex.EncodeToString(sum[:]) {
		t.Errorf("sha: %s", manifest.SHA)
	}
	app.privateExportEnabled = false
	if rr = callAPI(app, base+"/artifacts/privkey.pem", "cw_private"); rr.Code != 401 {
		t.Fatalf("expected opt-in guard, got %d", rr.Code)
	}
	if rr = callAPI(app, base+"/artifacts/cert.pem", "cw_private"); rr.Code != 200 {
		t.Fatalf("public should still work")
	}
}
func TestDistributionExpiryRevocationAndDeactivation(t *testing.T) {
	app, _, _, _ := setupDistributionTest(t)
	base := "/api/v1/distribution/internal/test/manifest"
	createAPIKeyForTest(t, app, "cw_expired", false, time.Now().Add(-time.Minute))
	if got := callAPI(app, base, "cw_expired").Code; got != 401 {
		t.Errorf("expired got %d", got)
	}
	id := createAPIKeyForTest(t, app, "cw_revoke", true, time.Now().Add(time.Hour))
	if got := callAPI(app, base, "cw_revoke").Code; got != 200 {
		t.Errorf("active got %d", got)
	}
	sessID := "sid"
	admin := app.state.Users[0]
	app.sessions[sessID] = session{userID: admin.ID, csrf: "csrf", expires: time.Now().Add(time.Hour)}
	r := httptest.NewRequest("POST", "/distribution/tokens/"+id+"/revoke", strings.NewReader(url.Values{"csrf": {"csrf"}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: "certwatch_session", Value: sessID})
	rr := httptest.NewRecorder()
	app.routes().ServeHTTP(rr, r)
	if rr.Code != 303 {
		t.Fatalf("revoke status=%d body=%s", rr.Code, rr.Body.String())
	}
	if got := callAPI(app, base, "cw_revoke").Code; got != 401 {
		t.Errorf("revoked got %d", got)
	}
	app.state.ACMECerts[0].Enabled = false
	if got := callAPI(app, base, "cw_revoke").Code; got != 401 {
		t.Errorf("disabled got %d", got)
	}
}
func TestDistributionRejectsReleaseEscapeAndInvalidPEM(t *testing.T) {
	app, _, _, version := setupDistributionTest(t)
	createAPIKeyForTest(t, app, "cw_secure", true, time.Now().Add(time.Hour))
	base := filepath.Join(app.handoffPath, "internal", "test")
	outside := filepath.Join(t.TempDir(), "danger.pem")
	if err := os.WriteFile(outside, []byte("secrets"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(base, "releases", version, "privkey.pem")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(base, "releases", version, "privkey.pem")); err != nil {
		t.Fatal(err)
	}
	url := "/api/v1/distribution/internal/test/artifacts/privkey.pem"
	if got := callAPI(app, url, "cw_secure").Code; got != 404 {
		t.Errorf("symlink escape got %d", got)
	}
	if err := os.Remove(filepath.Join(base, "releases", version, "fullchain.pem")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "releases", version, "fullchain.pem"), []byte("garbage"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := callAPI(app, "/api/v1/distribution/internal/test/manifest", "cw_secure").Code; got != 404 {
		t.Errorf("invalid PEM got %d", got)
	}
}
func TestDistributionCreateTokenOncePersisted(t *testing.T) {
	app, _, _, _ := setupDistributionTest(t)
	sessID := "sid"
	admin := app.state.Users[0]
	app.sessions[sessID] = session{userID: admin.ID, csrf: "csrf", expires: time.Now().Add(time.Hour)}
	form := url.Values{"csrf": {"csrf"}, "label": {"web01"}, "scope": {"internal/test"}, "days": {"30"}}
	req := httptest.NewRequest("POST", "/distribution/tokens", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "certwatch_session", Value: sessID})
	rr := httptest.NewRecorder()
	app.routes().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("create status=%d body=%s", rr.Code, rr.Body.String())
	}
	if len(app.state.DistributionTokens) != 1 {
		t.Fatalf("expected 1 token")
	}
	if strings.Contains(app.state.DistributionTokens[0].Hash, "cw_") {
		t.Fatal("plaintext token persisted")
	}
	stateBytes, err := os.ReadFile(app.path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stateBytes), "cw_") {
		t.Fatal("plaintext token in persisted state")
	}
	if !strings.Contains(rr.Body.String(), "cw_") {
		t.Fatal("created token not displayed once")
	}
	page := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/distribution", nil)
	r.AddCookie(&http.Cookie{Name: "certwatch_session", Value: sessID})
	app.routes().ServeHTTP(page, r)
	if strings.Contains(page.Body.String(), "cw_") {
		t.Fatal("token leaked on subsequent page")
	}
}
