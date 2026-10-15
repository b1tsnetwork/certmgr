package main

import (
	"bytes"
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

func testBrowser(app *App, path, sessionID string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if sessionID != "" {
		req.AddCookie(&http.Cookie{Name: "certwatch_session", Value: sessionID})
	}
	rr := httptest.NewRecorder()
	app.routes().ServeHTTP(rr, req)
	return rr
}

func TestBrowserDownloadsViewerPrivateWithoutAPIToken(t *testing.T) {
	app, cert, key := manualFixture(t)
	if got := manualUpload(t, app, cert, key); got.Code != http.StatusSeeOther {
		t.Fatalf("setup %d: %s", got.Code, got.Body.String())
	}
	app.state.Users[0].Role = "viewer"
	cookie, _ := manualSession(t, app)
	const detail = "/downloads/manual/myserver"
	if got := testBrowser(app, "/downloads", ""); got.Code != 303 {
		t.Fatalf("unauthenticated listing status = %d", got.Code)
	}
	if got := testBrowser(app, detail, ""); got.Code != 303 {
		t.Fatalf("unauthenticated detail status = %d", got.Code)
	}
	if got := testBrowser(app, "/downloads", cookie.Value); got.Code != 200 || !strings.Contains(got.Body.String(), "myserver") {
		t.Fatalf("viewer listing: %d %s", got.Code, got.Body.String())
	}
	page := testBrowser(app, detail, cookie.Value)
	if page.Code != 200 || !strings.Contains(page.Body.String(), "leaf-only.pfx") || !strings.Contains(page.Body.String(), "privkey.pem") || !strings.Contains(page.Body.String(), "pfx-password.txt") {
		t.Fatalf("private and public formats not in viewer UI: %d %s", page.Code, page.Body.String())
	}
	version, err := app.currentRelease("manual", "myserver")
	if err != nil {
		t.Fatal(err)
	}
	privateURL := detail + "/versions/" + version + "/artifacts/privkey.pem"
	if got := testBrowser(app, privateURL, ""); got.Code != 303 {
		t.Fatalf("private without login: %d", got.Code)
	}
	got := testBrowser(app, privateURL, cookie.Value)
	if got.Code != 200 || !bytes.Equal(got.Body.Bytes(), key) || got.Header().Get("Cache-Control") != "no-store, private" {
		t.Fatalf("viewer private result %d: %s", got.Code, got.Body.String())
	}
	for _, file := range []string{"leaf-only.pfx", "pfx-password.txt", "leaf.der"} {
		got := testBrowser(app, detail+"/versions/"+version+"/artifacts/"+file, cookie.Value)
		if got.Code != 200 || got.Body.Len() < 1 {
			t.Fatalf("viewer file %s status=%d: %s", file, got.Code, got.Body.String())
		}
	}
	if got := testBrowser(app, detail+"/versions/"+version+"/artifacts/state.json", cookie.Value); got.Code != 404 {
		t.Errorf("unexpected metadata access %d", got.Code)
	}
	if got := testBrowser(app, detail+"/versions/"+version+"/artifacts/privkey.pem", "api-token-only"); got.Code != 303 {
		t.Errorf("browser endpoint incorrectly accepts bearer-like token: %d", got.Code)
	}
	// The API must remain strictly bearer-based, even for a logged-in viewer.
	req := httptest.NewRequest("GET", "/api/v1/distribution/manual/myserver/artifacts/privkey.pem", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	app.routes().ServeHTTP(rr, req)
	if rr.Code != 401 {
		t.Errorf("API authenticated by browser cookie: %d", rr.Code)
	}
}

func TestMultiCertificateTokenScopesLatestAndRevoke(t *testing.T) {
	app, _, _, oldVersion := setupDistributionTest(t)
	// Add a manual certificate to the same server.
	original, cert, key := manualFixture(t)
	app.manualVault = original.manualVault
	if rr := manualUpload(t, app, cert, key); rr.Code != 303 {
		t.Fatalf("upload %d: %s", rr.Code, rr.Body.String())
	}
	cookie, csrf := manualSession(t, app)
	form := url.Values{
		"csrf": {csrf}, "label": {"k8s-deployment"}, "days": {"90"},
		"scopes": {"internal/test", "manual/myserver"}, "private": {"on"},
	}
	req := httptest.NewRequest(http.MethodPost, "/distribution/tokens", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	app.routes().ServeHTTP(rr, req)
	if rr.Code != 200 || len(app.state.DistributionTokens) != 1 {
		t.Fatalf("create multi-token: %d %s", rr.Code, rr.Body.String())
	}
	var rawToken string
	for _, field := range strings.Fields(rr.Body.String()) {
		if strings.HasPrefix(field, "cw_") {
			rawToken = strings.Trim(field, " \n\r\t<")
			break
		}
	}
	// Tokens are displayed only once. The HTML may place tags after the secret.
	begin := strings.Index(rr.Body.String(), "cw_")
	if begin < 0 {
		t.Fatal("token not displayed")
	}
	rawToken = strings.SplitN(rr.Body.String()[begin:], "<", 2)[0]
	if got := callAPI(app, "/api/v1/distribution/manual/myserver/manifest", rawToken); got.Code != 200 {
		t.Fatalf("manual grant: %d %s", got.Code, got.Body.String())
	}
	base := "/api/v1/distribution/internal/test"
	if got := callAPI(app, base+"/artifacts/privkey.pem", rawToken); got.Code != 200 {
		t.Fatalf("acme private grant: %d", got.Code)
	}
	if got := callAPI(app, "/api/v1/distribution/internal/other/manifest", rawToken); got.Code != 401 {
		t.Fatalf("unselected cert accessed: %d", got.Code)
	}
	if stored := app.state.DistributionTokens[0]; len(stored.Scopes) != 2 || stored.Hash == rawToken || stored.Profile != "" {
		t.Fatalf("new token stored incorrectly: %+v", stored)
	}
	// Current release pointer changes after rotation, token stays valid.
	newVersion := "20261016170000-ijklmnop"
	baseDir := filepath.Join(app.handoffPath, "internal", "test")
	destination := filepath.Join(baseDir, "releases", newVersion)
	if err := os.MkdirAll(destination, 0700); err != nil {
		t.Fatal(err)
	}
	other, newCert, newKey, _ := setupDistributionTest(t)
	_ = other
	for file, contents := range map[string][]byte{
		"cert.pem": newCert, "chain.pem": newCert, "fullchain.pem": newCert, "privkey.pem": newKey,
	} {
		if err := os.WriteFile(filepath.Join(destination, file), contents, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join("releases", newVersion), filepath.Join(baseDir, "new-current")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(baseDir, "new-current"), filepath.Join(baseDir, "current")); err != nil {
		t.Fatal(err)
	}
	manifest := callAPI(app, base+"/manifest", rawToken)
	if manifest.Code != 200 {
		t.Fatalf("manifest following rotation: %d", manifest.Code)
	}
	var summary struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(manifest.Body.Bytes(), &summary); err != nil || summary.Version != newVersion {
		t.Fatalf("latest version = %q, err = %v", summary.Version, err)
	}
	if got := callAPI(app, base+"/artifacts/privkey.pem", rawToken); got.Code != 200 || !bytes.Equal(got.Body.Bytes(), newKey) {
		t.Fatalf("latest private key not delivered: %d", got.Code)
	}
	if got := callAPI(app, base+"/versions/"+oldVersion+"/artifacts/privkey.pem", rawToken); got.Code != 200 {
		t.Errorf("old pinned release no longer accessible: %d", got.Code)
	}
	// Removing one scope preserves the other grant; then fully revokes token.
	app.mu.Lock()
	app.revokeScopeLocked("manual", "myserver")
	app.mu.Unlock()
	if got := callAPI(app, "/api/v1/distribution/manual/myserver/manifest", rawToken); got.Code != 401 {
		t.Errorf("removed manual scope remains usable: %d", got.Code)
	}
	if got := callAPI(app, base+"/manifest", rawToken); got.Code != 200 {
		t.Errorf("remaining ACME scope removed: %d", got.Code)
	}
	app.mu.Lock()
	app.revokeScopeLocked("internal", "test")
	app.mu.Unlock()
	if len(app.state.DistributionTokens) != 0 {
		t.Fatalf("empty token not revoked")
	}
}

func TestACMEWebDownloadsFullFormatConversionAndViewer(t *testing.T) {
	app, _, key, version := setupDistributionTest(t)
	v := t.TempDir()
	vaultKey := make([]byte, 32)
	_, _ = rand.Read(vaultKey)
	var err error
	app.manualVault, err = newVault(v, vaultKey)
	if err != nil {
		t.Fatal(err)
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(func() []byte { b, _ := pem.Decode(key); return b.Bytes }())
	if err != nil {
		t.Fatal(err)
	}
	leafSigner := parsedKey.(*ecdsa.PrivateKey)
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "Acme internal root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour), BasicConstraintsValid: true, IsCA: true,
		KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(43), Subject: pkix.Name{CommonName: "test.example.org"}, DNSNames: []string{"test.example.org"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, issuer, &leafSigner.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	place := filepath.Join(app.handoffPath, "internal", "test", "releases", version)
	for fn, b := range map[string][]byte{"cert.pem": cert, "chain.pem": chain, "fullchain.pem": append(append([]byte{}, cert...), chain...)} {
		if err := os.WriteFile(filepath.Join(place, fn), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	app.state.Users[0].Role = "viewer"
	app.sessions["viewersid"] = session{userID: app.state.Users[0].ID, csrf: "csrf", expires: time.Now().Add(time.Hour)}
	page := testBrowser(app, "/downloads/internal/test", "viewersid")
	if page.Code != 200 || !strings.Contains(page.Body.String(), "leaf-only.pfx") || !strings.Contains(page.Body.String(), "pfx-password.txt") || !strings.Contains(page.Body.String(), "leaf.der") {
		t.Fatalf("converted formats missing: %d %s", page.Code, page.Body.String())
	}
	prefix := "/downloads/internal/test/versions/" + version + "/artifacts/"
	for _, fn := range []string{"privkey.pem", "leaf-only.pfx", "pfx-password.txt", "leaf.der", "leaf-chain.p7b"} {
		got := testBrowser(app, prefix+fn, "viewersid")
		if got.Code != 200 || got.Body.Len() == 0 {
			t.Errorf("file %s status %d body %q", fn, got.Code, got.Body.String())
		}
	}
	cachePath := filepath.Join(v, "certificates", "_acme-converted", acmeCacheName("internal", "test"), version, "privkey.pem.sealed")
	b, err := os.ReadFile(cachePath)
	if err != nil || bytes.Contains(b, key) {
		t.Fatalf("unencrypted cache/private key exposure: %v", err)
	}
	if got := callAPI(app, "/api/v1/distribution/internal/test/artifacts/privkey.pem", ""); got.Code != 401 {
		t.Errorf("API became public: %d", got.Code)
	}
}

func TestLegacySingleCertificateTokenStillWorks(t *testing.T) {
	app, _, _, _ := setupDistributionTest(t)
	token := "cw_legacy_token"
	sum := sha256.Sum256([]byte(token))
	app.state.DistributionTokens = append(app.state.DistributionTokens, DistributionToken{
		ID: "legacy", Label: "legacy", Profile: "internal", Certificate: "test", Hash: hex.EncodeToString(sum[:]), ExpiresAt: time.Now().Add(time.Hour)})
	if got := callAPI(app, "/api/v1/distribution/internal/test/manifest", token); got.Code != 200 {
		t.Fatalf("legacy failed %d", got.Code)
	}
}

func TestDownloadAreaRoleHierarchy(t *testing.T) {
	app, _, _, _ := setupDistributionTest(t)
	for _, role := range []string{"viewer", "editor", "admin"} {
		app.state.Users[0].Role = role
		app.sessions["sid"] = session{userID: app.state.Users[0].ID, csrf: "csrf", expires: time.Now().Add(time.Hour)}
		if got := testBrowser(app, "/downloads", "sid"); got.Code != 200 {
			t.Errorf("role %s listing status %d", role, got.Code)
		}
		if got := testBrowser(app, "/downloads/internal/test", "sid"); got.Code != 200 {
			t.Errorf("role %s details status %d", role, got.Code)
		}
	}
}
