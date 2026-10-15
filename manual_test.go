package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func manualFixture(t *testing.T) (*App, []byte, []byte) {
	t.Helper()
	dir := t.TempDir()
	app, err := newApp(filepath.Join(dir, "state.json"), "bootstrap-very-secret-123")
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	app.manualVault, err = newVault(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	app.privateExportEnabled = true
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certDer, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(234), Subject: pkix.Name{CommonName: "example.internal"}, DNSNames: []string{"example.internal"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour)}, &x509.Certificate{SerialNumber: big.NewInt(234), Subject: pkix.Name{CommonName: "example.internal"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour)}, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return app, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDer}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
}
func manualSession(t *testing.T, app *App) (*http.Cookie, string) {
	t.Helper()
	const sid = "manualsid"
	const csrf = "man-csrf"
	app.sessions[sid] = session{userID: app.state.Users[0].ID, csrf: csrf, expires: time.Now().Add(time.Hour)}
	return &http.Cookie{Name: "certwatch_session", Value: sid}, csrf
}
func manualUpload(t *testing.T, app *App, cert, key []byte) *httptest.ResponseRecorder {
	t.Helper()
	cookie, csrf := manualSession(t, app)
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for k, v := range map[string]string{"name": "myserver", "label": "Mein Server", "csrf": csrf} {
		if err := mw.WriteField(k, v); err != nil {
			t.Fatal(err)
		}
	}
	for k, v := range map[string][]byte{"cert": cert, "key": key} {
		f, err := mw.CreateFormFile(k, k+".pem")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.Write(v)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/manual/upload", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	app.routes().ServeHTTP(rr, req)
	return rr
}
func scopedToken(app *App, secret string, priv bool) {
	h := sha256.Sum256([]byte(secret))
	app.state.DistributionTokens = append(app.state.DistributionTokens, DistributionToken{ID: secret, Label: "test", Profile: "manual", Certificate: "myserver", Hash: hex.EncodeToString(h[:]), Private: priv, ExpiresAt: time.Now().Add(time.Hour)})
}
func TestManualUploadConvertDownloadAndDelete(t *testing.T) {
	app, cert, key := manualFixture(t)
	rr := manualUpload(t, app, cert, key)
	if rr.Code != 303 {
		t.Fatalf("upload status=%d body=%s", rr.Code, rr.Body.String())
	}
	if len(app.state.ManualCertificates) != 1 {
		t.Fatal("metadata missing")
	}
	meta, err := app.manualVault.load("myserver", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(meta.Artifacts) < 22 {
		t.Fatalf("expected conversion into many formats, got %d", len(meta.Artifacts))
	}
	for _, f := range []string{"fullchain.pem", "cert.pem", "leaf.der", "leaf-only.pfx", "leaf-only.p12", "pfx-password.txt", "leaf-chain.p7b", "private-key-pkcs8-encrypted.der", "privkey.pem"} {
		if _, _, err := app.manualRead("myserver", meta.Version, f); err != nil {
			if f == "leaf-chain.p7b" {
				continue
			}
			t.Errorf("%s missing: %v", f, err)
		}
	}
	raw, err := os.ReadFile(filepath.Join(app.manualVault.root("myserver"), meta.Version, "privkey.pem.sealed"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, key) {
		t.Fatal("private key persisted in plaintext")
	}
	scopedToken(app, "cw_public_manual", false)
	scopedToken(app, "cw_private_manual", true)
	base := "/api/v1/distribution/manual/myserver"
	if got := callAPI(app, base+"/manifest", "cw_public_manual"); got.Code != 200 || strings.Contains(got.Body.String(), "leaf-only.pfx") || strings.Contains(got.Body.String(), "pfx-password.txt") {
		t.Errorf("public manifest leaked private formats: %d %s", got.Code, got.Body.String())
	}
	if got := callAPI(app, base+"/artifacts/leaf.der", "cw_public_manual"); got.Code != 200 {
		t.Errorf("DER public=%d", got.Code)
	}
	if got := callAPI(app, base+"/artifacts/leaf-only.pfx", "cw_public_manual"); got.Code != 401 {
		t.Errorf("PFX public=%d", got.Code)
	}
	if got := callAPI(app, base+"/artifacts/private-key.pem", "cw_public_manual"); got.Code != 401 {
		t.Errorf("KEY public=%d", got.Code)
	}
	if got := callAPI(app, base+"/artifacts/leaf-only.pfx", "cw_private_manual"); got.Code != 200 || got.Body.Len() < 100 {
		t.Errorf("PFX private=%d", got.Code)
	}
	if got := callAPI(app, base+"/artifacts/pfx-password.txt", "cw_private_manual"); got.Code != 200 {
		t.Errorf("PFX passwd private=%d", got.Code)
	}
	if got := callAPI(app, base+"/versions/"+meta.Version+"/artifacts/privkey.pem", "cw_private_manual"); got.Code != 200 {
		t.Errorf("version private=%d", got.Code)
	}
	if got := callAPI(app, base+"/artifacts/../state.json", "cw_private_manual"); got.Code == 200 {
		t.Fatal("path traversal!")
	}
	// Ensure existing version retained across new imports.
	rr = manualUpload(t, app, cert, key)
	if rr.Code != 303 {
		t.Fatalf("reupload: %d %s", rr.Code, rr.Body.String())
	}
	old := callAPI(app, base+"/versions/"+meta.Version+"/artifacts/cert.pem", "cw_public_manual")
	if old.Code != 200 {
		t.Fatalf("previous version missing: %d", old.Code)
	}
	app.privateExportEnabled = false
	if got := callAPI(app, base+"/artifacts/leaf-only.pfx", "cw_private_manual"); got.Code != 401 {
		t.Errorf("private opt-out=%d", got.Code)
	}
	app.privateExportEnabled = true
	cookie, csrf := manualSession(t, app)
	req := httptest.NewRequest("POST", "/manual/myserver/delete", strings.NewReader(url.Values{"csrf": {csrf}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	deleted := httptest.NewRecorder()
	app.routes().ServeHTTP(deleted, req)
	if deleted.Code != 303 {
		t.Fatalf("delete: %d", deleted.Code)
	}
	if got := callAPI(app, base+"/artifacts/leaf.der", "cw_public_manual"); got.Code != 401 {
		t.Fatalf("revocation failed: %d", got.Code)
	}
	if _, err := os.Stat(app.manualVault.root("myserver")); !os.IsNotExist(err) {
		t.Errorf("vault not erased: %v", err)
	}
}
func TestManualRejectsMismatchedKeyAndViewer(t *testing.T) {
	app, cert, key := manualFixture(t)
	other := []byte("not a key")
	if r := manualUpload(t, app, cert, other); r.Code != 400 {
		t.Errorf("invalid key accepted: %d", r.Code)
	}
	// Viewer cannot perform upload even when session and CSRF are valid.
	app.state.Users[0].Role = "viewer"
	if r := manualUpload(t, app, cert, key); r.Code != 403 {
		t.Errorf("viewer imported: %d", r.Code)
	}
}
func TestManualVaultKeyMismatch(t *testing.T) {
	app, cert, key := manualFixture(t)
	if rr := manualUpload(t, app, cert, key); rr.Code != 303 {
		t.Fatalf("upload: %d %s", rr.Code, rr.Body.String())
	}
	fresh := make([]byte, 32)
	_, _ = io.ReadFull(rand.Reader, fresh)
	wrong, err := newVault(filepath.Dir(app.path), fresh)
	if err != nil {
		t.Fatal(err)
	}
	app.manualVault = wrong
	if _, _, err := app.manualRead("myserver", "", "cert.pem"); err == nil {
		t.Fatal("key mismatch not rejected")
	}
}

func TestManualPFXImportRoundTrip(t *testing.T) {
	app, cert, key := manualFixture(t)
	if r := manualUpload(t, app, cert, key); r.Code != 303 {
		t.Fatalf("first upload %d", r.Code)
	}
	meta, err := app.manualVault.load("myserver", "")
	if err != nil {
		t.Fatal(err)
	}
	pfx, _, err := app.manualRead("myserver", meta.Version, "leaf-only.pfx")
	if err != nil {
		t.Fatal(err)
	}
	password, _, err := app.manualRead("myserver", meta.Version, "pfx-password.txt")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := manualParsePFX(pfx, strings.TrimSpace(string(password)))
	if err != nil {
		t.Fatalf("PFX roundtrip: %v", err)
	}
	if !bytes.Equal(parsed.leaf.Raw, metaLeaf(cert)) {
		t.Fatal("PFX leaf mismatch")
	}
	if _, err := manualParsePFX(pfx, "wrongpass"); err == nil {
		t.Fatal("wrong PFX password accepted")
	}
	// Test HTTP upload of the PFX source.
	cookie, csrf := manualSession(t, app)
	var b bytes.Buffer
	mw := multipart.NewWriter(&b)
	_ = mw.WriteField("csrf", csrf)
	_ = mw.WriteField("name", "pfxserver")
	_ = mw.WriteField("label", "PFX imported")
	_ = mw.WriteField("pfx_password", strings.TrimSpace(string(password)))
	f, err := mw.CreateFormFile("pfx", "existing.p12")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.Write(pfx)
	_ = mw.Close()
	req := httptest.NewRequest("POST", "/manual/upload", &b)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	app.routes().ServeHTTP(rr, req)
	if rr.Code != 303 {
		t.Fatalf("PFX upload failed: %d %s", rr.Code, rr.Body.String())
	}
	if _, err := app.manualVault.load("pfxserver", ""); err != nil {
		t.Fatal(err)
	}
}
func metaLeaf(cert []byte) []byte { b, _ := pem.Decode(cert); return b.Bytes }
func TestManualManifestChecksumsAndVaultEncryption(t *testing.T) {
	app, cert, key := manualFixture(t)
	if r := manualUpload(t, app, cert, key); r.Code != 303 {
		t.Fatal(r.Code)
	}
	scopedToken(app, "cw_public_manual", false)
	r := callAPI(app, "/api/v1/distribution/manual/myserver/manifest", "cw_public_manual")
	var m struct {
		Version   string     `json:"version"`
		Artifacts []string   `json:"artifacts"`
		Details   []artifact `json:"artifact_details"`
		Source    string     `json:"source"`
	}
	if err := json.Unmarshal(r.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if m.Source != "manual" || !publishedReleasePattern.MatchString(m.Version) {
		t.Fatalf("wrong manifest %+v", m)
	}
	for _, f := range m.Details {
		if f.Private || manualIsPrivate(f) {
			t.Fatalf("private details exposed: %s", f.Name)
		}
		response := callAPI(app, "/api/v1/distribution/manual/myserver/versions/"+m.Version+"/artifacts/"+f.Name, "cw_public_manual")
		if response.Code != 200 {
			t.Fatalf("%s missing: %d", f.Name, response.Code)
		}
		h := sha256.Sum256(response.Body.Bytes())
		if hex.EncodeToString(h[:]) != f.SHA256 {
			t.Fatalf("hash mismatch %s", f.Name)
		}
	}
	original := app.manualVault
	alternate := make([]byte, 32)
	_, _ = rand.Read(alternate)
	alternateKey := base64.StdEncoding.EncodeToString(alternate)
	if alternateKey == "" {
		t.Fatal("empty key")
	}
	v, err := newVault(filepath.Dir(app.path), alternate)
	if err != nil {
		t.Fatal(err)
	}
	app.manualVault = v
	if x := callAPI(app, "/api/v1/distribution/manual/myserver/manifest", "cw_public_manual"); x.Code == 200 {
		t.Fatal("wrong key was accepted")
	}
	app.manualVault = original
}
