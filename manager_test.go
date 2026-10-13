package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testChain(t *testing.T) ([]byte, []byte, []byte, []byte) {
	t.Helper()
	now := time.Now().UTC()
	serial := func() *big.Int {
		n, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 126))
		if e != nil {
			t.Fatal(e)
		}
		return n
	}
	newKey := func() *ecdsa.PrivateKey {
		k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		return k
	}
	rootKey, caKey, leafKey := newKey(), newKey(), newKey()
	rootTpl := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "Test Root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(400 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, MaxPathLen: 2}
	rootDER, e := x509.CreateCertificate(rand.Reader, rootTpl, rootTpl, &rootKey.PublicKey, rootKey)
	if e != nil {
		t.Fatal(e)
	}
	rootCert, e := x509.ParseCertificate(rootDER)
	if e != nil {
		t.Fatal(e)
	}
	caTpl := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "Test Intermediate"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(200 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, MaxPathLen: 0, MaxPathLenZero: true}
	caDER, e := x509.CreateCertificate(rand.Reader, caTpl, rootCert, &caKey.PublicKey, rootKey)
	if e != nil {
		t.Fatal(e)
	}
	caCert, e := x509.ParseCertificate(caDER)
	if e != nil {
		t.Fatal(e)
	}
	leafTpl := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "*.example.test"}, DNSNames: []string{"*.example.test", "example.test"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(80 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	leafDER, e := x509.CreateCertificate(rand.Reader, leafTpl, caCert, &leafKey.PublicKey, caKey)
	if e != nil {
		t.Fatal(e)
	}
	keyDER, e := x509.MarshalPKCS8PrivateKey(leafKey)
	if e != nil {
		t.Fatal(e)
	}
	wrap := func(b []byte, typ string) []byte { return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: b}) }
	return wrap(leafDER, "CERTIFICATE"), wrap(caDER, "CERTIFICATE"), wrap(keyDER, "PRIVATE KEY"), wrap(rootDER, "CERTIFICATE")
}
func TestInputValidation(t *testing.T) {
	leaf, chain, key, root := testChain(t)
	parsed, e := parseInput(leaf, chain, key, root)
	if e != nil {
		t.Fatalf("valid chain rejected: %v", e)
	}
	if parsed.root == nil || len(parsed.chain) != 1 {
		t.Fatal("CA chain not parsed")
	}
	_, _, otherKey, _ := testChain(t)
	if _, e = parseInput(leaf, chain, otherKey, root); e == nil || !strings.Contains(e.Error(), "Private Key") {
		t.Fatalf("wrong key accepted: %v", e)
	}
	otherLeaf, _, _, _ := testChain(t)
	if _, e = parseInput(otherLeaf, chain, key, root); e == nil {
		t.Fatal("mismatched leaf accepted")
	}
	_, _, _, otherRoot := testChain(t)
	if _, e = parseInput(leaf, chain, key, otherRoot); e == nil {
		t.Fatal("unrelated root accepted")
	}
}
func testServer(t *testing.T) (*server, []byte) {
	t.Helper()
	dir := t.TempDir()
	leaf, chain, key, root := testChain(t)
	source := filepath.Join(dir, "handoff", "wildcard-test", "current")
	if e := os.MkdirAll(source, 0700); e != nil {
		t.Fatal(e)
	}
	for name, b := range map[string][]byte{"cert.pem": leaf, "chain.pem": chain, "privkey.pem": key} {
		if e := os.WriteFile(filepath.Join(source, name), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	roots := filepath.Join(dir, "roots")
	if e := os.MkdirAll(roots, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(roots, "wildcard-test.pem"), root, 0600); e != nil {
		t.Fatal(e)
	}
	master := bytes.Repeat([]byte{0x21}, 32)
	c := config{addr: "127.0.0.1:8089", dataDir: filepath.Join(dir, "data"), sourceDir: filepath.Join(dir, "handoff"), rootsDir: roots, scratchDir: filepath.Join(dir, "scratch"), adminUser: "admin", adminPassword: "very-long-test-password", masterKey: master, names: []string{"wildcard-test"}, expectedSAN: map[string][]string{"wildcard-test": {"*.example.test", "example.test"}}}
	s, e := newServer(c)
	if e != nil {
		t.Fatal(e)
	}
	if e := s.importCertificate("wildcard-test"); e != nil {
		t.Fatalf("import failed: %v", e)
	}
	return s, key
}
func TestConversionVaultAndAPI(t *testing.T) {
	if _, e := exec.LookPath("openssl"); e != nil {
		t.Skip("openssl nicht installiert")
	}
	s, key := testServer(t)
	m, e := s.vault.load("wildcard-test", "")
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(strings.Join(m.DNSNames, ","), "*.example.test") {
		t.Fatal("missing SAN")
	}
	if len(m.Artifacts) < 20 {
		t.Errorf("too few converted artifacts: %d", len(m.Artifacts))
	}
	for _, f := range []string{"leaf-chain.pfx", "leaf-chain.p12", "leaf-fullchain-with-root.pfx", "fullchain-with-root.pem", "chain-intermediates.pem", "root-ca.der", "leaf-chain.p7b", "leaf-chain.p7c", "private-key-pkcs8-encrypted.pem", "key-fullchain-with-root.pem", "SHA256SUMS.txt"} {
		aFound := false
		for _, a := range m.Artifacts {
			if a.Name == f {
				aFound = true
			}
		}
		if !aFound {
			t.Errorf("missing artifact %s", f)
		}
	}
	raw, e := s.vault.read("wildcard-test", m.Version, "private-key.pem")
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(raw, key) { // normalisierte PKCS#8-PEM-Keys sind semantisch und hier auch bytes-identisch
		parsed1, _ := pem.Decode(raw)
		parsed2, _ := pem.Decode(key)
		if !bytes.Equal(parsed1.Bytes, parsed2.Bytes) {
			t.Fatal("key material changed")
		}
	}
	sealed, e := os.ReadFile(filepath.Join(s.vault.root("wildcard-test"), m.Version, "private-key.pem.sealed"))
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(sealed, []byte("BEGIN PRIVATE KEY")) {
		t.Fatal("private key stored in clear")
	}
	a := s.routes()
	get := func(path, token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	n := "/api/v1/certificates/wildcard-test"
	if code := get(n, "").Code; code != 200 {
		t.Fatalf("public metadata status %d", code)
	}
	if strings.Contains(get(n, "").Body.String(), "private-key.pem") {
		t.Fatal("public metadata leaks private artifact")
	}
	if code := get(n+"/artifacts/fullchain.pem", "").Code; code != 200 {
		t.Fatalf("public download status %d", code)
	}
	if code := get(n+"/artifacts/private-key.pem", "").Code; code != 401 {
		t.Fatalf("private download without token: %d", code)
	}
	publicToken, e := s.auth.create("public-bot", "wildcard-test", false, 90)
	if e != nil {
		t.Fatal(e)
	}
	if code := get(n+"/artifacts/private-key.pem", publicToken).Code; code != 401 {
		t.Fatalf("public token reads key: %d", code)
	}
	wrongToken, e := s.auth.create("wrong-bot", "other-cert", true, 90)
	if e != nil {
		t.Fatal(e)
	}
	if code := get(n+"/artifacts/private-key.pem", wrongToken).Code; code != 401 {
		t.Fatalf("wrong-scope token reads key: %d", code)
	}
	privateToken, e := s.auth.create("iis-bot", "wildcard-test", true, 90)
	if e != nil {
		t.Fatal(e)
	}
	response := get(n+"/versions/"+m.Version+"/artifacts/private-key.pem", privateToken)
	if response.Code != 200 || !bytes.Equal(response.Body.Bytes(), raw) {
		t.Fatal("authorized private key download failed")
	}
	if strings.Contains(response.Header().Get("Content-Type"), "text/html") {
		t.Fatal("private key must be attachment")
	}
	// Token werden nur gehasht gespeichert.
	tokenJSON, e := os.ReadFile(filepath.Join(s.cfg.dataDir, "tokens.json"))
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(tokenJSON, []byte(privateToken)) {
		t.Fatal("raw token found on disk")
	}
	var id string
	for _, tok := range s.auth.list() {
		if tok.Label == "iis-bot" {
			id = tok.ID
		}
	}
	if e := s.auth.revoke(id); e != nil {
		t.Fatal(e)
	}
	if code := get(n+"/artifacts/private-key.pem", privateToken).Code; code != 401 {
		t.Fatalf("revoked token still authorized: %d", code)
	}
	pw, e := s.vault.read("wildcard-test", m.Version, "pfx-password.txt")
	if e != nil {
		t.Fatal(e)
	}
	pfx, e := s.vault.read("wildcard-test", m.Version, "leaf-chain.pfx")
	if e != nil {
		t.Fatal(e)
	}
	tmp := t.TempDir()
	pfxFile := filepath.Join(tmp, "test.pfx")
	if e = os.WriteFile(pfxFile, pfx, 0600); e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command("openssl", "pkcs12", "-in", pfxFile, "-info", "-noout", "-passin", "env:CERTMGR_TEST_PASSWORD")
	cmd.Env = append(os.Environ(), "CERTMGR_TEST_PASSWORD="+strings.TrimSpace(string(pw)))
	if output, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("PFX password invalid: %v: %s", e, output)
	}
	// Frisch erstellte Dateien überstehen einen Neustart mit gleichem Master-Key.
	reloaded, e := newVault(s.cfg.dataDir, s.cfg.masterKey)
	if e != nil {
		t.Fatal(e)
	}
	reread, e := reloaded.read("wildcard-test", m.Version, "private-key.pem")
	if e != nil || !bytes.Equal(reread, raw) {
		t.Fatal("encrypted artifacts not recoverable with master key", e)
	}
}
func TestSANValidation(t *testing.T) {
	for _, domain := range []string{"*.example.com", "www.example.com", "www.test-123.example.com"} {
		if !validSAN(domain) {
			t.Errorf("valid SAN rejected: %s", domain)
		}
	}
	for _, domain := range []string{"*.*.com", "foo*bar.com", "example", ".example.com", "foo..com", "-a.com", "examp_le.com"} {
		if validSAN(domain) {
			t.Errorf("unsafe SAN accepted: %s", domain)
		}
	}
}
func TestUnsafeNameAndAuthOrigin(t *testing.T) {
	for _, n := range []string{"../foo", "x/y", ".hidden", "", "..", "x%20"} {
		if safeName(n) {
			t.Errorf("unsafe name accepted: %q", n)
		}
	}
	for _, n := range []string{"wildcard-example-com", "example.com", "a_b"} {
		if !safeName(n) {
			t.Errorf("valid name rejected: %q", n)
		}
	}
	request := httptest.NewRequest("POST", "https://cert.example.test/admin/tokens", nil)
	request.Header.Set("Origin", "https://evil.example.test")
	if checkOrigin(request) {
		t.Fatal("cross-site origin accepted")
	}
	request.Header.Set("Origin", "https://cert.example.test")
	if !checkOrigin(request) {
		t.Fatal("same-site origin rejected")
	}
}

func TestDashboardLoginAndCSRF(t *testing.T) {
	s, key := testServer(t)
	_ = key
	handler := s.routes()
	login := httptest.NewRequest("POST", "http://localhost:8089/admin/login", strings.NewReader(url.Values{"username": {"admin"}, "password": {"very-long-test-password"}}.Encode()))
	login.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	login.Header.Set("Origin", "http://localhost:8089")
	login.RemoteAddr = "127.0.0.1:1234"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, login)
	if w.Code != 303 {
		t.Fatalf("Login status %d: %s", w.Code, w.Body.String())
	}
	var session *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "ucngcert_session" {
			session = c
		}
	}
	if session == nil {
		t.Fatal("missing session cookie")
	}
	read := httptest.NewRequest("GET", "http://localhost:8089/admin", nil)
	read.AddCookie(session)
	out := httptest.NewRecorder()
	handler.ServeHTTP(out, read)
	if out.Code != 200 || !strings.Contains(out.Body.String(), "Certificate Center") {
		t.Fatalf("dashboard failed: %d", out.Code)
	}
	form := url.Values{"label": {"ci-iis"}, "certificate": {"wildcard-test"}, "days": {"90"}, "private": {"yes"}}
	forbidden := httptest.NewRequest("POST", "http://localhost:8089/admin/tokens", strings.NewReader(form.Encode()))
	forbidden.Header.Set("Origin", "http://localhost:8089")
	forbidden.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	forbidden.AddCookie(session)
	denied := httptest.NewRecorder()
	handler.ServeHTTP(denied, forbidden)
	if denied.Code != 403 {
		t.Fatalf("CSRF missing but accepted: %d", denied.Code)
	}
	ss, ok := s.auth.session(read)
	if !ok {
		t.Fatal("session vanished")
	}
	form.Set("csrf", ss.CSRF)
	allowed := httptest.NewRequest("POST", "http://localhost:8089/admin/tokens", strings.NewReader(form.Encode()))
	allowed.Header.Set("Origin", "http://localhost:8089")
	allowed.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	allowed.AddCookie(session)
	success := httptest.NewRecorder()
	handler.ServeHTTP(success, allowed)
	if success.Code != 200 || !strings.Contains(success.Body.String(), "ucng_") {
		t.Fatalf("authorized token creation failed: %d", success.Code)
	}
}
func TestBadImportKeepsLastGoodVersion(t *testing.T) {
	s, _ := testServer(t)
	old, e := s.vault.load("wildcard-test", "")
	if e != nil {
		t.Fatal(e)
	}
	// Expected SANs are now persisted in the catalog, not read from env at runtime.
	if e := s.catalog.upsertCertificate(certificateDefinition{Name: "wildcard-test", DNSNames: []string{"*.wrong.example.test"}, Enabled: true}); e != nil {
		t.Fatal(e)
	}
	if e := s.importCertificate("wildcard-test"); e == nil {
		t.Fatal("invalid SAN accepted")
	}
	current, e := s.vault.load("wildcard-test", "")
	if e != nil || current.Version != old.Version {
		t.Fatal("last known good version was discarded")
	}
}
