package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func makeCert(t *testing.T, cn string, parent *x509.Certificate, signer *ecdsa.PrivateKey, isCA bool, days int) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serialMax := new(big.Int).Lsh(big.NewInt(1), 120)
	serial, err := rand.Int(rand.Reader, serialMax)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	cert := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: cn},
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(0, 0, days),
		BasicConstraintsValid: true, IsCA: isCA,
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	if isCA {
		cert.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		cert.MaxPathLen = 1
	}
	if !isCA {
		cert.DNSNames = []string{cn}
		cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	if parent == nil {
		parent = cert
		signer = key
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, parent, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return parsed, key
}

func testCertServer(t *testing.T, rootDays, intermediateDays int) (addr string, pemRoot string, closeFn func()) {
	t.Helper()
	root, rootKey := makeCert(t, "Test Corporate Root", nil, nil, true, rootDays)
	intermediate, interKey := makeCert(t, "Test Issuing CA", root, rootKey, true, intermediateDays)
	leaf, leafKey := makeCert(t, "service.internal", intermediate, interKey, false, 20)
	pair := tls.Certificate{Certificate: [][]byte{leaf.Raw, intermediate.Raw}, PrivateKey: leafKey}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				if tlsConn, ok := c.(*tls.Conn); ok {
					_ = tlsConn.Handshake()
				}
				c.Close()
			}()
		}
	}()
	return ln.Addr().String(), string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})), func() { ln.Close(); <-done }
}

func targetAndSettings(addr string) (Target, Settings) {
	return Target{ID: "abc", Name: "Service", URL: "tls://" + addr, SNI: "service.internal", IntervalMinutes: 15}, Settings{WarningDays: 30, CriticalDays: 7, UseSystemRoots: false}
}
func rootEntry(pemText string) []RootCA { return []RootCA{{ID: "root", Name: "CA", PEM: pemText}} }

func TestValidChainIncludesLocallyStoredRoot(t *testing.T) {
	addr, root, done := testCertServer(t, 180, 90)
	defer done()
	target, settings := targetAndSettings(addr)
	r := checkTarget(context.Background(), target, settings, rootEntry(root))
	if !r.Valid || r.Status != "yellow" {
		t.Fatalf("want trusted and yellow (leaf 20d), got %+v", r)
	}
	if len(r.Chain) != 3 || r.Chain[2].Role != "Stammzertifikat" || r.Chain[2].Source != "Vertrauensspeicher" {
		t.Fatalf("incorrect chain: %+v", r.Chain)
	}
	if !r.FullChain {
		t.Fatal("chain should show full root")
	}
}
func TestNearExpiryOfRootTurnsWholeChainRed(t *testing.T) {
	addr, root, done := testCertServer(t, 3, 90)
	defer done()
	target, settings := targetAndSettings(addr)
	r := checkTarget(context.Background(), target, settings, rootEntry(root))
	if !r.Valid || r.Status != "red" {
		t.Fatalf("expect verified but critical root: %+v", r)
	}
	if r.Chain[2].Status != "red" {
		t.Fatalf("root must be critical: %+v", r.Chain[2])
	}
}
func TestMissingRootShowsUntrustedButDisplaysPeerChain(t *testing.T) {
	addr, _, done := testCertServer(t, 180, 90)
	defer done()
	target, settings := targetAndSettings(addr)
	r := checkTarget(context.Background(), target, settings, nil)
	if r.Valid || r.Status != "red" || len(r.Chain) != 2 || r.FullChain {
		t.Fatalf("must show incomplete failed validation, got %+v", r)
	}
	if !strings.Contains(r.Message, "nicht vertrauenswürdig") {
		t.Fatalf("error not clear: %s", r.Message)
	}
}
func TestWrongServerNameRejected(t *testing.T) {
	addr, root, done := testCertServer(t, 180, 90)
	defer done()
	target, settings := targetAndSettings(addr)
	target.SNI = "wrong.internal"
	r := checkTarget(context.Background(), target, settings, rootEntry(root))
	if r.Valid || r.Status != "red" || !strings.Contains(r.Message, "Hostname") {
		t.Fatalf("wrong SAN not rejected: %+v", r)
	}
}
func TestExpiredIntermediateIsVisible(t *testing.T) {
	addr, root, done := testCertServer(t, 180, -1)
	defer done()
	target, settings := targetAndSettings(addr)
	r := checkTarget(context.Background(), target, settings, rootEntry(root))
	if r.Valid || r.Status != "red" || len(r.Chain) < 2 || r.Chain[1].Status != "red" {
		t.Fatalf("expired intermediate missed: %+v", r)
	}
}
func TestPEMImportRejectsIntermediateAndPrivateKeys(t *testing.T) {
	root, _ := makeCert(t, "Root", nil, nil, true, 100)
	p := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw}))
	if out, err := parseRootPEM(p); err != nil || len(out) != 1 {
		t.Fatalf("should accept root: %v", err)
	}
	if _, err := parseRootPEM(p + "garbage"); err == nil {
		t.Fatal("garbage accepted")
	}
	if _, err := parseRootPEM("-----BEGIN PRIVATE KEY-----\nYWJj\n-----END PRIVATE KEY-----"); err == nil {
		t.Fatal("private key accepted")
	}
}
func TestPersistAndAuthenticationCSRF(t *testing.T) {
	a, err := newApp(filepath.Join(t.TempDir(), "state.json"), "correct-horse-battery-staple")
	if err != nil {
		t.Fatal(err)
	}
	handler := a.routes()
	req := httptest.NewRequest("GET", "http://localhost/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("no login gate: %d", w.Code)
	}
	creds := url.Values{"username": {"admin"}, "password": {"correct-horse-battery-staple"}}
	req = httptest.NewRequest("POST", "http://localhost/login", strings.NewReader(creds.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != 303 {
		t.Fatalf("login failed: %d / %s", w.Code, w.Body.String())
	}
	cookies := w.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("no cookie")
	}
	req = httptest.NewRequest("GET", "http://localhost/targets/new", nil)
	req.AddCookie(cookies[0])
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	re := regexp.MustCompile(`name="csrf" value="([^"]+)"`)
	match := re.FindStringSubmatch(w.Body.String())
	if w.Code != 200 || len(match) < 2 {
		t.Fatalf("csrf not in form: %d", w.Code)
	}
	form := url.Values{"name": {"Internal"}, "url": {"tls://127.0.0.1:1"}, "interval": {"60"}}
	send := func() int {
		req = httptest.NewRequest("POST", "http://localhost/targets", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(cookies[0])
		w = httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w.Code
	}
	if got := send(); got != 403 {
		t.Fatalf("CSRF missing should deny: %d", got)
	}
	form.Set("csrf", match[1])
	if got := send(); got != 303 {
		t.Fatalf("create failed: %d %s", got, w.Body.String())
	}
	// A check is launched asynchronously; wait for it before TempDir cleanup.
	deadline := time.Now().Add(3 * time.Second)
	for a.isRunning(a.snapshot().Targets[0].ID) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	b, err := newApp(a.path, "")
	if err != nil || len(b.state.Targets) != 1 {
		t.Fatalf("restart persistence failed: %v %+v", err, b.state)
	}
}

func TestURLParsing(t *testing.T) {
	_, host, addr, err := parseTargetURL("example.local:8443/x")
	if err != nil || host != "example.local" || addr != "example.local:8443" {
		t.Fatalf("host incorrect %v %s %s", err, host, addr)
	}
	for _, str := range []string{"http://example.com", "https://user:pass@example.com", "https://example.com:65536", "tls://a.local/foo"} {
		if _, _, _, err := parseTargetURL(str); err == nil {
			t.Fatalf("bad url accepted: %q", str)
		}
	}
	if _, _, _, err := parseTargetURL("tls://[::1]:443"); err != nil {
		t.Fatalf("IPv6 should work: %v", err)
	}
}

func TestCannotConfuseCustomRootWithIntermediate(t *testing.T) {
	root, rootKey := makeCert(t, "Root", nil, nil, true, 90)
	inter, _ := makeCert(t, "Intermediate", root, rootKey, true, 45)
	pemText := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: inter.Raw}))
	if _, err := parseRootPEM(pemText); err == nil {
		t.Fatal("intermediate imported as root")
	}
}

func TestSelectedRootsAreIsolatedPerTarget(t *testing.T) {
	addr, root, done := testCertServer(t, 180, 90)
	defer done()
	target, settings := targetAndSettings(addr)
	target.RootPolicy = "selected"
	target.RootIDs = []string{"not-matching"}
	available := rootEntry(root)
	if r := checkTarget(context.Background(), target, settings, selectRoots(target, available)); r.Valid {
		t.Fatalf("target unexpectedly trusted a root not selected")
	}
	target.RootIDs = []string{"root"}
	if r := checkTarget(context.Background(), target, settings, selectRoots(target, available)); !r.Valid {
		t.Fatalf("selected root should be trusted: %+v", r)
	}
}
func TestSystemTrustOverride(t *testing.T) {
	yes := true
	no := false
	settings := Settings{UseSystemRoots: true}
	if effectiveSystemRoots(Target{}, settings) != true {
		t.Fatal("expected global trust")
	}
	if effectiveSystemRoots(Target{TrustSystem: &no}, settings) {
		t.Fatal("target must disable system root trust")
	}
	settings.UseSystemRoots = false
	if !effectiveSystemRoots(Target{TrustSystem: &yes}, settings) {
		t.Fatal("target must enable system trust")
	}
}

func TestAllTemplateViewsRender(t *testing.T) {
	a, err := newApp(filepath.Join(t.TempDir(), "state.json"), "long-test-password-000001")
	if err != nil {
		t.Fatal(err)
	}
	tID := "testtarget"
	a.mu.Lock()
	a.state.Targets = append(a.state.Targets, Target{ID: tID, Name: "Test Service", URL: "tls://127.0.0.1:9999", IntervalMinutes: 60})
	if err := a.saveLocked(); err != nil {
		t.Fatal(err)
	}
	sessionID := "example-session"
	a.sessions[sessionID] = session{csrf: "csrf-value", userID: a.state.Users[0].ID, expires: time.Now().Add(time.Hour)}
	a.mu.Unlock()
	pages := []string{"/", "/targets/new", "/targets/" + tID, "/targets/" + tID + "/edit", "/roots", "/settings", "/users", "/acme"}
	for _, path := range pages {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://localhost"+path, nil)
			req.AddCookie(&http.Cookie{Name: "certwatch_session", Value: sessionID})
			rec := httptest.NewRecorder()
			a.routes().ServeHTTP(rec, req)
			if rec.Code != 200 || !strings.Contains(rec.Body.String(), "<!doctype html>") || !strings.Contains(rec.Body.String(), "</html>") {
				t.Fatalf("bad template status=%d html=%s", rec.Code, rec.Body.String())
			}
		})
	}
}
