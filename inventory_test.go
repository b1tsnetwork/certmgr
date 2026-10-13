package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMultipleCertificatesAndServiceScopes(t *testing.T) {
	s, _ := testServer(t)
	// The second lineage is configured in the UI catalog, not the environment.
	def := certificateDefinition{Name: "additional-test", Label: "Weitere Domain", DNSNames: []string{"*.example.test", "example.test"}, Enabled: true}
	if err := s.catalog.upsertCertificate(def); err != nil {
		t.Fatal(err)
	}
	leaf, chain, key, _ := testChain(t)
	source := filepath.Join(s.cfg.sourceDir, "additional-test", "current")
	if err := os.MkdirAll(source, 0700); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"cert.pem": leaf, "chain.pem": chain, "privkey.pem": key} {
		if err := os.WriteFile(filepath.Join(source, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.importCertificate("additional-test"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.vault.load("additional-test", ""); err != nil {
		t.Fatal(err)
	}
	token1, err := s.auth.create("scope-first", "wildcard-test", true, 90)
	if err != nil {
		t.Fatal(err)
	}
	get := func(path, tok string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", path, nil)
		if tok != "" {
			r.Header.Set("Authorization", "Bearer "+tok)
		}
		w := httptest.NewRecorder()
		s.routes().ServeHTTP(w, r)
		return w
	}
	if code := get("/api/v1/certificates/additional-test/artifacts/private-key.pem", token1).Code; code != 401 {
		t.Fatalf("cross certificate access: %d", code)
	}
	if !strings.Contains(get("/api/v1/certificates", "").Body.String(), "additional-test") {
		t.Fatal("second cert not listed")
	}

	svc, err := s.catalog.upsertService(serviceRecord{Certificate: "wildcard-test", Name: "IIS Prod 01", Kind: "IIS", Host: "web01.example.test", Environment: "Produktion", Files: []string{"leaf.der", "leaf-chain.pfx"}})
	if err != nil {
		t.Fatal(err)
	}
	other, err := s.catalog.upsertService(serviceRecord{Certificate: "wildcard-test", Name: "Apache Prod 01", Kind: "Apache", Files: []string{"fullchain.pem", "private-key.pem"}})
	if err != nil {
		t.Fatal(err)
	}
	pubToken, err := s.auth.createService("iis-public", svc.ID, svc.Certificate, false, 90)
	if err != nil {
		t.Fatal(err)
	}
	privateToken, err := s.auth.createService("iis-private", svc.ID, svc.Certificate, true, 90)
	if err != nil {
		t.Fatal(err)
	}
	otherToken, err := s.auth.createService("apache-private", other.ID, other.Certificate, true, 90)
	if err != nil {
		t.Fatal(err)
	}
	base := "/api/v1/services/" + svc.ID
	if code := get(base, "").Code; code != 401 {
		t.Fatalf("service inventory public: %d", code)
	}
	if code := get(base, token1).Code; code != 401 {
		t.Fatalf("cert token accessed service: %d", code)
	}
	if code := get(base, otherToken).Code; code != 401 {
		t.Fatalf("other service accessed manifest: %d", code)
	}
	if code := get(base, pubToken).Code; code != 200 {
		t.Fatalf("public service token: %d", code)
	}
	pub := get(base, pubToken).Body.String()
	if strings.Contains(pub, "leaf-chain.pfx") || strings.Contains(pub, "pfx-password.txt") || !strings.Contains(pub, "leaf.der") {
		t.Fatal("public service manifest discloses wrong files")
	}
	manifest := get(base, privateToken)
	if manifest.Code != 200 {
		t.Fatalf("private service manifest: %d", manifest.Code)
	}
	var m struct {
		Name      string     `json:"name"`
		Version   string     `json:"version"`
		ServiceID string     `json:"service_id"`
		Artifacts []artifact `json:"artifacts"`
	}
	if err := json.Unmarshal(manifest.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if m.Name != "wildcard-test" || m.ServiceID != svc.ID || len(m.Artifacts) != 3 {
		t.Fatalf("wrong manifest: %+v", m)
	}
	pinned := base + "/versions/" + m.Version + "/artifacts/"
	if get(pinned+"leaf.der", privateToken).Code != 200 {
		t.Fatal("selected public format denied")
	}
	if get(pinned+"leaf-chain.pfx", privateToken).Code != 200 {
		t.Fatal("selected PFX denied")
	}
	if get(pinned+"pfx-password.txt", privateToken).Code != 200 {
		t.Fatal("automatically included PFX password denied")
	}
	if get(pinned+"leaf-chain.pfx", pubToken).Code != 401 {
		t.Fatal("public service token read private PFX")
	}
	if get(pinned+"private-key.pem", privateToken).Code != 404 {
		t.Fatal("unchecked private key accessed")
	}
	if get(pinned+"fullchain.pem", privateToken).Code != 404 {
		t.Fatal("unchecked public format accessed")
	}
	if get(pinned+"leaf.der", otherToken).Code != 401 {
		t.Fatal("other service token read file")
	}
	// Format edits must take effect without generating new tokens.
	svc.Files = []string{"fullchain.pem"}
	if _, err := s.catalog.upsertService(svc); err != nil {
		t.Fatal(err)
	}
	if get(pinned+"leaf-chain.pfx", privateToken).Code != 404 {
		t.Fatal("old access survived an edit")
	}
	if get(pinned+"pfx-password.txt", privateToken).Code != 404 {
		t.Fatal("PFX password survived removal of PFX")
	}
	if get(pinned+"fullchain.pem", privateToken).Code != 200 {
		t.Fatal("new service format denied")
	}

	// Record persists across process restarts.
	restored, err := newCatalog(filepath.Join(s.cfg.dataDir, "catalog.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(restored.snapshot().Certificates) != 2 || len(restored.snapshot().Services) != 2 {
		t.Fatal("catalog did not persist")
	}
	b, err := os.ReadFile(filepath.Join(s.cfg.dataDir, "catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte(privateToken)) {
		t.Fatal("token leaked into CMS catalog")
	}
	if err := s.auth.revokeScope("", svc.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.catalog.deleteService(svc.ID); err != nil {
		t.Fatal(err)
	}
	if get(base, privateToken).Code != 404 {
		t.Fatal("deleted service still served")
	}
	if err := s.auth.revokeScope("additional-test", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.catalog.deleteCertificate("additional-test"); err != nil {
		t.Fatal(err)
	}
	if get("/api/v1/certificates/additional-test", "").Code != 404 {
		t.Fatal("deleted certificate still active")
	}
}
func TestInventoryValidationAndUI(t *testing.T) {
	s, _ := testServer(t)
	if _, err := s.catalog.upsertService(serviceRecord{Name: "broken", Kind: "IIS", Certificate: "wildcard-test", Files: []string{"private-key.pem", "../secrets"}}); err == nil {
		t.Fatal("invalid selected format accepted")
	}
	if err := s.catalog.upsertCertificate(certificateDefinition{Name: "good-test", DNSNames: []string{"*.example.test", "not valid"}, Enabled: true}); err == nil {
		t.Fatal("invalid SAN accepted")
	}
	sv, err := s.catalog.upsertService(serviceRecord{Name: "Web App", Kind: "IIS", Certificate: "wildcard-test", Files: []string{"leaf.der", "leaf-chain.pfx"}})
	if err != nil {
		t.Fatal(err)
	}
	// Log in and make sure both HTML pages render all checkboxes and selections.
	login := httptest.NewRequest(http.MethodPost, "http://localhost:8089/admin/login", strings.NewReader("username=admin&password=very-long-test-password"))
	login.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, login)
	if rec.Code != 303 {
		t.Fatalf("login failed %d", rec.Code)
	}
	var cookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "ucngcert_session" {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("missing session")
	}
	for path, required := range map[string]string{
		"/admin":                            "Alle Zertifikate",
		"/admin/certificates/wildcard-test": "Neuen Dienst zuordnen",
		"/admin/services/" + sv.ID:          "leaf-chain.pfx",
	} {
		r := httptest.NewRequest("GET", "http://localhost:8089"+path, nil)
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		s.routes().ServeHTTP(w, r)
		if w.Code != 200 || !strings.Contains(w.Body.String(), required) {
			t.Fatalf("page %s failed: status=%d length=%d", path, w.Code, w.Body.Len())
		}
	}
}

func TestAdminServiceCRUDThroughForms(t *testing.T) {
	s, _ := testServer(t)
	h := s.routes()
	request := func(method, path string, fields map[string][]string, cookie *http.Cookie) *httptest.ResponseRecorder {
		body := ""
		if fields != nil {
			values := url.Values(fields)
			body = values.Encode()
		}
		r := httptest.NewRequest(method, "http://localhost:8089"+path, strings.NewReader(body))
		if method == "POST" {
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Set("Origin", "http://localhost:8089")
		}
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	login := request("POST", "/admin/login", map[string][]string{"username": {"admin"}, "password": {"very-long-test-password"}}, nil)
	if login.Code != 303 {
		t.Fatalf("login: %d", login.Code)
	}
	var cookie *http.Cookie
	for _, v := range login.Result().Cookies() {
		if v.Name == "ucngcert_session" {
			cookie = v
		}
	}
	if cookie == nil {
		t.Fatal("no login cookie")
	}
	r := httptest.NewRequest("GET", "http://localhost:8089/admin", nil)
	r.AddCookie(cookie)
	ss, valid := s.auth.session(r)
	if !valid {
		t.Fatal("session invalid")
	}
	data := map[string][]string{"csrf": {ss.CSRF}, "name": {"new-wildcard"}, "label": {"Wildcard NEXT"}, "sans": {"*.next.test,next.test"}}
	if w := request("POST", "/admin/certificates", data, cookie); w.Code != 303 {
		t.Fatalf("create certificate: %d %s", w.Code, w.Body.String())
	}
	created, ok := s.catalog.certificate("new-wildcard")
	if !ok || !created.Enabled {
		t.Fatal("certificate was not persisted")
	}
	data = map[string][]string{"csrf": {ss.CSRF}, "name": {"Proxy CDN"}, "kind": {"Nginx"}, "host": {"edge.example"}, "environment": {"Production"}, "files": {"fullchain.pem", "private-key.pem"}}
	if w := request("POST", "/admin/certificates/new-wildcard/services", data, cookie); w.Code != 303 {
		t.Fatalf("create service: %d %s", w.Code, w.Body.String())
	}
	stored := s.catalog.snapshot().Services
	if len(stored) != 1 || stored[0].Certificate != "new-wildcard" || len(stored[0].Files) != 2 {
		t.Fatalf("service not created correctly: %+v", stored)
	}
	id := stored[0].ID
	// Requests without the login CSRF should not mutate the catalog.
	data["files"] = []string{"fullchain.pem"}
	delete(data, "csrf")
	if w := request("POST", "/admin/services/"+id, data, cookie); w.Code != 403 {
		t.Fatalf("unprotected service update: %d", w.Code)
	}
	if len(s.catalog.snapshot().Services[0].Files) != 2 {
		t.Fatal("csrf-protected data altered")
	}
	data["csrf"] = []string{ss.CSRF}
	if w := request("POST", "/admin/services/"+id, data, cookie); w.Code != 303 {
		t.Fatalf("update service: %d %s", w.Code, w.Body.String())
	}
	if got := s.catalog.snapshot().Services[0].Files; len(got) != 1 || got[0] != "fullchain.pem" {
		t.Fatalf("service files not updated: %v", got)
	}
	token, err := s.auth.createService("my token", id, "new-wildcard", true, 90)
	if err != nil {
		t.Fatal(err)
	}
	data = map[string][]string{"csrf": {ss.CSRF}, "confirm": {"Proxy CDN"}}
	if w := request("POST", "/admin/services/"+id+"/delete", data, cookie); w.Code != 303 {
		t.Fatalf("remove service: %d", w.Code)
	}
	if len(s.catalog.snapshot().Services) != 0 {
		t.Fatal("service still present")
	}
	if s.auth.bearerServiceAllowed(withBearer(token), id, "new-wildcard", true) {
		t.Fatal("deleted service token remains active")
	}
	data = map[string][]string{"csrf": {ss.CSRF}, "confirm": {"new-wildcard"}}
	if w := request("POST", "/admin/certificates/new-wildcard/delete", data, cookie); w.Code != 303 {
		t.Fatalf("remove cert: %d", w.Code)
	}
	if _, ok := s.catalog.certificate("new-wildcard"); ok {
		t.Fatal("removed cert still present")
	}
}
func withBearer(t string) *http.Request {
	r := httptest.NewRequest("GET", "http://localhost/", nil)
	r.Header.Set("Authorization", "Bearer "+t)
	return r
}
