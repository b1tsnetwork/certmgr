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

func testSystemRequest(app *App, method, path, sid string, form url.Values) *httptest.ResponseRecorder {
	var req *http.Request
	if form != nil {
		req = httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	if sid != "" {
		req.AddCookie(&http.Cookie{Name: "certwatch_session", Value: sid})
	}
	rec := httptest.NewRecorder()
	app.routes().ServeHTTP(rec, req)
	return rec
}
func systemTestApp(t *testing.T) *App {
	t.Helper()
	app, err := newApp(filepath.Join(t.TempDir(), "state.json"), "strong-enough-password-for-admin")
	if err != nil {
		t.Fatal(err)
	}
	app.mu.Lock()
	app.sessions["admin-session"] = session{userID: app.state.Users[0].ID, csrf: "csrf-admin", expires: time.Now().Add(time.Hour)}
	app.state.Users = append(app.state.Users, User{ID: "viewer1", Username: "viewer", Role: "viewer"})
	app.sessions["viewer-session"] = session{userID: "viewer1", csrf: "csrf-viewer", expires: time.Now().Add(time.Hour)}
	app.state.Targets = []Target{{ID: "target1", Name: "Webportal TLS", URL: "https://web.example.org", IntervalMinutes: 60}}
	app.state.ACMECerts = []ACMECertificate{{Name: "web-live", Profile: "internal", Label: "ACME Web", Enabled: true}}
	app.state.ManualCertificates = []ManualCertificate{{Name: "manualweb", Label: "Manuelles Web"}}
	if err := app.saveLocked(); err != nil {
		t.Fatal(err)
	}
	app.mu.Unlock()
	return app
}
func TestExistingTextServersMigrateWithoutDuplicates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	hash, err := hashPassword("legacy-password-for-admin")
	if err != nil {
		t.Fatal(err)
	}
	st := State{Version: 2, Users: []User{{ID: "id", Username: "admin", Role: "admin", Password: hash}}, Settings: Settings{UseSystemRoots: true}, Targets: []Target{{ID: "one", Name: "One", Server: "srv-web-01"}, {ID: "two", Name: "Two", Server: "srv-web-01"}, {ID: "three", Name: "Three", Server: "Cluster X"}, {ID: "four", Name: "Four"}}}
	b, _ := json.Marshal(st)
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	app, err := newApp(path, "")
	if err != nil {
		t.Fatal(err)
	}
	if app.state.Version != 3 || len(app.state.Systems) != 2 || len(app.state.Assignments) != 3 {
		t.Fatalf("migration: version=%d systems=%v refs=%v", app.state.Version, app.state.Systems, app.state.Assignments)
	}
	if len(systemsForRef(app.state, "target:one")) != 1 || systemsForRef(app.state, "target:one")[0].ID != systemsForRef(app.state, "target:two")[0].ID {
		t.Fatal("same server text not de-duplicated")
	}
	if app.state.Targets[0].Server != "srv-web-01" {
		t.Fatal("legacy values lost")
	}
	after, err := newApp(path, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(after.state.Assignments) != 3 || len(after.state.Systems) != 2 {
		t.Fatal("migration repeated on restart")
	}
}
func TestSystemRelationsCRUDAndRolePermissions(t *testing.T) {
	app := systemTestApp(t)
	create := url.Values{"csrf": {"csrf-admin"}, "name": {"Web-Cluster"}, "kind": {"server"}, "ip_address": {"10.1.2.3"}, "documentation_url": {"https://docs.example.org/web"}, "description": {"Wichtige Systeme"}, "certificate_refs": {"target:target1", "acme:web-live", "manual:manualweb"}}
	if got := testSystemRequest(app, "POST", "/systems", "viewer-session", create); got.Code != 403 {
		t.Fatalf("viewer created system: %d", got.Code)
	}
	if got := testSystemRequest(app, "POST", "/systems", "admin-session", create); got.Code != 303 {
		t.Fatalf("create system %d: %s", got.Code, got.Body.String())
	}
	st := app.snapshot()
	if len(st.Systems) != 1 || len(st.Assignments) != 3 {
		t.Fatalf("relations not saved: %v %v", st.Systems, st.Assignments)
	}
	id := st.Systems[0].ID
	for _, p := range []string{"/systems", "/systems/" + id, "/dependencies", "/dependencies?system=" + id, "/dependencies?certificate=manual%3Amanualweb", "/dependencies/certificates/manual/manualweb"} {
		resp := testSystemRequest(app, "GET", p, "viewer-session", nil)
		if resp.Code != 200 {
			t.Fatalf("viewer GET %s = %d: %s", p, resp.Code, resp.Body.String())
		}
		if !strings.Contains(resp.Body.String(), "Web-Cluster") {
			t.Fatalf("missing system in %s", p)
		}
	}
	if got := testSystemRequest(app, "GET", "/systems", "", nil); got.Code != 303 {
		t.Fatalf("anon read system: %d", got.Code)
	}
	if got := testSystemRequest(app, "POST", "/dependencies/certificates/manual/manualweb", "viewer-session", url.Values{"csrf": {"csrf-viewer"}}); got.Code != 403 {
		t.Fatalf("viewer changed assignment: %d", got.Code)
	}
	change := url.Values{"csrf": {"csrf-admin"}, "system_ids": {id}}
	if got := testSystemRequest(app, "POST", "/dependencies/certificates/manual/manualweb", "admin-session", change); got.Code != 303 {
		t.Fatalf("update cert relation: %d %s", got.Code, got.Body.String())
	}
	// Reassign through certificate perspective; only that certificate changes.
	clear := url.Values{"csrf": {"csrf-admin"}}
	if got := testSystemRequest(app, "POST", "/dependencies/certificates/acme/web-live", "admin-session", clear); got.Code != 303 {
		t.Fatalf("clear acme relation: %d", got.Code)
	}
	st = app.snapshot()
	if len(st.Assignments) != 2 || len(certificatesForSystem(st, id)) != 2 {
		t.Fatalf("unexpected changes to other relations: %v", st.Assignments)
	}
	// System changes update both metadata and associations.
	update := url.Values{"csrf": {"csrf-admin"}, "name": {"Web-Cluster-2"}, "kind": {"application"}, "description": {"Portal"}, "certificate_refs": {"target:target1"}}
	if got := testSystemRequest(app, "POST", "/systems/"+id, "admin-session", update); got.Code != 303 {
		t.Fatalf("update system: %d %s", got.Code, got.Body.String())
	}
	st = app.snapshot()
	if len(st.Assignments) != 1 || st.Systems[0].Kind != "application" {
		t.Fatalf("system update failed: %v", st)
	}
	if got := testSystemRequest(app, "POST", "/systems/"+id+"/delete", "admin-session", clear); got.Code != 303 {
		t.Fatalf("delete: %d", got.Code)
	}
	st = app.snapshot()
	if len(st.Systems) != 0 || len(st.Assignments) != 0 || len(st.Targets) != 1 || len(st.ManualCertificates) != 1 {
		t.Fatal("system deletion deleted certificates or left dangling links")
	}
	reloaded, err := newApp(app.path, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.state.Systems) != 0 || len(reloaded.state.Targets) != 1 {
		t.Fatal("deletion did not persist")
	}
}
func TestSystemInputsInvalidReferencesAndURL(t *testing.T) {
	app := systemTestApp(t)
	base := url.Values{"csrf": {"csrf-admin"}, "name": {"API"}, "kind": {"application"}}
	samples := []url.Values{
		{"csrf": {"csrf-admin"}, "name": {"api"}, "kind": {"application"}, "documentation_url": {"javascript:alert(1)"}},
		{"csrf": {"csrf-admin"}, "name": {"api"}, "kind": {"application"}, "documentation_url": {"https://user:password@example.org/wiki"}},
		{"csrf": {"csrf-admin"}, "name": {"api"}, "kind": {"application"}, "ip_address": {"not-an-ip"}},
		{"csrf": {"csrf-admin"}, "name": {"api"}, "kind": {"unknown"}},
		{"csrf": {"csrf-admin"}, "name": {"api"}, "kind": {"server"}, "certificate_refs": {"manual:unknown"}},
	}
	for i, form := range samples {
		res := testSystemRequest(app, "POST", "/systems", "admin-session", form)
		if res.Code != 400 {
			t.Errorf("invalid example %d accepted: %d %s", i, res.Code, res.Body.String())
		}
	}
	res := testSystemRequest(app, "POST", "/systems", "admin-session", base)
	if res.Code != 303 {
		t.Fatalf("create: %d %s", res.Code, res.Body.String())
	}
	st := app.snapshot()
	if len(st.Systems) != 1 || len(st.Assignments) != 0 {
		t.Fatal("invalid inputs created records")
	}
	id := st.Systems[0].ID
	if got := testSystemRequest(app, "POST", "/dependencies/certificates/manual/manualweb", "admin-session", url.Values{"csrf": {"csrf-admin"}, "system_ids": {"missing-system"}}); got.Code != 400 {
		t.Fatalf("unknown system accepted: %d", got.Code)
	}
	// Refuse missing certificates; also forbid replacing any other relationship.
	if got := testSystemRequest(app, "POST", "/systems/"+id, "admin-session", url.Values{"csrf": {"csrf-admin"}, "name": {"API"}, "kind": {"server"}, "certificate_refs": {"target:other"}}); got.Code != 400 {
		t.Fatalf("unknown certificate accepted: %d", got.Code)
	}
	if len(app.snapshot().Assignments) != 0 {
		t.Fatal("invalid relations persisted")
	}
}
func TestDeleteCertificatePrunesSystemLinks(t *testing.T) {
	app := systemTestApp(t)
	app.mu.Lock()
	app.state.Systems = []System{{ID: "sys", Name: "Host", Kind: "server"}}
	app.state.Assignments = []SystemAssignment{{SystemID: "sys", CertificateRef: "target:target1"}, {SystemID: "sys", CertificateRef: "manual:manualweb"}, {SystemID: "sys", CertificateRef: "acme:web-live"}}
	app.mu.Unlock()
	resp := testSystemRequest(app, "POST", "/targets/target1/delete", "admin-session", url.Values{"csrf": {"csrf-admin"}})
	if resp.Code != 303 {
		t.Fatalf("delete target: %d %s", resp.Code, resp.Body.String())
	}
	st := app.snapshot()
	if len(st.Assignments) != 2 || len(st.Targets) != 0 {
		t.Fatal("target delete did not prune only its links")
	}
	resp = testSystemRequest(app, "POST", "/acme/certificates/web-live/delete", "admin-session", url.Values{"csrf": {"csrf-admin"}})
	if resp.Code != 303 {
		t.Fatalf("delete acme: %d %s", resp.Code, resp.Body.String())
	}
	st = app.snapshot()
	if len(st.Assignments) != 1 || st.Assignments[0].CertificateRef != "manual:manualweb" {
		t.Fatalf("incorrect pruned references: %v", st.Assignments)
	}
}

func TestTargetFormUsesSystemObjectsInsteadOfFreeText(t *testing.T) {
	app := systemTestApp(t)
	app.mu.Lock()
	app.state.Systems = []System{{ID: "host1", Name: "srv-intra-01", Kind: "server", IPAddress: "10.0.0.15"}}
	app.mu.Unlock()
	edit := testSystemRequest(app, "GET", "/targets/target1/edit", "admin-session", nil)
	if edit.Code != 200 || !strings.Contains(edit.Body.String(), `name="system_ids"`) || strings.Contains(edit.Body.String(), `name="server"`) {
		t.Fatalf("target form still uses free text instead of system inventory: status=%d", edit.Code)
	}
	values := url.Values{"csrf": {"csrf-admin"}, "name": {"Webportal TLS"}, "url": {"https://web.example.org"}, "interval": {"60"}, "root_policy": {"all"}, "system_ids": {"host1"}}
	result := testSystemRequest(app, "POST", "/targets/target1", "admin-session", values)
	if result.Code != 303 {
		t.Fatalf("save target with inventory references: %d %s", result.Code, result.Body.String())
	}
	st := app.snapshot()
	got := systemsForRef(st, "target:target1")
	if len(got) != 1 || got[0].ID != "host1" {
		t.Fatalf("target assignment not persisted: %v", got)
	}
	if page := testSystemRequest(app, "GET", "/targets/target1", "viewer-session", nil); page.Code != 200 || !strings.Contains(page.Body.String(), "srv-intra-01") {
		t.Fatalf("target details do not show system: %d", page.Code)
	}
}
