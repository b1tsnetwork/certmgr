package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const refreshMeta = `<meta http-equiv="refresh" content="30">`

func TestPageRefreshPolicy(t *testing.T) {
	// Keine der Verwaltungsseiten darf Formularinhalte regelmäßig zurücksetzen.
	cases := []struct {
		page     string
		template string
		refresh  bool
	}{
		{"dashboard", "dashboard", true},
		{"target-detail", "target_detail", true},
		{"acme", "acme", false},
		{"target-form", "target_form", false},
		{"roots", "roots", false},
		{"settings", "settings", false},
		{"users", "users", false},
		{"login", "login", false},
	}
	for _, tc := range cases {
		t.Run(tc.page, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			render(recorder, tc.template, PageData{
				Page:   tc.page,
				Title:  "Test",
				Counts: map[string]int{},
			})
			if recorder.Code != http.StatusOK {
				t.Fatalf("Seite %s konnte nicht gerendert werden: %d: %s", tc.page, recorder.Code, recorder.Body.String())
			}
			got := strings.Contains(recorder.Body.String(), refreshMeta)
			if got != tc.refresh {
				t.Fatalf("Seite %s: meta-refresh vorhanden=%t, erwartet=%t", tc.page, got, tc.refresh)
			}
		})
	}
}

func TestACMEPagePreservesForms(t *testing.T) {
	app, err := newApp(filepath.Join(t.TempDir(), "state.json"), "long-password-for-admin")
	if err != nil {
		t.Fatal(err)
	}
	app.acmeEnabled = true
	app.mu.Lock()
	app.sessions["test-token"] = session{
		csrf:    "test-csrf",
		userID:  app.state.Users[0].ID,
		expires: time.Now().Add(time.Hour),
	}
	app.mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/acme", nil)
	req.AddCookie(&http.Cookie{Name: "certwatch_session", Value: "test-token"})
	rr := httptest.NewRecorder()
	app.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("ACME-Seite: HTTP %d", rr.Code)
	}
	html := rr.Body.String()
	if strings.Contains(html, `http-equiv="refresh"`) {
		t.Fatal("ACME-Formularseite enthält einen automatischen Seiten-Refresh")
	}
	for _, wanted := range []string{
		`action="/acme/profiles"`,
		`action="/acme/certificates"`,
		`href="/acme"`,
		`name="dns_server"`,
	} {
		if !strings.Contains(html, wanted) {
			t.Errorf("Erwartete ACME-Funktion fehlt: %s", wanted)
		}
	}
}
