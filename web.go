package main

import (
	"bytes"
	"crypto/subtle"
	"embed"
	"encoding/pem"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed templates/*.html static/*
var assets embed.FS

type DashboardRow struct {
	Target  Target
	Next    time.Time
	Running bool
	Worst   string
}

type RootChoice struct {
	ID       string
	Name     string
	Selected bool
}

type RootRow struct {
	Root RootCA
	Cert CertInfo
}

type PageData struct {
	Page                   string
	Title                  string
	CSRF                   string
	Error                  string
	Notice                 string
	Settings               Settings
	Target                 Target
	Editing                bool
	Running                bool
	Rows                   []DashboardRow
	Roots                  []RootRow
	RootChoices            []RootChoice
	SystemTrustSelect      string
	Counts                 map[string]int
	MetaRaw                string
	WarnOverride           string
	CriticalOverride       string
	EffectiveWarning       int
	EffectiveCritical      int
	Now                    time.Time
	CurrentUser            string
	CurrentUserID          string
	CurrentRole            string
	CanEdit                bool
	IsAdmin                bool
	Users                  []User
	ACMEEnabled            bool
	Profiles               []ACMEProfile
	ACMECertificates       []ACMECertificate
	ACMECertificateOptions []ACMECertificate
	ACMEStatus             map[string]ACMEStatus
	ACMEProfileSelected    string
	DistributionTokens     []DistributionToken
	DistributionCerts      []ACMECertificate
	DistributionEnabled    bool
	PrivateExportEnabled   bool
	NewlyCreatedToken      string
	ManualCertificates     []ManualDisplay
	ManualVaultEnabled     bool
	DownloadEntries        []DownloadEntry
	DownloadSelection      *DownloadDetail
	Systems                []System
	SystemRows             []SystemRow
	CurrentSystem          System
	SystemEditing          bool
	AssignedSystemIDs      map[string]bool
	RelatedCertificates    []CertificateView
	RelatedSystems         []System
	CertViews              []CertificateView
	FocusCertificate       CertificateView
	FocusedSystem          *System
	FocusedCertificate     *CertificateView
	DependencyNodes        []GraphNode
}

var templateFuncs = template.FuncMap{
	"date": func(t time.Time) string {
		if t.IsZero() {
			return "–"
		}
		return t.Local().Format("02.01.2006 15:04")
	},
	"datetime": func(t time.Time) string {
		if t.IsZero() {
			return "–"
		}
		return t.Local().Format("02.01.2006 15:04:05 MST")
	},
	"isEmpty": func(t string) bool { return strings.TrimSpace(t) == "" },
}

func render(w http.ResponseWriter, page string, d PageData) {
	t, err := template.New("base.html").Funcs(templateFuncs).ParseFS(assets, "templates/base.html", "templates/"+page+".html")
	if err != nil {
		log.Printf("template parse: %v", err)
		http.Error(w, "template error", 500)
		return
	}
	var out bytes.Buffer
	if err := t.ExecuteTemplate(&out, "base.html", d); err != nil {
		log.Printf("template execute: %v", err)
		http.Error(w, "template error", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = out.WriteTo(w)
}

func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'")
		w.Header().Set("Cache-Control", "no-store")
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		r.Body = http.MaxBytesReader(w, r.Body, 8<<20)
		next.ServeHTTP(w, r)
	})
}

func (a *App) sessionFor(r *http.Request) (session, bool) {
	c, err := r.Cookie("certwatch_session")
	if err != nil {
		return session{}, false
	}
	a.mu.RLock()
	s, ok := a.sessions[c.Value]
	a.mu.RUnlock()
	if !ok || time.Now().After(s.expires) {
		return session{}, false
	}
	a.mu.RLock()
	exists := false
	for _, u := range a.state.Users {
		if u.ID == s.userID {
			exists = true
			break
		}
	}
	a.mu.RUnlock()
	return s, exists
}
func (a *App) withAuth(post bool, fn func(http.ResponseWriter, *http.Request, session)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := a.sessionFor(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if post && (r.FormValue("csrf") == "" || subtle.ConstantTimeCompare([]byte(r.FormValue("csrf")), []byte(sess.csrf)) != 1) {
			http.Error(w, "Ungültiger CSRF-Schutz. Bitte Seite neu laden.", http.StatusForbidden)
			return
		}
		if post && r.URL.Path != "/logout" && r.URL.Path != "/settings/password" && !a.userHasRole(sess.userID, "editor") {
			http.Error(w, "Keine Schreibberechtigung", http.StatusForbidden)
			return
		}
		fn(w, r, sess)
	}
}
func (a *App) userHasRole(id, minRole string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	levels := map[string]int{"viewer": 1, "editor": 2, "admin": 3}
	minimum := levels[minRole]
	if minimum == 0 {
		return false
	}
	for _, u := range a.state.Users {
		if u.ID == id {
			return levels[u.Role] >= minimum
		}
	}
	return false
}
func (a *App) onlyRole(role string, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s, ok := a.sessionFor(r)
		if !ok {
			http.Redirect(w, r, "/login", 303)
			return
		}
		if !a.userHasRole(s.userID, role) {
			http.Error(w, "Keine Berechtigung", 403)
			return
		}
		handler(w, r)
	}
}
func pageData(title, page string, s session, st State) PageData {
	d := PageData{Title: title, Page: page, CSRF: s.csrf, Settings: st.Settings, Now: time.Now(), Counts: map[string]int{"green": 0, "yellow": 0, "red": 0, "pending": 0}}
	for _, u := range st.Users {
		if u.ID == s.userID {
			d.CurrentUser = u.Username
			d.CurrentUserID = u.ID
			d.CurrentRole = u.Role
			d.CanEdit = u.Role != "viewer"
			d.IsAdmin = u.Role == "admin"
			break
		}
	}
	d.Systems = st.Systems
	d.Profiles = st.ACMEProfiles
	d.ACMECertificates = st.ACMECerts
	return d
}

func (a *App) routes() http.Handler {
	mux := http.NewServeMux()
	static, _ := assets.ReadFile("static/style.css")
	mux.HandleFunc("GET /static/style.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Write(static)
	})
	mux.HandleFunc("GET /login", a.showLogin)
	mux.HandleFunc("POST /login", a.postLogin)
	mux.HandleFunc("POST /logout", a.withAuth(true, a.logout))
	mux.HandleFunc("GET /", a.withAuth(false, a.dashboard))
	mux.HandleFunc("GET /systems", a.withAuth(false, a.systemsPage))
	mux.HandleFunc("GET /systems/new", a.onlyRole("editor", a.withAuth(false, a.newSystemPage)))
	mux.HandleFunc("POST /systems", a.onlyRole("editor", a.withAuth(true, a.createSystem)))
	mux.HandleFunc("GET /systems/{id}", a.withAuth(false, a.systemDetail))
	mux.HandleFunc("GET /systems/{id}/edit", a.onlyRole("editor", a.withAuth(false, a.editSystemPage)))
	mux.HandleFunc("POST /systems/{id}", a.onlyRole("editor", a.withAuth(true, a.updateSystem)))
	mux.HandleFunc("POST /systems/{id}/delete", a.onlyRole("editor", a.withAuth(true, a.deleteSystem)))
	mux.HandleFunc("GET /dependencies", a.withAuth(false, a.dependenciesPage))
	mux.HandleFunc("GET /dependencies/certificates/{kind}/{id}", a.withAuth(false, a.certificateRelations))
	mux.HandleFunc("POST /dependencies/certificates/{kind}/{id}", a.onlyRole("editor", a.withAuth(true, a.updateCertificateRelations)))
	mux.HandleFunc("GET /targets/new", a.onlyRole("editor", a.withAuth(false, a.showNewTarget)))
	mux.HandleFunc("POST /targets", a.withAuth(true, a.createTarget))
	mux.HandleFunc("GET /targets/{id}", a.withAuth(false, a.targetDetails))
	mux.HandleFunc("GET /targets/{id}/edit", a.onlyRole("editor", a.withAuth(false, a.showEditTarget)))
	mux.HandleFunc("POST /targets/{id}", a.withAuth(true, a.updateTarget))
	mux.HandleFunc("POST /targets/{id}/delete", a.withAuth(true, a.deleteTarget))
	mux.HandleFunc("POST /targets/{id}/check", a.withAuth(true, a.checkNow))
	mux.HandleFunc("GET /roots", a.withAuth(false, a.rootsPage))
	mux.HandleFunc("POST /roots", a.withAuth(true, a.addRoots))
	mux.HandleFunc("POST /roots/{id}/delete", a.withAuth(true, a.deleteRoot))
	mux.HandleFunc("GET /settings", a.withAuth(false, a.settingsPage))
	mux.HandleFunc("POST /settings", a.onlyRole("admin", a.withAuth(true, a.updateSettings)))
	mux.HandleFunc("POST /settings/password", a.withAuth(true, a.updatePassword))
	mux.HandleFunc("GET /users", a.onlyRole("admin", a.withAuth(false, a.usersPage)))
	mux.HandleFunc("POST /users", a.onlyRole("admin", a.withAuth(true, a.createUser)))
	mux.HandleFunc("POST /users/{id}/role", a.onlyRole("admin", a.withAuth(true, a.changeUserRole)))
	mux.HandleFunc("POST /users/{id}/password", a.onlyRole("admin", a.withAuth(true, a.resetUserPassword)))
	mux.HandleFunc("POST /users/{id}/delete", a.onlyRole("admin", a.withAuth(true, a.deleteUser)))
	mux.HandleFunc("GET /acme", a.withAuth(false, a.acmePage))
	mux.HandleFunc("GET /manual", a.onlyRole("admin", a.withAuth(false, a.manualPage)))
	mux.HandleFunc("POST /manual/upload", a.onlyRole("admin", a.withAuth(true, a.uploadManual)))
	mux.HandleFunc("POST /manual/{name}/delete", a.onlyRole("admin", a.withAuth(true, a.deleteManual)))
	mux.HandleFunc("GET /downloads", a.onlyRole("viewer", a.withAuth(false, a.downloadPage)))
	mux.HandleFunc("GET /downloads/{profile}/{name}", a.onlyRole("viewer", a.withAuth(false, a.downloadDetail)))
	mux.HandleFunc("GET /downloads/{profile}/{name}/versions/{version}/artifacts/{file}", a.onlyRole("viewer", a.withAuth(false, a.browserDownload)))
	mux.HandleFunc("GET /distribution", a.onlyRole("admin", a.withAuth(false, a.distributionPage)))
	mux.HandleFunc("POST /distribution/tokens", a.onlyRole("admin", a.withAuth(true, a.createDistributionToken)))
	mux.HandleFunc("POST /distribution/tokens/{id}/revoke", a.onlyRole("admin", a.withAuth(true, a.revokeDistributionToken)))
	mux.HandleFunc("GET /api/v1/distribution/{profile}/{name}/manifest", a.apiDistributionManifest)
	mux.HandleFunc("GET /api/v1/distribution/{profile}/{name}/artifacts/{file}", a.apiDistributionArtifact)
	mux.HandleFunc("GET /api/v1/distribution/{profile}/{name}/versions/{version}/artifacts/{file}", a.apiDistributionArtifact)
	mux.HandleFunc("POST /acme/profiles", a.onlyRole("admin", a.withAuth(true, a.saveACMEProfile)))
	mux.HandleFunc("POST /acme/profiles/{id}/delete", a.onlyRole("admin", a.withAuth(true, a.deleteACMEProfile)))
	mux.HandleFunc("POST /acme/certificates", a.onlyRole("editor", a.withAuth(true, a.saveACMECertificate)))
	mux.HandleFunc("POST /acme/certificates/{name}/delete", a.onlyRole("editor", a.withAuth(true, a.deleteACMECertificate)))
	return secureHeaders(mux)
}

func (a *App) showLogin(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.sessionFor(r); ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	render(w, "login", PageData{Title: "Anmelden", Page: "login"})
}

func (a *App) postLogin(w http.ResponseWriter, r *http.Request) {
	// Browser submissions from an unrelated origin must not create a session.
	if origin := r.Header.Get("Origin"); origin != "" {
		u, err := url.Parse(origin)
		if err != nil || !strings.EqualFold(u.Host, r.Host) || (u.Scheme != "http" && u.Scheme != "https") {
			http.Error(w, "Unzulässiger Origin", 403)
			return
		}
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	now := time.Now()
	a.mu.Lock()
	attempts := a.loginAttempts[ip][:0]
	for _, v := range a.loginAttempts[ip] {
		if now.Sub(v) < 10*time.Minute {
			attempts = append(attempts, v)
		}
	}
	if len(attempts) >= 10 {
		a.loginAttempts[ip] = attempts
		a.mu.Unlock()
		http.Error(w, "Zu viele Versuche. Bitte später erneut versuchen.", 429)
		return
	}
	a.loginAttempts[ip] = append(attempts, now)
	username := strings.TrimSpace(r.FormValue("username"))
	var user User
	for _, u := range a.state.Users {
		if u.Username == username {
			user = u
			break
		}
	}
	a.mu.Unlock()
	if !user.Password.matches(r.FormValue("password")) {
		w.WriteHeader(http.StatusUnauthorized)
		render(w, "login", PageData{Title: "Anmelden", Page: "login", Error: "Passwort ist nicht korrekt."})
		return
	}
	id, e1 := newID()
	csrf, e2 := newID()
	if e1 != nil || e2 != nil {
		http.Error(w, "Zufallsquelle nicht verfügbar", 500)
		return
	}
	a.mu.Lock()
	delete(a.loginAttempts, ip)
	a.sessions[id] = session{csrf: csrf, userID: user.ID, expires: now.Add(12 * time.Hour)}
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "certwatch_session", Value: id, Path: "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: 12 * 3600})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
func (a *App) logout(w http.ResponseWriter, r *http.Request, s session) {
	if cookie, err := r.Cookie("certwatch_session"); err == nil {
		a.mu.Lock()
		delete(a.sessions, cookie.Value)
		a.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "certwatch_session", Value: "", Path: "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (a *App) dashboard(w http.ResponseWriter, r *http.Request, s session) {
	st := a.snapshot()
	d := pageData("Dashboard", "dashboard", s, st)
	for _, t := range st.Targets {
		row := DashboardRow{Target: t, Running: a.isRunning(t.ID)}
		if t.LastCheck == nil {
			d.Counts["pending"]++
		} else {
			d.Counts[t.LastCheck.Status]++
			row.Next = t.LastCheck.CheckedAt.Add(time.Duration(t.IntervalMinutes) * time.Minute)
			if len(t.LastCheck.Chain) > 0 {
				c := t.LastCheck.Chain[0]
				for _, other := range t.LastCheck.Chain[1:] {
					if other.NotAfter.Before(c.NotAfter) {
						c = other
					}
				}
				row.Worst = c.TimeText
			}
		}
		d.Rows = append(d.Rows, row)
	}
	sort.Slice(d.Rows, func(i, j int) bool {
		return strings.ToLower(d.Rows[i].Target.Name) < strings.ToLower(d.Rows[j].Target.Name)
	})
	if r.URL.Query().Get("notice") == "deleted" {
		d.Notice = "Ziel wurde gelöscht."
	}
	render(w, "dashboard", d)
}

func parseOptionalDay(v string) (*int, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 || n > 3650 {
		return nil, fmt.Errorf("Schwellwerte müssen zwischen 0 und 3650 Tagen liegen")
	}
	return &n, nil
}
func metadataToRaw(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var lines []string
	for _, k := range keys {
		lines = append(lines, k+"="+m[k])
	}
	return strings.Join(lines, "\n")
}
func parseMetadata(raw string) (map[string]string, error) {
	out := map[string]string{}
	for i, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if !ok || len(k) == 0 || len(k) > 100 || len(v) > 500 {
			return nil, fmt.Errorf("Zusatzfeld in Zeile %d benötigt das Format Schlüssel=Wert (max. 100/500 Zeichen)", i+1)
		}
		out[k] = v
		if len(out) > 40 {
			return nil, fmt.Errorf("maximal 40 Zusatzfelder")
		}
	}
	return out, nil
}
func parseTargetForm(r *http.Request, global Settings, knownRoots []RootCA) (Target, error) {
	get := func(name string) string { return strings.TrimSpace(r.FormValue(name)) }
	t := Target{Name: get("name"), URL: get("url"), SNI: get("sni"), Formats: get("formats"), Environment: get("environment"), Owner: get("owner"), Notes: get("notes"), RootPolicy: get("root_policy"), ACMECert: get("acme_certificate")}
	rawURL, _, _, err := parseTargetURL(t.URL)
	if err != nil {
		return t, err
	}
	t.URL = rawURL
	interval, err := strconv.Atoi(get("interval"))
	if err != nil || interval < 1 || interval > 10080 {
		return t, fmt.Errorf("Prüfintervall muss zwischen 1 und 10080 Minuten liegen")
	}
	t.IntervalMinutes = interval
	t.WarningDays, err = parseOptionalDay(get("warn"))
	if err != nil {
		return t, err
	}
	t.CriticalDays, err = parseOptionalDay(get("critical"))
	if err != nil {
		return t, err
	}
	switch get("system_trust") {
	case "", "inherit":
	case "yes":
		b := true
		t.TrustSystem = &b
	case "no":
		b := false
		t.TrustSystem = &b
	default:
		return t, fmt.Errorf("Ungültige System-Root-Einstellung")
	}
	if t.RootPolicy != "" && t.RootPolicy != "all" && t.RootPolicy != "selected" {
		return t, fmt.Errorf("Ungültige Root-CA-Auswahl")
	}
	if t.RootPolicy == "selected" {
		valid := map[string]bool{}
		for _, root := range knownRoots {
			valid[root.ID] = true
		}
		seen := map[string]bool{}
		for _, id := range r.Form["root_ids"] {
			if !valid[id] {
				return t, fmt.Errorf("Nicht bekanntes Root-CA-Zertifikat")
			}
			if !seen[id] {
				t.RootIDs = append(t.RootIDs, id)
				seen[id] = true
			}
		}
	} else {
		t.RootPolicy = "all"
	}
	if len(t.Name) == 0 || len(t.Name) > 100 {
		return t, fmt.Errorf("Anzeigename benötigt 1 bis 100 Zeichen")
	}
	if len(t.URL) > 2048 || len(t.SNI) > 253 || len(t.Server) > 200 || len(t.Formats) > 200 || len(t.Environment) > 100 || len(t.Owner) > 150 || len(t.Notes) > 3000 {
		return t, fmt.Errorf("Ein oder mehrere Textfelder sind zu lang")
	}
	if strings.ContainsAny(t.SNI, " /\\?#@:") {
		return t, fmt.Errorf("SNI muss ein Hostname oder eine IP-Adresse ohne Port sein")
	}
	if len(t.ACMECert) > 128 {
		return t, fmt.Errorf("ACME-Zertifikatsname zu lang")
	}
	t.Metadata, err = parseMetadata(get("metadata"))
	if err != nil {
		return t, err
	}
	warning, critical := effectiveThresholds(t, global)
	if warning < critical {
		return t, fmt.Errorf("Warnschwelle muss größer oder gleich der kritischen Schwelle sein")
	}
	return t, nil
}
func formData(t Target, edit bool, s session, st State) PageData {
	d := pageData("Ziel konfigurieren", "target-form", s, st)
	d.Target = t
	d.Editing = edit
	d.MetaRaw = metadataToRaw(t.Metadata)
	selected := map[string]bool{}
	for _, id := range t.RootIDs {
		selected[id] = true
	}
	for _, root := range st.Roots {
		d.RootChoices = append(d.RootChoices, RootChoice{ID: root.ID, Name: root.Name, Selected: selected[root.ID]})
	}
	d.ACMECertificateOptions = st.ACMECerts
	d.AssignedSystemIDs = assignedSystems(st, "target:"+t.ID)
	d.SystemTrustSelect = "inherit"
	if t.TrustSystem != nil {
		if *t.TrustSystem {
			d.SystemTrustSelect = "yes"
		} else {
			d.SystemTrustSelect = "no"
		}
	}
	if t.WarningDays != nil {
		d.WarnOverride = strconv.Itoa(*t.WarningDays)
	}
	if t.CriticalDays != nil {
		d.CriticalOverride = strconv.Itoa(*t.CriticalDays)
	}
	return d
}
func (a *App) showNewTarget(w http.ResponseWriter, r *http.Request, s session) {
	st := a.snapshot()
	render(w, "target_form", formData(Target{IntervalMinutes: 60}, false, s, st))
}
func (a *App) createTarget(w http.ResponseWriter, r *http.Request, s session) {
	st := a.snapshot()
	t, err := parseTargetForm(r, st.Settings, st.Roots)
	if err == nil {
		err = validateTargetACME(t, st.ACMECerts)
	}
	if err == nil {
		_, err = validSystemSelection(r.Form["system_ids"], st)
	}
	if err != nil {
		d := formData(t, false, s, st)
		d.Error = err.Error()
		w.WriteHeader(400)
		render(w, "target_form", d)
		return
	}
	t.ID, err = newID()
	if err != nil {
		http.Error(w, "ID konnte nicht erstellt werden", 500)
		return
	}
	t.Revision = 1
	a.mu.Lock()
	a.state.Targets = append(a.state.Targets, t)
	err = setCertificateAssignmentsLocked(&a.state, "target:"+t.ID, r.Form["system_ids"])
	if err == nil {
		err = a.saveLocked()
	}
	a.mu.Unlock()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	a.queueCheck(t.ID)
	http.Redirect(w, r, "/targets/"+t.ID, http.StatusSeeOther)
}
func (a *App) showEditTarget(w http.ResponseWriter, r *http.Request, s session) {
	st := a.snapshot()
	t := findTarget(&st, r.PathValue("id"))
	if t == nil {
		http.NotFound(w, r)
		return
	}
	render(w, "target_form", formData(*t, true, s, st))
}
func (a *App) updateTarget(w http.ResponseWriter, r *http.Request, s session) {
	st := a.snapshot()
	orig := findTarget(&st, r.PathValue("id"))
	if orig == nil {
		http.NotFound(w, r)
		return
	}
	t, err := parseTargetForm(r, st.Settings, st.Roots)
	if err == nil {
		err = validateTargetACME(t, st.ACMECerts)
	}
	if err == nil {
		_, err = validSystemSelection(r.Form["system_ids"], st)
	}
	if err != nil {
		t.ID = orig.ID
		d := formData(t, true, s, st)
		d.Error = err.Error()
		w.WriteHeader(400)
		render(w, "target_form", d)
		return
	}
	a.mu.Lock()
	current := findTarget(&a.state, orig.ID)
	if current == nil {
		a.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	t.ID = current.ID
	t.Revision = current.Revision + 1
	// Retain the old free-text value for legacy inspection but use System objects from now on.
	t.Server = current.Server
	*current = t
	err = setCertificateAssignmentsLocked(&a.state, "target:"+t.ID, r.Form["system_ids"])
	if err == nil {
		err = a.saveLocked()
	}
	a.mu.Unlock()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	a.queueCheck(t.ID)
	http.Redirect(w, r, "/targets/"+t.ID, http.StatusSeeOther)
}
func (a *App) deleteTarget(w http.ResponseWriter, r *http.Request, s session) {
	id := r.PathValue("id")
	a.mu.Lock()
	found := false
	for i, t := range a.state.Targets {
		if t.ID == id {
			a.state.Targets = append(a.state.Targets[:i], a.state.Targets[i+1:]...)
			pruneCertificateAssignments(&a.state, "target:"+id)
			found = true
			break
		}
	}
	if found {
		if err := a.saveLocked(); err != nil {
			log.Print(err)
			a.mu.Unlock()
			http.Error(w, "Speicherfehler", 500)
			return
		}
	}
	a.mu.Unlock()
	if !found {
		http.NotFound(w, r)
		return
	}
	http.Redirect(w, r, "/?notice=deleted", http.StatusSeeOther)
}
func (a *App) checkNow(w http.ResponseWriter, r *http.Request, s session) {
	if !a.queueCheck(r.PathValue("id")) {
		http.Redirect(w, r, "/targets/"+r.PathValue("id"), 303)
		return
	}
	http.Redirect(w, r, "/targets/"+r.PathValue("id"), 303)
}
func (a *App) targetDetails(w http.ResponseWriter, r *http.Request, s session) {
	st := a.snapshot()
	t := findTarget(&st, r.PathValue("id"))
	if t == nil {
		http.NotFound(w, r)
		return
	}
	d := pageData(t.Name, "target-detail", s, st)
	d.Target = *t
	d.RelatedSystems = systemsForRef(st, "target:"+t.ID)
	d.Running = a.isRunning(t.ID)
	d.EffectiveWarning, d.EffectiveCritical = effectiveThresholds(*t, st.Settings)
	d.SystemTrustSelect = "Nein"
	if effectiveSystemRoots(*t, st.Settings) {
		d.SystemTrustSelect = "Ja"
	}
	render(w, "target_detail", d)
}

func (a *App) rootsPage(w http.ResponseWriter, r *http.Request, s session) {
	st := a.snapshot()
	d := pageData("Vertrauenswürdige Stammzertifikate", "roots", s, st)
	for _, root := range st.Roots {
		certs, err := parseRootPEM(root.PEM)
		if err != nil || len(certs) != 1 {
			continue
		}
		d.Roots = append(d.Roots, RootRow{Root: root, Cert: getCertInfo(certs[0], "Stammzertifikat", "Eigener Vertrauensspeicher", d.Now, st.Settings.WarningDays, st.Settings.CriticalDays)})
	}
	switch r.URL.Query().Get("notice") {
	case "added":
		d.Notice = "Stammzertifikat(e) importiert. Alle Ziele werden neu geprüft."
	case "deleted":
		d.Notice = "Stammzertifikat entfernt. Alle Ziele werden neu geprüft."
	}
	render(w, "roots", d)
}
func (a *App) invalidateAll() []string {
	ids := make([]string, 0, len(a.state.Targets))
	for i := range a.state.Targets {
		a.state.Targets[i].Revision++
		a.state.Targets[i].LastCheck = nil
		ids = append(ids, a.state.Targets[i].ID)
	}
	return ids
}
func (a *App) addRoots(w http.ResponseWriter, r *http.Request, s session) {
	st := a.snapshot()
	raw := strings.TrimSpace(r.FormValue("pem"))
	name := strings.TrimSpace(r.FormValue("name"))
	file, _, err := r.FormFile("file")
	if err == nil {
		defer file.Close()
		data, err := io.ReadAll(io.LimitReader(file, 1<<20))
		if err != nil {
			http.Error(w, "Datei nicht lesbar", 400)
			return
		}
		raw = strings.TrimSpace(string(data))
	}
	fail := func(msg string) {
		d := pageData("Vertrauenswürdige Stammzertifikate", "roots", s, st)
		d.Error = msg
		w.WriteHeader(400)
		render(w, "roots", d)
	}
	certs, err := parseRootPEM(raw)
	if err != nil {
		fail(err.Error())
		return
	}
	if len(name) > 100 {
		fail("Bezeichnung maximal 100 Zeichen")
		return
	}
	var roots []RootCA
	for i, cert := range certs {
		id, err := newID()
		if err != nil {
			fail("ID-Generierung fehlgeschlagen")
			return
		}
		entryName := name
		if entryName == "" {
			entryName = certName(cert)
		} else if len(certs) > 1 {
			entryName = fmt.Sprintf("%s (%d)", name, i+1)
		}
		roots = append(roots, RootCA{ID: id, Name: entryName, PEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})), AddedAt: time.Now().UTC(), Fingerprint: fingerprint(cert.Raw)})
	}
	a.mu.Lock()
	existing := map[string]bool{}
	for _, v := range a.state.Roots {
		existing[v.Fingerprint] = true
	}
	for _, v := range roots {
		if existing[v.Fingerprint] {
			a.mu.Unlock()
			fail("Eines der Stammzertifikate ist bereits hinterlegt")
			return
		}
		existing[v.Fingerprint] = true
	}
	a.state.Roots = append(a.state.Roots, roots...)
	ids := a.invalidateAll()
	err = a.saveLocked()
	a.mu.Unlock()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	for _, id := range ids {
		a.queueCheck(id)
	}
	http.Redirect(w, r, "/roots?notice=added", 303)
}
func (a *App) deleteRoot(w http.ResponseWriter, r *http.Request, s session) {
	a.mu.Lock()
	found := false
	for i, root := range a.state.Roots {
		if root.ID == r.PathValue("id") {
			a.state.Roots = append(a.state.Roots[:i], a.state.Roots[i+1:]...)
			for j := range a.state.Targets {
				ids := a.state.Targets[j].RootIDs[:0]
				for _, id := range a.state.Targets[j].RootIDs {
					if id != root.ID {
						ids = append(ids, id)
					}
				}
				a.state.Targets[j].RootIDs = ids
			}
			found = true
			break
		}
	}
	var ids []string
	var err error
	if found {
		ids = a.invalidateAll()
		err = a.saveLocked()
	}
	a.mu.Unlock()
	if !found {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	for _, id := range ids {
		a.queueCheck(id)
	}
	http.Redirect(w, r, "/roots?notice=deleted", 303)
}
func (a *App) settingsPage(w http.ResponseWriter, r *http.Request, s session) {
	st := a.snapshot()
	d := pageData("Einstellungen", "settings", s, st)
	if r.URL.Query().Get("notice") == "saved" {
		d.Notice = "Einstellungen wurden übernommen."
	}
	if r.URL.Query().Get("notice") == "password" {
		d.Notice = "Passwort wurde geändert. Bitte bei Bedarf erneut anmelden."
	}
	render(w, "settings", d)
}
func (a *App) updateSettings(w http.ResponseWriter, r *http.Request, s session) {
	st := a.snapshot()
	d := pageData("Einstellungen", "settings", s, st)
	warn, e1 := strconv.Atoi(r.FormValue("warning"))
	crit, e2 := strconv.Atoi(r.FormValue("critical"))
	if e1 != nil || e2 != nil || crit < 0 || warn < crit || warn > 3650 {
		d.Error = "Warnschwelle muss ≥ kritischer Schwelle sein (0–3650 Tage)."
		w.WriteHeader(400)
		render(w, "settings", d)
		return
	}
	newSettings := Settings{WarningDays: warn, CriticalDays: crit, UseSystemRoots: r.FormValue("system_roots") == "on"}
	for _, target := range st.Targets {
		warnDays, critDays := effectiveThresholds(target, newSettings)
		if warnDays < critDays {
			d.Error = fmt.Sprintf("Neue Standardschwellen sind mit individuellen Werten für %q unvereinbar (Gelb %d < Rot %d).", target.Name, warnDays, critDays)
			w.WriteHeader(400)
			render(w, "settings", d)
			return
		}
	}
	a.mu.Lock()
	a.state.Settings = newSettings
	ids := a.invalidateAll()
	err := a.saveLocked()
	a.mu.Unlock()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	for _, id := range ids {
		a.queueCheck(id)
	}
	http.Redirect(w, r, "/settings?notice=saved", 303)
}
func (a *App) updatePassword(w http.ResponseWriter, r *http.Request, s session) {
	st := a.snapshot()
	d := pageData("Einstellungen", "settings", s, st)
	old, newPass, confirm := r.FormValue("old_password"), r.FormValue("new_password"), r.FormValue("confirm_password")
	var me *User
	for i := range st.Users {
		if st.Users[i].ID == s.userID {
			me = &st.Users[i]
			break
		}
	}
	if me == nil || !me.Password.matches(old) {
		d.Error = "Bisheriges Passwort stimmt nicht."
		w.WriteHeader(400)
		render(w, "settings", d)
		return
	}
	if newPass != confirm {
		d.Error = "Neue Passwörter stimmen nicht überein."
		w.WriteHeader(400)
		render(w, "settings", d)
		return
	}
	h, err := hashPassword(newPass)
	if err != nil {
		d.Error = err.Error()
		w.WriteHeader(400)
		render(w, "settings", d)
		return
	}
	a.mu.Lock()
	for i := range a.state.Users {
		if a.state.Users[i].ID == s.userID {
			a.state.Users[i].Password = h
		}
	}
	err = a.saveLocked()
	for id, ss := range a.sessions {
		if ss.userID == s.userID {
			delete(a.sessions, id)
		}
	}
	a.mu.Unlock()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "certwatch_session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil})
	http.Redirect(w, r, "/login", 303)
}
