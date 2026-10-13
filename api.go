package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

func (s *server) routes() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, "ok")
	})
	m.HandleFunc("GET /static/style.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		b, _ := assets.ReadFile("static/style.css")
		w.Write(b)
	})
	m.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, "/admin", 303)
	})
	m.HandleFunc("GET /public", s.publicIndex)
	m.HandleFunc("GET /public/{name}", s.publicDetail)
	m.HandleFunc("POST /admin/profiles", s.protected(s.saveProfile))
	m.HandleFunc("GET /admin/profiles/{id}", s.profilePage)
	m.HandleFunc("POST /admin/profiles/{id}", s.protected(s.saveProfile))
	m.HandleFunc("POST /admin/profiles/{id}/delete", s.protected(s.deleteProfile))
	m.HandleFunc("GET /admin/login", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := s.auth.session(r); ok {
			http.Redirect(w, r, "/admin", 303)
			return
		}
		s.template(w, 200, "login.html", viewData{Title: "UCNG Cert Manager", AdminUser: s.cfg.adminUser})
	})
	m.HandleFunc("POST /admin/login", s.login)
	m.HandleFunc("GET /admin", s.dashboard)
	m.HandleFunc("POST /admin/logout", s.protected(s.logout))
	m.HandleFunc("POST /admin/sync", s.protected(func(w http.ResponseWriter, r *http.Request, _ authSession) {
		s.syncAll()
		http.Redirect(w, r, "/admin?sync=1", 303)
	}))
	m.HandleFunc("POST /admin/tokens", s.protected(s.createToken))
	m.HandleFunc("POST /admin/tokens/revoke", s.protected(s.revokeToken))
	m.HandleFunc("POST /admin/certificates", s.protected(s.saveCertificate))
	m.HandleFunc("GET /admin/certificates/{name}", s.certificatePage)
	m.HandleFunc("POST /admin/certificates/{name}", s.protected(s.saveCertificate))
	m.HandleFunc("POST /admin/certificates/{name}/delete", s.protected(s.deleteCertificateAdmin))
	m.HandleFunc("POST /admin/certificates/{name}/services", s.protected(s.createService))
	m.HandleFunc("GET /admin/services/{id}", s.servicePage)
	m.HandleFunc("POST /admin/services/{id}", s.protected(s.updateService))
	m.HandleFunc("POST /admin/services/{id}/delete", s.protected(s.deleteServiceAdmin))
	m.HandleFunc("GET /api/v1/services/{id}", s.apiServiceManifest)
	m.HandleFunc("GET /api/v1/services/{id}/versions/{version}/artifacts/{filename}", s.apiServiceArtifact)
	m.HandleFunc("GET /api/v1/certificates", s.apiList)
	m.HandleFunc("GET /api/v1/certificates/{name}", s.apiCertificate)
	m.HandleFunc("GET /api/v1/certificates/{name}/artifacts/{filename}", s.apiArtifact)
	m.HandleFunc("GET /api/v1/certificates/{name}/versions/{version}/artifacts/{filename}", s.apiArtifact)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; style-src 'self'; connect-src 'self'")
		m.ServeHTTP(w, r)
	})
}
func (s *server) renderData(ss authSession) viewData {
	d := viewData{Title: "UCNG Certificate Manager", CSRF: ss.CSRF, AdminUser: s.cfg.adminUser, FormatOptions: formatOptions}
	s.mu.RLock()
	defer s.mu.RUnlock()
	registry := s.catalog.snapshot()
	d.Profiles = registry.Profiles
	for _, def := range registry.Certificates {
		n := def.Name
		item := certificateView{Name: n, Label: def.Label, Profile: def.Profile, Enabled: def.Enabled, ExpectedSAN: strings.Join(def.DNSNames, ", "), Error: s.status[n]}
		for _, svc := range registry.Services {
			if svc.Certificate == n {
				item.ServiceCount++
			}
		}
		meta, e := s.vault.load(n, "")
		if e == nil {
			item.Version = meta.Version
			item.Fingerprint = meta.Fingerprint
			item.NotBefore = meta.NotBefore.Local().Format("02.01.2006")
			item.NotAfter = meta.NotAfter.Local().Format("02.01.2006 15:04")
			item.DNSNames = strings.Join(meta.DNSNames, ", ")
			item.Updated = meta.Published.Local().Format("02.01.2006 15:04")
		}
		if e != nil && item.Error == "" {
			item.Error = "Noch keine importierte Version"
		}
		d.Certificates = append(d.Certificates, item)
	}
	for _, svc := range registry.Services {
		m, _ := s.vault.load(svc.Certificate, "")
		d.Services = append(d.Services, displayService(svc, m))
	}
	for _, t := range s.auth.list() {
		access := "Öffentlich"
		if t.Private {
			access = "Privater Schlüssel + öffentlich"
		}
		scope := t.Certificate
		if t.ServiceID != "" {
			scope = "Dienst " + t.ServiceID + " (" + t.Certificate + ")"
		}
		d.Tokens = append(d.Tokens, tokenView{ID: t.ID, Label: t.Label, Certificate: scope, Access: access, Expires: t.Expires.Local().Format("02.01.2006"), Created: t.Created.Local().Format("02.01.2006")})
	}
	sort.Slice(d.Tokens, func(i, j int) bool { return d.Tokens[i].Label < d.Tokens[j].Label })
	return d
}
func (s *server) dashboard(w http.ResponseWriter, r *http.Request) {
	ss, ok := s.auth.session(r)
	if !ok {
		http.Redirect(w, r, "/admin/login", 303)
		return
	}
	d := s.renderData(ss)
	if r.URL.Query().Has("removed") {
		d.Notice = "Zertifikat entfernt; zugehörige Tokens widerrufen. Die verschlüsselten Versionen bleiben als Archiv erhalten."
	}
	if r.URL.Query().Has("profile_removed") {
		d.Notice = "ACME-Profil entfernt."
	}
	if r.URL.Query().Has("sync") {
		d.Notice = "Quellen wurden erneut eingelesen."
	}
	s.template(w, 200, "dashboard.html", d)
}
func (s *server) createToken(w http.ResponseWriter, r *http.Request, ss authSession) {
	n := r.PostForm.Get("certificate")
	svcID := r.PostForm.Get("service_id")
	if svcID != "" {
		svc, ok := s.catalog.service(svcID)
		if !ok || !s.configured(svc.Certificate) {
			http.Error(w, "Ungültiger Dienst", 400)
			return
		}
		n = svc.Certificate
	}
	if svcID == "" && n != "*" && !s.configured(n) {
		http.Error(w, "Ungültiges Zertifikat", 400)
		return
	}
	days := 90
	switch r.PostForm.Get("days") {
	case "30":
		days = 30
	case "90":
		days = 90
	case "365":
		days = 365
	default:
		http.Error(w, "Ungültige Gültigkeit", 400)
		return
	}
	var raw string
	var e error
	if svcID != "" {
		raw, e = s.auth.createService(strings.TrimSpace(r.PostForm.Get("label")), svcID, n, r.PostForm.Get("private") == "yes", days)
	} else {
		raw, e = s.auth.create(strings.TrimSpace(r.PostForm.Get("label")), n, r.PostForm.Get("private") == "yes", days)
	}
	if e != nil {
		http.Error(w, e.Error(), 400)
		return
	}
	d := s.renderData(ss)
	d.Token = raw
	d.Notice = "API-Token erzeugt. Er wird ausschließlich jetzt angezeigt. Sicher ablegen!"
	s.template(w, 200, "dashboard.html", d)
}
func (s *server) revokeToken(w http.ResponseWriter, r *http.Request, _ authSession) {
	if e := s.auth.revoke(r.PostForm.Get("id")); e != nil {
		http.Error(w, e.Error(), 400)
		return
	}
	http.Redirect(w, r, "/admin", 303)
}
func jsonReply(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if e := json.NewEncoder(w).Encode(data); e != nil {
		return
	}
}
func (s *server) apiList(w http.ResponseWriter, r *http.Request) {
	names := []string{}
	for _, def := range s.catalog.snapshot().Certificates {
		if def.Enabled {
			names = append(names, def.Name)
		}
	}
	jsonReply(w, map[string]any{"certificates": names})
}
func (s *server) apiCertificate(w http.ResponseWriter, r *http.Request) {
	n := r.PathValue("name")
	if !s.configured(n) {
		http.NotFound(w, r)
		return
	}
	meta, e := s.vault.load(n, "")
	if e != nil {
		http.Error(w, "Zertifikat nicht verfügbar", 404)
		return
	}
	if !s.auth.bearerAllowed(r, n, true) {
		var filtered []artifact
		for _, a := range meta.Artifacts {
			if !a.Private {
				filtered = append(filtered, a)
			}
		}
		meta.Artifacts = filtered
	}
	jsonReply(w, meta)
}
func (s *server) apiArtifact(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !s.configured(name) {
		http.NotFound(w, r)
		return
	}
	version := r.PathValue("version")
	meta, e := s.vault.load(name, version)
	if e != nil {
		http.NotFound(w, r)
		return
	}
	fn := r.PathValue("filename")
	var a *artifact
	for i := range meta.Artifacts {
		if meta.Artifacts[i].Name == fn {
			a = &meta.Artifacts[i]
			break
		}
	}
	if a == nil {
		http.NotFound(w, r)
		return
	}
	if a.Private && !s.auth.bearerAllowed(r, name, true) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="certificate-artifact"`)
		http.Error(w, "Bearer-Token mit Private-Key-Recht erforderlich", 401)
		return
	}
	body, e := s.vault.read(name, meta.Version, fn)
	if e != nil {
		http.Error(w, "Artefakt nicht verfügbar", 500)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", fn))
	w.Header().Set("X-Certificate-Version", meta.Version)
	http.ServeContent(w, r, fn, time.Time{}, bytes.NewReader(body))
}
