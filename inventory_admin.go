package main

import (
	"net/http"
	"strings"
)

func (s *server) certificatePage(w http.ResponseWriter, r *http.Request) {
	ss, ok := s.auth.session(r)
	if !ok {
		http.Redirect(w, r, "/admin/login", 303)
		return
	}
	def, ok := s.catalog.certificate(r.PathValue("name"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	d := viewData{Title: "Zertifikat verwalten · " + def.Name, CSRF: ss.CSRF, FormatOptions: formatOptions, Profiles: s.catalog.snapshot().Profiles}
	d.Certificate = certificateView{Name: def.Name, Label: def.Label, Profile: def.Profile, Enabled: def.Enabled, ExpectedSAN: strings.Join(def.DNSNames, ", ")}
	meta, _ := s.vault.load(def.Name, "")
	d.FormatOptions = formatOptionsFor(meta)
	d.FormatGroups = groupFormats(d.FormatOptions)
	if meta.Version != "" {
		d.Certificate.Version = meta.Version
		d.Certificate.NotAfter = meta.NotAfter.Local().Format("02.01.2006 15:04")
		d.Certificate.DNSNames = strings.Join(meta.DNSNames, ", ")
	}
	for _, svc := range s.catalog.snapshot().Services {
		if svc.Certificate == def.Name {
			d.Services = append(d.Services, displayService(svc, meta))
		}
	}
	if r.URL.Query().Has("saved") {
		d.Notice = "Änderungen gespeichert."
	}
	if r.URL.Query().Has("deleted") {
		d.Notice = "Dienst entfernt; zugehörige Tokens widerrufen."
	}
	s.template(w, 200, "certificate.html", d)
}
func (s *server) saveCertificate(w http.ResponseWriter, r *http.Request, _ authSession) {
	name := r.PostForm.Get("name")
	if pathName := r.PathValue("name"); pathName != "" && name != pathName {
		http.Error(w, "Zertifikatsname darf nicht geändert werden", 400)
		return
	}
	old, existing := s.catalog.certificate(name)
	if r.PathValue("name") == "" && existing {
		http.Error(w, "Zertifikat existiert bereits", 409)
		return
	}
	if r.PathValue("name") != "" && !existing {
		http.NotFound(w, r)
		return
	}
	newDef := certificateDefinition{Name: name, Profile: r.PostForm.Get("profile"), Label: strings.TrimSpace(r.PostForm.Get("label")), DNSNames: sanitizeSANInput(r.PostForm.Get("sans")), Enabled: r.PostForm.Get("enabled") == "yes"}
	if !existing && r.PostForm.Get("enabled") == "" {
		newDef.Enabled = true
	}
	if e := s.catalog.upsertCertificate(newDef); e != nil {
		http.Error(w, e.Error(), 400)
		return
	}
	if existing && old.Enabled && !newDef.Enabled {
		s.mu.Lock()
		delete(s.status, name)
		s.mu.Unlock()
	}
	// Import only after the request is validated and stored. Import failure is
	// reported on the dashboard, never accepted as a reason to skip the record.
	if newDef.Enabled {
		if e := s.importCertificate(name); e != nil {
			s.mu.Lock()
			s.status[name] = e.Error()
			s.mu.Unlock()
		} else {
			s.mu.Lock()
			delete(s.status, name)
			s.mu.Unlock()
		}
	}
	http.Redirect(w, r, "/admin/certificates/"+name+"?saved=1", 303)
}
func (s *server) deleteCertificateAdmin(w http.ResponseWriter, r *http.Request, _ authSession) {
	name := r.PathValue("name")
	if _, ok := s.catalog.certificate(name); !ok {
		http.NotFound(w, r)
		return
	}
	if r.PostForm.Get("confirm") != name {
		http.Error(w, "Bestätigung mit Zertifikatsnamen erforderlich", 400)
		return
	}
	if e := s.auth.revokeScope(name, ""); e != nil {
		http.Error(w, "Token-Widerruf fehlgeschlagen", 500)
		return
	}
	if e := s.catalog.deleteCertificate(name); e != nil {
		http.Error(w, e.Error(), 500)
		return
	}
	s.mu.Lock()
	delete(s.status, name)
	s.mu.Unlock()
	http.Redirect(w, r, "/admin?removed=1", 303)
}
func (s *server) createService(w http.ResponseWriter, r *http.Request, _ authSession) {
	cert := r.PathValue("name")
	if _, ok := s.catalog.certificate(cert); !ok {
		http.NotFound(w, r)
		return
	}
	svc := serviceRecord{Certificate: cert, Name: strings.TrimSpace(r.PostForm.Get("name")), Kind: r.PostForm.Get("kind"), Host: strings.TrimSpace(r.PostForm.Get("host")), Environment: strings.TrimSpace(r.PostForm.Get("environment")), Notes: strings.TrimSpace(r.PostForm.Get("notes")), Files: r.PostForm["files"]}
	if _, e := s.catalog.upsertService(svc); e != nil {
		http.Error(w, e.Error(), 400)
		return
	}
	http.Redirect(w, r, "/admin/certificates/"+cert+"?saved=1", 303)
}
func (s *server) servicePage(w http.ResponseWriter, r *http.Request) {
	ss, ok := s.auth.session(r)
	if !ok {
		http.Redirect(w, r, "/admin/login", 303)
		return
	}
	svc, ok := s.catalog.service(r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	meta, _ := s.vault.load(svc.Certificate, "")
	d := viewData{Title: "Dienst bearbeiten · " + svc.Name, CSRF: ss.CSRF, Service: displayService(svc, meta), FormatOptions: formatOptionsFor(meta), FormatGroups: groupFormats(formatOptionsFor(meta)), Certificate: certificateView{Name: svc.Certificate}}
	if r.URL.Query().Has("saved") {
		d.Notice = "Dienst gespeichert."
	}
	s.template(w, 200, "service.html", d)
}
func (s *server) updateService(w http.ResponseWriter, r *http.Request, _ authSession) {
	old, ok := s.catalog.service(r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	old.Name = strings.TrimSpace(r.PostForm.Get("name"))
	old.Kind = r.PostForm.Get("kind")
	old.Host = strings.TrimSpace(r.PostForm.Get("host"))
	old.Environment = strings.TrimSpace(r.PostForm.Get("environment"))
	old.Notes = strings.TrimSpace(r.PostForm.Get("notes"))
	old.Files = r.PostForm["files"]
	if _, e := s.catalog.upsertService(old); e != nil {
		http.Error(w, e.Error(), 400)
		return
	}
	http.Redirect(w, r, "/admin/services/"+old.ID+"?saved=1", 303)
}
func (s *server) deleteServiceAdmin(w http.ResponseWriter, r *http.Request, _ authSession) {
	old, ok := s.catalog.service(r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	if r.PostForm.Get("confirm") != old.Name {
		http.Error(w, "Dienstname zur Bestätigung eingeben", 400)
		return
	}
	if e := s.auth.revokeScope("", old.ID); e != nil {
		http.Error(w, "Token-Widerruf fehlgeschlagen", 500)
		return
	}
	if e := s.catalog.deleteService(old.ID); e != nil {
		http.Error(w, e.Error(), 500)
		return
	}
	http.Redirect(w, r, "/admin/certificates/"+old.Certificate+"?deleted=1", 303)
}
