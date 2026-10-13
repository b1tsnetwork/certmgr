package main

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"time"
)

func selectedArtifact(svc serviceRecord, name string) bool {
	if name == "pfx-password.txt" {
		return needsPassword(svc.Files)
	}
	for _, s := range svc.Files {
		if s == name {
			return true
		}
	}
	return false
}
func (s *server) apiServiceManifest(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.catalog.service(r.PathValue("id"))
	if !ok || !s.configured(svc.Certificate) {
		http.NotFound(w, r)
		return
	}
	// The service inventory is private, even if the service selects only public certs.
	if !s.auth.bearerServiceAllowed(r, svc.ID, svc.Certificate, false) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="certificate-service"`)
		http.Error(w, "Service-Token erforderlich", 401)
		return
	}
	meta, e := s.vault.load(svc.Certificate, "")
	if e != nil {
		http.NotFound(w, r)
		return
	}
	authPrivate := s.auth.bearerServiceAllowed(r, svc.ID, svc.Certificate, true)
	artifacts := make([]artifact, 0, len(svc.Files)+1)
	for _, a := range meta.Artifacts {
		if selectedArtifact(svc, a.Name) && (!a.Private || authPrivate) {
			artifacts = append(artifacts, a)
		}
	}
	meta.Artifacts = artifacts
	jsonReply(w, struct {
		certMeta
		ServiceID   string   `json:"service_id"`
		ServiceName string   `json:"service_name"`
		ServiceKind string   `json:"service_kind"`
		Host        string   `json:"host"`
		Missing     []string `json:"missing_files"`
	}{meta, svc.ID, svc.Name, svc.Kind, svc.Host, missingFiles(svc, artifacts, authPrivate)})
}
func missingFiles(svc serviceRecord, actual []artifact, maySeePrivate bool) []string {
	existing := map[string]bool{}
	for _, a := range actual {
		existing[a.Name] = true
	}
	var missing []string
	for _, f := range svc.Files {
		if !maySeePrivate && filePrivate(f) {
			continue
		}
		if !existing[f] {
			missing = append(missing, f)
		}
	}
	return missing
}
func (s *server) apiServiceArtifact(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.catalog.service(r.PathValue("id"))
	if !ok || !s.configured(svc.Certificate) {
		http.NotFound(w, r)
		return
	}
	fn := r.PathValue("filename")
	if !selectedArtifact(svc, fn) {
		http.NotFound(w, r)
		return
	}
	meta, e := s.vault.load(svc.Certificate, r.PathValue("version"))
	if e != nil {
		http.NotFound(w, r)
		return
	}
	var chosen *artifact
	for i := range meta.Artifacts {
		if meta.Artifacts[i].Name == fn {
			chosen = &meta.Artifacts[i]
			break
		}
	}
	if chosen == nil {
		http.NotFound(w, r)
		return
	}
	if !s.auth.bearerServiceAllowed(r, svc.ID, svc.Certificate, chosen.Private) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="certificate-service"`)
		http.Error(w, "Service-Token mit passender Berechtigung erforderlich", 401)
		return
	}
	body, e := s.vault.read(svc.Certificate, meta.Version, fn)
	if e != nil {
		http.Error(w, "Artefakt nicht verfügbar", 500)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", fn))
	w.Header().Set("X-Certificate-Version", meta.Version)
	http.ServeContent(w, r, fn, time.Time{}, bytes.NewReader(body))
}
func filenameSet(files []string) map[string]bool {
	set := map[string]bool{}
	for _, f := range files {
		set[f] = true
	}
	return set
}
func displayService(svc serviceRecord, meta certMeta) serviceView {
	got := map[string]bool{}
	for _, a := range meta.Artifacts {
		got[a.Name] = true
	}
	item := serviceView{serviceRecord: svc, Selected: filenameSet(svc.Files)}
	for _, fn := range svc.Files {
		if got[fn] {
			item.Available = append(item.Available, fn)
		} else {
			item.Missing = append(item.Missing, fn)
		}
		if filePrivate(fn) {
			item.Private = true
		}
	}
	return item
}
func sanitizeSANInput(s string) []string {
	parts := strings.FieldsFunc(strings.ToLower(s), func(r rune) bool { return r == ',' || r == ';' || r == '\n' || r == '\r' })
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func formatOptionsFor(meta certMeta) []formatOption {
	opts := append([]formatOption(nil), formatOptions...)
	for _, a := range meta.Artifacts {
		if extraIntermediate.MatchString(a.Name) {
			opts = append(opts, formatOption{File: a.Name, Title: "Intermediate (" + a.Name + ")", Group: "Zertifikate"})
		}
	}
	return opts
}

type formatGroup struct {
	Name    string
	Options []formatOption
}

func groupFormats(options []formatOption) []formatGroup {
	groups := []formatGroup{}
	index := map[string]int{}
	for _, op := range options {
		i, found := index[op.Group]
		if !found {
			i = len(groups)
			index[op.Group] = i
			groups = append(groups, formatGroup{Name: op.Group})
		}
		groups[i].Options = append(groups[i].Options, op)
	}
	return groups
}
