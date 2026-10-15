package main

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// CertificateView is deliberately metadata-only: dependency pages must never
// read or expose private certificate files or API credentials.
type CertificateView struct {
	Ref       string
	Kind      string
	ID        string
	Label     string
	Status    string
	DetailURL string
	KindLabel string
}

type SystemRow struct {
	System       System
	Certificates []CertificateView
}

type GraphNode struct{ Label string }

func certificateViews(st State) []CertificateView {
	out := make([]CertificateView, 0, len(st.Targets)+len(st.ACMECerts)+len(st.ManualCertificates))
	for _, t := range st.Targets {
		status := "pending"
		if t.LastCheck != nil {
			status = t.LastCheck.Status
		}
		out = append(out, CertificateView{Ref: "target:" + t.ID, Kind: "target", ID: t.ID, Label: t.Name, KindLabel: "TLS-Monitoring", DetailURL: "/targets/" + t.ID, Status: status})
	}
	for _, c := range st.ACMECerts {
		out = append(out, CertificateView{Ref: "acme:" + c.Name, Kind: "acme", ID: c.Name, Label: c.Label, KindLabel: "ACME", DetailURL: "/downloads/" + c.Profile + "/" + c.Name, Status: "pending"})
	}
	for _, c := range st.ManualCertificates {
		out = append(out, CertificateView{Ref: "manual:" + c.Name, Kind: "manual", ID: c.Name, Label: c.Label, KindLabel: "Manueller Import", DetailURL: "/downloads/manual/" + c.Name, Status: "pending"})
	}
	sort.Slice(out, func(i, j int) bool {
		if strings.EqualFold(out[i].Label, out[j].Label) {
			return out[i].Ref < out[j].Ref
		}
		return strings.ToLower(out[i].Label) < strings.ToLower(out[j].Label)
	})
	return out
}
func findCertificate(st State, ref string) (CertificateView, bool) {
	for _, c := range certificateViews(st) {
		if c.Ref == ref {
			return c, true
		}
	}
	return CertificateView{}, false
}
func findSystem(st State, id string) (System, bool) {
	for _, s := range st.Systems {
		if s.ID == id {
			return s, true
		}
	}
	return System{}, false
}
func assignedSystems(st State, ref string) map[string]bool {
	found := make(map[string]bool)
	for _, a := range st.Assignments {
		if a.CertificateRef == ref {
			found[a.SystemID] = true
		}
	}
	return found
}
func assignedCertificates(st State, id string) map[string]bool {
	found := make(map[string]bool)
	for _, a := range st.Assignments {
		if a.SystemID == id {
			found[a.CertificateRef] = true
		}
	}
	return found
}
func systemsForRef(st State, ref string) []System {
	selected := assignedSystems(st, ref)
	out := make([]System, 0, len(selected))
	for _, s := range st.Systems {
		if selected[s.ID] {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}
func certificatesForSystem(st State, id string) []CertificateView {
	selected := assignedCertificates(st, id)
	out := []CertificateView{}
	for _, cert := range certificateViews(st) {
		if selected[cert.Ref] {
			out = append(out, cert)
		}
	}
	return out
}
func validSystemSelection(ids []string, st State) ([]string, error) {
	if len(ids) > 500 {
		return nil, errors.New("Zu viele Systemzuordnungen")
	}
	known := map[string]bool{}
	for _, s := range st.Systems {
		known[s.ID] = true
	}
	seen := map[string]bool{}
	out := []string{}
	for _, id := range ids {
		if !known[id] {
			return nil, fmt.Errorf("Unbekanntes System: %s", id)
		}
		if !seen[id] {
			out = append(out, id)
			seen[id] = true
		}
	}
	return out, nil
}
func validCertificateSelection(refs []string, st State) ([]string, error) {
	if len(refs) > 500 {
		return nil, errors.New("Zu viele Zertifikatszuordnungen")
	}
	valid := map[string]bool{}
	for _, c := range certificateViews(st) {
		valid[c.Ref] = true
	}
	out := []string{}
	seen := map[string]bool{}
	for _, ref := range refs {
		if !valid[ref] {
			return nil, fmt.Errorf("Unbekanntes Zertifikat: %s", ref)
		}
		if !seen[ref] {
			out = append(out, ref)
			seen[ref] = true
		}
	}
	return out, nil
}
func pruneCertificateAssignments(st *State, ref string) {
	filtered := make([]SystemAssignment, 0, len(st.Assignments))
	for _, a := range st.Assignments {
		if a.CertificateRef != ref {
			filtered = append(filtered, a)
		}
	}
	st.Assignments = filtered
}
func pruneSystemAssignments(st *State, id string) {
	filtered := make([]SystemAssignment, 0, len(st.Assignments))
	for _, a := range st.Assignments {
		if a.SystemID != id {
			filtered = append(filtered, a)
		}
	}
	st.Assignments = filtered
}
func setCertificateAssignmentsLocked(st *State, ref string, ids []string) error {
	if _, ok := findCertificate(*st, ref); !ok {
		return errors.New("Zertifikat existiert nicht")
	}
	selected, err := validSystemSelection(ids, *st)
	if err != nil {
		return err
	}
	pruneCertificateAssignments(st, ref)
	for _, id := range selected {
		st.Assignments = append(st.Assignments, SystemAssignment{SystemID: id, CertificateRef: ref})
	}
	return nil
}
func setSystemAssignmentsLocked(st *State, id string, refs []string) error {
	if _, ok := findSystem(*st, id); !ok {
		return errors.New("System existiert nicht")
	}
	selected, err := validCertificateSelection(refs, *st)
	if err != nil {
		return err
	}
	pruneSystemAssignments(st, id)
	for _, ref := range selected {
		st.Assignments = append(st.Assignments, SystemAssignment{SystemID: id, CertificateRef: ref})
	}
	return nil
}

func validateSystemIdentity(st State, candidate System) error {
	for _, existing := range st.Systems {
		if existing.ID != candidate.ID && existing.Kind == candidate.Kind && strings.EqualFold(strings.TrimSpace(existing.Name), candidate.Name) {
			return errors.New("Ein System mit diesem Namen und Typ existiert bereits")
		}
	}
	return nil
}

func parseSystemForm(r *http.Request) (System, error) {
	clean := func(k string) string { return strings.TrimSpace(r.FormValue(k)) }
	s := System{Name: clean("name"), Kind: clean("kind"), IPAddress: clean("ip_address"), Description: clean("description"), DocumentationURL: clean("documentation_url")}
	if len(s.Name) < 1 || len(s.Name) > 120 {
		return s, errors.New("Systemname benötigt 1 bis 120 Zeichen")
	}
	if s.Kind != "server" && s.Kind != "application" {
		return s, errors.New("Typ muss Server oder Applikation sein")
	}
	if len(s.Description) > 3000 {
		return s, errors.New("Beschreibung zu lang (maximal 3000 Zeichen)")
	}
	if s.IPAddress != "" && net.ParseIP(s.IPAddress) == nil {
		return s, errors.New("Ungültige IPv4- oder IPv6-Adresse")
	}
	if s.DocumentationURL != "" {
		if len(s.DocumentationURL) > 2048 {
			return s, errors.New("Dokumentationslink zu lang")
		}
		u, err := url.Parse(s.DocumentationURL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil {
			return s, errors.New("Dokumentationslink muss eine vollständige HTTP(S)-URL ohne Zugangsdaten sein")
		}
	}
	return s, nil
}
func (a *App) systemsPage(w http.ResponseWriter, r *http.Request, s session) {
	st := a.snapshot()
	d := pageData("Systeme & Applikationen", "systems", s, st)
	for _, sys := range st.Systems {
		d.SystemRows = append(d.SystemRows, SystemRow{System: sys, Certificates: certificatesForSystem(st, sys.ID)})
	}
	sort.Slice(d.SystemRows, func(i, j int) bool {
		return strings.ToLower(d.SystemRows[i].System.Name) < strings.ToLower(d.SystemRows[j].System.Name)
	})
	if r.URL.Query().Get("deleted") == "1" {
		d.Notice = "System und seine Zuordnungen entfernt. Zertifikate bleiben erhalten."
	}
	render(w, "systems", d)
}
func (a *App) systemForm(w http.ResponseWriter, s session, st State, sys System, edit bool, errText string) {
	d := pageData("System konfigurieren", "systems", s, st)
	d.CurrentSystem = sys
	d.SystemEditing = edit
	d.Error = errText
	d.CertViews = certificateViews(st)
	d.AssignedSystemIDs = assignedCertificates(st, sys.ID)
	render(w, "system_form", d)
}
func (a *App) newSystemPage(w http.ResponseWriter, _ *http.Request, s session) {
	a.systemForm(w, s, a.snapshot(), System{Kind: "server"}, false, "")
}
func (a *App) editSystemPage(w http.ResponseWriter, r *http.Request, s session) {
	st := a.snapshot()
	sys, ok := findSystem(st, r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	a.systemForm(w, s, st, sys, true, "")
}
func (a *App) createSystem(w http.ResponseWriter, r *http.Request, s session) {
	st := a.snapshot()
	sys, err := parseSystemForm(r)
	if err == nil {
		err = validateSystemIdentity(st, sys)
	}
	if err == nil {
		_, err = validCertificateSelection(r.Form["certificate_refs"], st)
	}
	if err != nil {
		w.WriteHeader(400)
		a.systemForm(w, s, st, sys, false, err.Error())
		return
	}
	sys.ID, err = newID()
	if err != nil {
		http.Error(w, "ID-Erzeugung fehlgeschlagen", 500)
		return
	}
	a.mu.Lock()
	if len(a.state.Systems) >= 1000 {
		a.mu.Unlock()
		http.Error(w, "Maximal 1000 Systeme", 409)
		return
	}
	// Revalidate under the lock: another request might have changed the inventory.
	if err = validateSystemIdentity(a.state, sys); err == nil {
		_, err = validCertificateSelection(r.Form["certificate_refs"], a.state)
	}
	if err == nil {
		a.state.Systems = append(a.state.Systems, sys)
		err = setSystemAssignmentsLocked(&a.state, sys.ID, r.Form["certificate_refs"])
	}
	if err == nil {
		err = a.saveLocked()
	}
	a.mu.Unlock()
	if err != nil {
		http.Error(w, "System konnte nicht gespeichert werden: "+err.Error(), 500)
		return
	}
	http.Redirect(w, r, "/systems/"+sys.ID, 303)
}
func (a *App) updateSystem(w http.ResponseWriter, r *http.Request, s session) {
	st := a.snapshot()
	old, ok := findSystem(st, r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	sys, err := parseSystemForm(r)
	sys.ID = old.ID
	if err == nil {
		err = validateSystemIdentity(st, sys)
	}
	if err == nil {
		_, err = validCertificateSelection(r.Form["certificate_refs"], st)
	}
	if err != nil {
		w.WriteHeader(400)
		a.systemForm(w, s, st, sys, true, err.Error())
		return
	}
	a.mu.Lock()
	index := -1
	for i, existing := range a.state.Systems {
		if existing.ID == old.ID {
			index = i
			break
		}
	}
	if index < 0 {
		a.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	if err = validateSystemIdentity(a.state, sys); err == nil {
		_, err = validCertificateSelection(r.Form["certificate_refs"], a.state)
	}
	if err == nil {
		a.state.Systems[index] = sys
		err = setSystemAssignmentsLocked(&a.state, sys.ID, r.Form["certificate_refs"])
	}
	if err == nil {
		err = a.saveLocked()
	}
	a.mu.Unlock()
	if err != nil {
		http.Error(w, "Speicherfehler: "+err.Error(), 500)
		return
	}
	http.Redirect(w, r, "/systems/"+sys.ID, 303)
}
func (a *App) deleteSystem(w http.ResponseWriter, r *http.Request, _ session) {
	id := r.PathValue("id")
	a.mu.Lock()
	found := false
	for i, sys := range a.state.Systems {
		if sys.ID == id {
			a.state.Systems = append(a.state.Systems[:i], a.state.Systems[i+1:]...)
			found = true
			break
		}
	}
	if !found {
		a.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	pruneSystemAssignments(&a.state, id)
	err := a.saveLocked()
	a.mu.Unlock()
	if err != nil {
		http.Error(w, "Speicherfehler", 500)
		return
	}
	http.Redirect(w, r, "/systems?deleted=1", 303)
}
func (a *App) systemDetail(w http.ResponseWriter, r *http.Request, s session) {
	st := a.snapshot()
	sys, ok := findSystem(st, r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	d := pageData(sys.Name, "systems", s, st)
	d.CurrentSystem = sys
	d.RelatedCertificates = certificatesForSystem(st, sys.ID)
	render(w, "system_detail", d)
}
func (a *App) certificateRelations(w http.ResponseWriter, r *http.Request, s session) {
	ref := r.PathValue("kind") + ":" + r.PathValue("id")
	st := a.snapshot()
	c, ok := findCertificate(st, ref)
	if !ok {
		http.NotFound(w, r)
		return
	}
	d := pageData("Zertifikatsabhängigkeiten", "dependencies", s, st)
	d.FocusCertificate = c
	d.RelatedSystems = systemsForRef(st, ref)
	d.AssignedSystemIDs = assignedSystems(st, ref)
	d.FocusedCertificate = &c
	if r.URL.Query().Get("saved") == "1" {
		d.Notice = "Systemzuordnungen aktualisiert."
	}
	render(w, "certificate_relations", d)
}
func (a *App) updateCertificateRelations(w http.ResponseWriter, r *http.Request, _ session) {
	ref := r.PathValue("kind") + ":" + r.PathValue("id")
	a.mu.Lock()
	err := setCertificateAssignmentsLocked(&a.state, ref, r.Form["system_ids"])
	if err == nil {
		err = a.saveLocked()
	}
	a.mu.Unlock()
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	http.Redirect(w, r, "/dependencies/certificates/"+r.PathValue("kind")+"/"+r.PathValue("id")+"?saved=1", 303)
}
func (a *App) dependenciesPage(w http.ResponseWriter, r *http.Request, s session) {
	st := a.snapshot()
	d := pageData("Abhängigkeiten", "dependencies", s, st)
	d.CertViews = certificateViews(st)
	for _, sys := range st.Systems {
		d.SystemRows = append(d.SystemRows, SystemRow{System: sys, Certificates: certificatesForSystem(st, sys.ID)})
	}
	sort.Slice(d.SystemRows, func(i, j int) bool {
		return strings.ToLower(d.SystemRows[i].System.Name) < strings.ToLower(d.SystemRows[j].System.Name)
	})
	if ref := r.URL.Query().Get("certificate"); ref != "" {
		cert, ok := findCertificate(st, ref)
		if ok {
			d.FocusedCertificate = &cert
			d.RelatedSystems = systemsForRef(st, ref)
		}
	} else if id := r.URL.Query().Get("system"); id != "" {
		sys, ok := findSystem(st, id)
		if ok {
			d.FocusedSystem = &sys
			d.RelatedCertificates = certificatesForSystem(st, id)
		}
	} else if len(d.SystemRows) > 0 {
		first := d.SystemRows[0].System
		d.FocusedSystem = &first
		d.RelatedCertificates = certificatesForSystem(st, first.ID)
	} else if len(d.CertViews) > 0 {
		first := d.CertViews[0]
		d.FocusedCertificate = &first
		d.RelatedSystems = systemsForRef(st, first.Ref)
	}
	render(w, "dependencies", d)
}
