package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// The ACME catalog contains public configuration only. Credentials remain in
// the independently deployed Certbot worker. No private key enters this process.
type acmeCatalog struct {
	Profiles     []ACMEProfile     `json:"acme_profiles"`
	Certificates []ACMECertificate `json:"certificates"`
}
type ACMEStatus struct {
	Name      string `json:"name"`
	Profile   string `json:"profile"`
	Status    string `json:"status"`
	Message   string `json:"message"`
	NotAfter  string `json:"not_after,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

func (a *App) exportACMECatalogLocked() error {
	if a.acmeCatalogPath == "" {
		return nil
	}
	c := acmeCatalog{Profiles: []ACMEProfile{}, Certificates: []ACMECertificate{}}
	if a.acmeEnabled {
		c.Profiles = append(c.Profiles, a.state.ACMEProfiles...)
		c.Certificates = append(c.Certificates, a.state.ACMECerts...)
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(a.acmeCatalogPath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".acme-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0644); err != nil {
		tmp.Close()
		return err
	}
	if _, err = tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), a.acmeCatalogPath)
}
func (a *App) loadACMEStatus() map[string]ACMEStatus {
	out := map[string]ACMEStatus{}
	if a.acmeStatusPath == "" || !a.acmeEnabled {
		return out
	}
	b, err := os.ReadFile(a.acmeStatusPath)
	if err != nil || len(b) > 1<<20 {
		return out
	}
	var statuses []ACMEStatus
	if json.Unmarshal(b, &statuses) == nil {
		for _, s := range statuses {
			out[s.Name] = s
		}
	}
	return out
}

var acmeIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
var envNamePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,79}$`)
var domainLabel = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

func validDomain(d string) bool {
	if strings.HasPrefix(d, "*.") {
		d = strings.TrimPrefix(d, "*.")
	}
	if len(d) < 3 || len(d) > 253 || strings.Contains(d, "..") {
		return false
	}
	parts := strings.Split(d, ".")
	if len(parts) < 2 {
		return false
	}
	for _, part := range parts {
		if !domainLabel.MatchString(part) {
			return false
		}
	}
	return true
}
func validWorkerPath(p, prefix string) bool {
	if p == "" {
		return true
	}
	return strings.HasPrefix(p, prefix) && p != prefix && filepath.IsAbs(p) && filepath.Clean(p) == p && !strings.Contains(p, "..")
}
func validateProfile(p ACMEProfile) error {
	if !acmeIDPattern.MatchString(p.ID) || p.ID == "manual" || len(p.Label) < 1 || len(p.Label) > 100 {
		return errors.New("Profil-ID oder Bezeichnung ungültig")
	}
	u, err := url.Parse(p.DirectoryURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || len(p.DirectoryURL) > 500 {
		return errors.New("ACME-Directory benötigt eine gültige HTTPS-URL")
	}
	if !strings.Contains(p.Email, "@") || strings.ContainsAny(p.Email, " \t\n\r") || len(p.Email) > 254 {
		return errors.New("Gültige Kontakt-E-Mail erforderlich")
	}
	if p.Challenge != "cloudflare" && p.Challenge != "manual-dns-hooks" && p.Challenge != "rfc2136" {
		return errors.New("Nur Cloudflare, RFC2136/TSIG oder manuelle DNS-Hooks unterstützt")
	}
	if !validWorkerPath(p.CredentialsFile, "/run/secrets/") || !validWorkerPath(p.AuthHook, "/hooks/") || !validWorkerPath(p.CleanupHook, "/hooks/") || !validWorkerPath(p.CABundleFile, "/run/acme-ca/") {
		return errors.New("Unsicherer Worker-Dateipfad")
	}
	if (p.Challenge == "cloudflare" || p.Challenge == "rfc2136") && p.CredentialsFile == "" {
		return errors.New("Credentials-Datei für das DNS-Verfahren fehlt")
	}
	if p.Challenge == "rfc2136" {
		ip := net.ParseIP(p.DNSServer)
		if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
			return errors.New("RFC2136 benötigt eine gültige DNS-Server-IP (IPv4 oder IPv6)")
		}
		if p.DNSPort < 0 || p.DNSPort > 65535 {
			return errors.New("DNS-Port muss zwischen 1 und 65535 liegen (0 = Standard 53)")
		}
		if p.DNSPropagationSeconds < 0 || p.DNSPropagationSeconds > 3600 {
			return errors.New("DNS-Wartezeit muss zwischen 0 und 3600 Sekunden liegen (0 = 60)")
		}
	}
	if p.Challenge == "manual-dns-hooks" && (p.AuthHook == "" || p.CleanupHook == "") {
		return errors.New("Beide DNS-Hooks sind erforderlich")
	}
	if (p.EABKidEnv == "") != (p.EABHMACEnv == "") {
		return errors.New("EAB benötigt KID- und HMAC-ENV-Namen")
	}
	if p.EABKidEnv != "" && (!envNamePattern.MatchString(p.EABKidEnv) || !envNamePattern.MatchString(p.EABHMACEnv)) {
		return errors.New("EAB-ENV-Namen ungültig")
	}
	return nil
}
func validateCertificate(c ACMECertificate, profiles []ACMEProfile) error {
	if !acmeIDPattern.MatchString(c.Name) || len(c.Label) > 100 || len(c.DNSNames) == 0 || len(c.DNSNames) > 50 {
		return errors.New("Ungültiger Zertifikatsname, Bezeichnung oder SAN-Anzahl")
	}
	found := false
	for _, p := range profiles {
		if p.ID == c.Profile {
			found = true
			break
		}
	}
	if !found {
		return errors.New("ACME-Profil unbekannt")
	}
	for _, d := range c.DNSNames {
		if !validDomain(d) {
			return fmt.Errorf("Ungültiger DNS-Name: %q", d)
		}
	}
	return nil
}
func (a *App) acmePage(w http.ResponseWriter, r *http.Request, s session) {
	st := a.snapshot()
	d := pageData("ACME / Certbot", "acme", s, st)
	d.ACMEEnabled = a.acmeEnabled
	d.ACMEStatus = a.loadACMEStatus()
	if r.URL.Query().Get("notice") == "saved" {
		d.Notice = "ACME-Konfiguration gespeichert. Der Worker übernimmt sie beim nächsten Lauf."
	}
	if r.URL.Query().Get("notice") == "deleted" {
		d.Notice = "ACME-Eintrag gelöscht."
	}
	render(w, "acme", d)
}
func (a *App) saveACMEProfile(w http.ResponseWriter, r *http.Request, _ session) {
	if !a.acmeEnabled {
		http.Error(w, "ACME nicht aktiviert", 403)
		return
	}
	g := func(k string) string { return strings.TrimSpace(r.FormValue(k)) }
	p := ACMEProfile{ID: g("id"), Label: g("label"), DirectoryURL: g("directory_url"), Email: g("email"), Challenge: g("challenge"), CredentialsFile: g("credentials_file"), AuthHook: g("auth_hook"), CleanupHook: g("cleanup_hook"), CABundleFile: g("ca_bundle_file"), EABKidEnv: g("eab_kid_env"), EABHMACEnv: g("eab_hmac_env"), DNSServer: g("dns_server")}
	if v := g("dns_port"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			http.Error(w, "DNS-Port ist keine Zahl", 400)
			return
		}
		p.DNSPort = n
	}
	if v := g("dns_propagation_seconds"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			http.Error(w, "DNS-Wartezeit ist keine Zahl", 400)
			return
		}
		p.DNSPropagationSeconds = n
	}
	if err := validateProfile(p); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	a.mu.Lock()
	for _, old := range a.state.ACMEProfiles {
		if old.ID == p.ID && old.DirectoryURL != p.DirectoryURL {
			for _, cert := range a.state.ACMECerts {
				if cert.Profile == p.ID {
					a.mu.Unlock()
					http.Error(w, "ACME-Directory kann für ein bereits verwendetes Profil nicht geändert werden. Stattdessen ein neues Profil anlegen.", http.StatusConflict)
					return
				}
			}
		}
	}
	found := false
	for i := range a.state.ACMEProfiles {
		if a.state.ACMEProfiles[i].ID == p.ID {
			a.state.ACMEProfiles[i] = p
			found = true
			break
		}
	}
	if !found {
		a.state.ACMEProfiles = append(a.state.ACMEProfiles, p)
	}
	err := a.saveLocked()
	a.mu.Unlock()
	if err != nil {
		http.Error(w, "Speicherfehler", 500)
		return
	}
	http.Redirect(w, r, "/acme?notice=saved", 303)
}
func (a *App) deleteACMEProfile(w http.ResponseWriter, r *http.Request, _ session) {
	id := r.PathValue("id")
	a.mu.Lock()
	for _, c := range a.state.ACMECerts {
		if c.Profile == id {
			a.mu.Unlock()
			http.Error(w, "Profil wird von einem Zertifikat verwendet", 409)
			return
		}
	}
	found := false
	for i, p := range a.state.ACMEProfiles {
		if p.ID == id {
			a.state.ACMEProfiles = append(a.state.ACMEProfiles[:i], a.state.ACMEProfiles[i+1:]...)
			found = true
			break
		}
	}
	if !found {
		a.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	err := a.saveLocked()
	a.mu.Unlock()
	if err != nil {
		http.Error(w, "Speicherfehler", 500)
		return
	}
	http.Redirect(w, r, "/acme?notice=deleted", 303)
}
func (a *App) saveACMECertificate(w http.ResponseWriter, r *http.Request, _ session) {
	if !a.acmeEnabled {
		http.Error(w, "ACME nicht aktiviert", 403)
		return
	}
	g := func(k string) string { return strings.TrimSpace(r.FormValue(k)) }
	parts := strings.FieldsFunc(g("domains"), func(c rune) bool { return c == ',' || c == '\n' || c == ';' || c == ' ' || c == '\r' })
	c := ACMECertificate{Name: g("name"), Label: g("label"), Profile: g("profile"), DNSNames: parts, Enabled: r.FormValue("enabled") == "on"}
	st := a.snapshot()
	if err := validateCertificate(c, st.ACMEProfiles); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	a.mu.Lock()
	found := false
	for i := range a.state.ACMECerts {
		if a.state.ACMECerts[i].Name == c.Name {
			if a.state.ACMECerts[i].Profile != c.Profile || a.state.ACMECerts[i].Enabled != c.Enabled || !slices.Equal(a.state.ACMECerts[i].DNSNames, c.DNSNames) {
				// Old tokens must never grant access to newly attached profiles.
				a.revokeScopeLocked(a.state.ACMECerts[i].Profile, c.Name)
			}
			a.state.ACMECerts[i] = c
			found = true
			break
		}
	}
	if !found {
		a.state.ACMECerts = append(a.state.ACMECerts, c)
	}
	err := a.saveLocked()
	a.mu.Unlock()
	if err != nil {
		http.Error(w, "Speicherfehler", 500)
		return
	}
	http.Redirect(w, r, "/acme?notice=saved", 303)
}
func (a *App) deleteACMECertificate(w http.ResponseWriter, r *http.Request, _ session) {
	name := r.PathValue("name")
	a.mu.Lock()
	found := false
	for i, c := range a.state.ACMECerts {
		if c.Name == name {
			a.revokeScopeLocked(c.Profile, name)
			a.state.ACMECerts = append(a.state.ACMECerts[:i], a.state.ACMECerts[i+1:]...)
			pruneCertificateAssignments(&a.state, "acme:"+name)
			found = true
			break
		}
	}
	if !found {
		a.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	// Revoke all scoped API credentials on deletion. A re-created lineage must
	// not inherit access from a previously deleted certificate.
	// The relevant grant was revoked above; unrelated grants remain usable.
	for i := range a.state.Targets {
		if a.state.Targets[i].ACMECert == name {
			a.state.Targets[i].ACMECert = ""
		}
	}
	err := a.saveLocked()
	a.mu.Unlock()
	if err != nil {
		http.Error(w, "Speicherfehler", 500)
		return
	}
	http.Redirect(w, r, "/acme?notice=deleted", 303)
}

// Private key export is opt-in: API access requires both a scoped token with
// private permission and CERTWATCH_PRIVATE_EXPORT_ENABLED=true.

func validateTargetACME(t Target, certs []ACMECertificate) error {
	if t.ACMECert == "" {
		return nil
	}
	for _, c := range certs {
		if c.Name == t.ACMECert {
			return nil
		}
	}
	return errors.New("ACME-Zertifikat nicht vorhanden")
}
