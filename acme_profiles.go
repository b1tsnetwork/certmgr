package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
)

// Profiles contain ONLY non-secret settings and paths to secrets accessible to
// the isolated Certbot worker. EAB HMAC values are resolved in its environment.
type acmeProfile struct {
	ID              string `json:"id"`
	Label           string `json:"label"`
	DirectoryURL    string `json:"directory_url"`
	Email           string `json:"email"`
	Challenge       string `json:"challenge"` // cloudflare or manual-dns-hooks
	CredentialsFile string `json:"credentials_file,omitempty"`
	AuthHook        string `json:"auth_hook,omitempty"`
	CleanupHook     string `json:"cleanup_hook,omitempty"`
	CABundleFile    string `json:"ca_bundle_file,omitempty"`
	EABKidEnv       string `json:"eab_kid_env,omitempty"`
	EABHMACEnv      string `json:"eab_hmac_env,omitempty"`
}

var envRef = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,79}$`)

func safePath(root, file string) bool {
	return file == "" || (strings.HasPrefix(file, root) && filepath.Clean(file) == file && !strings.Contains(file, ".."))
}
func validACMEProfile(p acmeProfile) error {
	if !safeName(p.ID) || len(p.ID) > 64 || strings.TrimSpace(p.Label) == "" || len(p.Label) > 100 {
		return errors.New("Ungültiger Profilname/Bezeichnung")
	}
	u, err := url.Parse(p.DirectoryURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || len(p.DirectoryURL) > 500 {
		return errors.New("ACME Directory muss eine vollständige HTTPS-URL sein")
	}
	if len(p.Email) > 254 || (p.Email != "" && (!strings.Contains(p.Email, "@") || strings.ContainsAny(p.Email, "\r\n\t "))) {
		return errors.New("Ungültige E-Mail-Adresse")
	}
	if p.Challenge != "cloudflare" && p.Challenge != "manual-dns-hooks" {
		return errors.New("DNS-01-Methode muss cloudflare oder manual-dns-hooks sein")
	}
	if !safePath("/run/secrets/", p.CredentialsFile) || !safePath("/hooks/", p.AuthHook) || !safePath("/hooks/", p.CleanupHook) || !safePath("/run/acme-ca/", p.CABundleFile) {
		return errors.New("Pfadangaben müssen in /run/secrets/, /hooks/ oder /run/acme-ca/ liegen")
	}
	if p.Challenge == "cloudflare" && p.CredentialsFile == "" {
		return errors.New("Cloudflare-Credentials-Pfad erforderlich")
	}
	if p.Challenge == "manual-dns-hooks" && (p.AuthHook == "" || p.CleanupHook == "") {
		return errors.New("Beide DNS-Hook-Pfade erforderlich")
	}
	if (p.EABKidEnv == "") != (p.EABHMACEnv == "") {
		return errors.New("Für EAB werden beide Env-Namen benötigt")
	}
	if p.EABKidEnv != "" && (!envRef.MatchString(p.EABKidEnv) || !envRef.MatchString(p.EABHMACEnv)) {
		return errors.New("EAB-Env-Namen ungültig")
	}
	return nil
}
func hasProfile(profiles []acmeProfile, id string) bool {
	for _, p := range profiles {
		if p.ID == id {
			return true
		}
	}
	return false
}
func (c *catalog) profile(id string) (acmeProfile, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, p := range c.data.Profiles {
		if p.ID == id {
			return p, true
		}
	}
	return acmeProfile{}, false
}
func (c *catalog) upsertProfile(v acmeProfile) error {
	if err := validACMEProfile(v); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	d := c.snapshotWithoutLock()
	found := false
	for i, p := range d.Profiles {
		if p.ID == v.ID {
			if p.DirectoryURL != v.DirectoryURL {
				for _, cert := range d.Certificates {
					if cert.Profile == v.ID {
						return errors.New("CA-Wechsel: neues Profil anlegen und Zertifikat neu zuordnen")
					}
				}
			}
			d.Profiles[i] = v
			found = true
			break
		}
	}
	if !found {
		d.Profiles = append(d.Profiles, v)
	}
	if err := c.saveLocked(d); err != nil {
		return err
	}
	c.data = d
	return nil
}
func (c *catalog) deleteProfile(id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	d := c.snapshotWithoutLock()
	for _, cert := range d.Certificates {
		if cert.Profile == id {
			return errors.New("Profil wird noch von einem Zertifikat verwendet")
		}
	}
	out := make([]acmeProfile, 0, len(d.Profiles))
	found := false
	for _, p := range d.Profiles {
		if p.ID == id {
			found = true
		} else {
			out = append(out, p)
		}
	}
	if !found {
		return errors.New("Profil nicht gefunden")
	}
	d.Profiles = out
	if err := c.saveLocked(d); err != nil {
		return err
	}
	c.data = d
	return nil
}
func (s *server) saveProfile(w http.ResponseWriter, r *http.Request, _ authSession) {
	id := r.FormValue("id")
	existing := r.PathValue("id")
	if existing != "" && existing != id {
		http.Error(w, "Profil-ID kann nicht geändert werden", 400)
		return
	}
	v := acmeProfile{ID: id, Label: strings.TrimSpace(r.FormValue("label")), DirectoryURL: strings.TrimSpace(r.FormValue("directory_url")), Email: strings.TrimSpace(r.FormValue("email")), Challenge: r.FormValue("challenge"), CredentialsFile: strings.TrimSpace(r.FormValue("credentials_file")), AuthHook: strings.TrimSpace(r.FormValue("auth_hook")), CleanupHook: strings.TrimSpace(r.FormValue("cleanup_hook")), CABundleFile: strings.TrimSpace(r.FormValue("ca_bundle_file")), EABKidEnv: strings.TrimSpace(r.FormValue("eab_kid_env")), EABHMACEnv: strings.TrimSpace(r.FormValue("eab_hmac_env"))}
	if err := s.catalog.upsertProfile(v); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	http.Redirect(w, r, "/admin/profiles/"+id+"?saved=1", 303)
}
func (s *server) profilePage(w http.ResponseWriter, r *http.Request) {
	ss, ok := s.auth.session(r)
	if !ok {
		http.Redirect(w, r, "/admin/login", 303)
		return
	}
	p, ok := s.catalog.profile(r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	d := viewData{Title: "ACME-Profil · " + p.Label, CSRF: ss.CSRF, Profile: p, Profiles: s.catalog.snapshot().Profiles}
	if r.URL.Query().Has("saved") {
		d.Notice = "ACME-Profil gespeichert. Der Certbot-Worker verwendet es beim nächsten Lauf."
	}
	s.template(w, 200, "profile.html", d)
}
func (s *server) deleteProfile(w http.ResponseWriter, r *http.Request, _ authSession) {
	id := r.PathValue("id")
	if r.FormValue("confirm") != id {
		http.Error(w, "Profil-ID zur Bestätigung eingeben", 400)
		return
	}
	if err := s.catalog.deleteProfile(id); err != nil {
		http.Error(w, fmt.Sprintf("Profil kann nicht gelöscht werden: %s", err), 400)
		return
	}
	http.Redirect(w, r, "/admin?profile_removed=1", 303)
}
