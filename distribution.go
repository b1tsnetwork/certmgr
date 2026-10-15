package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Distribution API endpoints accept only bearer tokens with explicit scopes.
// Browser downloads use a separate session-only handler and never accept tokens in URLs.
var publishedReleasePattern = regexp.MustCompile(`^[0-9]{14}-[A-Za-z0-9_-]{8,24}$`)
var distributableFiles = map[string]bool{
	"cert.pem": true, "chain.pem": true, "fullchain.pem": true, "privkey.pem": true,
}

// grantsScope preserves previously persisted single-certificate credentials.
func (t DistributionToken) grantsScope(profile, name string) bool {
	if len(t.Scopes) == 0 {
		return t.Profile == profile && t.Certificate == name
	}
	for _, sc := range t.Scopes {
		if sc.Profile == profile && sc.Certificate == name {
			return true
		}
	}
	return false
}

// Remove only the changed/deleted certificate from multi-certificate tokens.
// A credential with no surviving grants is removed completely.
// Must be called with a.mu locked.
func (a *App) revokeScopeLocked(profile, name string) {
	kept := a.state.DistributionTokens[:0]
	for _, t := range a.state.DistributionTokens {
		if len(t.Scopes) == 0 {
			if t.Profile != profile || t.Certificate != name {
				kept = append(kept, t)
			}
			continue
		}
		scopes := make([]CertificateScope, 0, len(t.Scopes))
		for _, sc := range t.Scopes {
			if sc.Profile != profile || sc.Certificate != name {
				scopes = append(scopes, sc)
			}
		}
		if len(scopes) != 0 {
			t.Scopes = scopes
			kept = append(kept, t)
		}
	}
	a.state.DistributionTokens = kept
}

func (a *App) certificateRegisteredLocked(profile, name string) bool {
	if profile == "manual" {
		return a.manualRegisteredLocked(name) && a.manualVault != nil
	}
	for _, c := range a.state.ACMECerts {
		if c.Name == name && c.Profile == profile && c.Enabled {
			return true
		}
	}
	return false
}

func (a *App) distributionPage(w http.ResponseWriter, r *http.Request, s session) {
	a.renderDistribution(w, s, "", "")
}

func (a *App) renderDistribution(w http.ResponseWriter, s session, token, notice string) {
	st := a.snapshot()
	d := pageData("Zentraler Zertifikatsabruf", "distribution", s, st)
	d.DistributionTokens = st.DistributionTokens
	for _, c := range st.ManualCertificates {
		d.DistributionCerts = append(d.DistributionCerts, ACMECertificate{Name: c.Name, Label: c.Label + " (manuell)", Profile: "manual", Enabled: true})
	}
	for _, c := range st.ACMECerts {
		if c.Enabled {
			d.DistributionCerts = append(d.DistributionCerts, c)
		}
	}
	d.DistributionEnabled = a.handoffPath != "" || a.manualVault != nil
	d.PrivateExportEnabled = a.privateExportEnabled
	d.NewlyCreatedToken = token
	d.Notice = notice
	render(w, "distribution", d)
}

func (a *App) createDistributionToken(w http.ResponseWriter, r *http.Request, s session) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Formular unlesbar", 400)
		return
	}
	label := strings.TrimSpace(r.FormValue("label"))
	selections := r.Form["scopes"]
	if len(selections) == 0 && r.FormValue("scope") != "" {
		selections = []string{r.FormValue("scope")} // older UI/client compatibility
	}
	days, err := strconv.Atoi(r.FormValue("days"))
	private := r.FormValue("private") == "on"
	if label == "" || len(label) > 100 || err != nil || days < 1 || days > 365 || len(selections) < 1 || len(selections) > 50 {
		http.Error(w, "Ungültige Token-Konfiguration (1 bis 50 Zertifikate)", 400)
		return
	}
	if private && !a.privateExportEnabled {
		http.Error(w, "Private-Key-Export über die API ist nicht aktiviert", 403)
		return
	}
	scopes := make([]CertificateScope, 0, len(selections))
	unique := make(map[string]bool)
	for _, selection := range selections {
		pair := strings.Split(selection, "/")
		if len(pair) != 2 || !acmeIDPattern.MatchString(pair[0]) || !acmeIDPattern.MatchString(pair[1]) || unique[selection] {
			http.Error(w, "Ungültige oder doppelte Zertifikatsauswahl", 400)
			return
		}
		unique[selection] = true
		scopes = append(scopes, CertificateScope{Profile: pair[0], Certificate: pair[1]})
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		http.Error(w, "Zufallsquelle nicht verfügbar", 500)
		return
	}
	secret := "cw_" + base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(secret))
	id, err := newID()
	if err != nil {
		http.Error(w, "Zufallsquelle nicht verfügbar", 500)
		return
	}
	now := time.Now().UTC()
	t := DistributionToken{ID: id, Label: label, Scopes: scopes, Hash: hex.EncodeToString(sum[:]), Private: private,
		CreatedAt: now, ExpiresAt: now.Add(time.Duration(days) * 24 * time.Hour)}
	a.mu.Lock()
	for _, sc := range scopes {
		if !a.certificateRegisteredLocked(sc.Profile, sc.Certificate) ||
			(sc.Profile != "manual" && a.handoffPath == "") || (sc.Profile == "manual" && a.manualVault == nil) {
			a.mu.Unlock()
			http.Error(w, "Mindestens ein Zertifikat ist unbekannt, deaktiviert oder nicht abrufbar", 400)
			return
		}
	}
	if len(a.state.DistributionTokens) >= 500 {
		a.mu.Unlock()
		http.Error(w, "Token-Limit erreicht", 409)
		return
	}
	a.state.DistributionTokens = append(a.state.DistributionTokens, t)
	err = a.saveLocked()
	a.mu.Unlock()
	if err != nil {
		http.Error(w, "Token konnte nicht gespeichert werden", 500)
		return
	}
	a.renderDistribution(w, s, secret, "API-Token erzeugt. Er wird nur dieses eine Mal angezeigt – sicher speichern!")
}

func (a *App) revokeDistributionToken(w http.ResponseWriter, r *http.Request, _ session) {
	id := r.PathValue("id")
	a.mu.Lock()
	kept := make([]DistributionToken, 0, len(a.state.DistributionTokens))
	found := false
	for _, t := range a.state.DistributionTokens {
		if t.ID == id {
			found = true
		} else {
			kept = append(kept, t)
		}
	}
	if !found {
		a.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	a.state.DistributionTokens = kept
	err := a.saveLocked()
	a.mu.Unlock()
	if err != nil {
		http.Error(w, "Speicherfehler", 500)
		return
	}
	http.Redirect(w, r, "/distribution", 303)
}

func (a *App) authorizeDistribution(r *http.Request, profile, name string, private bool) bool {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") || len(h) > 160 {
		return false
	}
	secret := strings.TrimPrefix(h, "Bearer ")
	if !strings.HasPrefix(secret, "cw_") {
		return false
	}
	sum := sha256.Sum256([]byte(secret))
	now := time.Now()
	a.mu.RLock()
	defer a.mu.RUnlock()
	if !a.certificateRegisteredLocked(profile, name) || (profile != "manual" && a.handoffPath == "") {
		return false
	}
	if private && !a.privateExportEnabled {
		return false
	}
	for _, t := range a.state.DistributionTokens {
		if !t.grantsScope(profile, name) || (private && !t.Private) || !now.Before(t.ExpiresAt) {
			continue
		}
		expected, err := hex.DecodeString(t.Hash)
		if err == nil && subtle.ConstantTimeCompare(expected, sum[:]) == 1 {
			return true
		}
	}
	return false
}

func denyDistribution(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="certwatch-distribution"`)
	http.Error(w, "Nicht autorisiert", http.StatusUnauthorized)
}

// read only the worker's published immutable release. Forbid symlink escapes,
// unrecognized filenames, huge files and invalid PEM.
// A release ID refers to an immutable generation written by the Certbot hook.
func (a *App) currentRelease(profile, name string) (string, error) {
	if !acmeIDPattern.MatchString(profile) || !acmeIDPattern.MatchString(name) {
		return "", os.ErrNotExist
	}
	if profile == "manual" {
		if !a.manualScopeAvailable(name) {
			return "", os.ErrNotExist
		}
		meta, err := a.manualVault.load(name, "")
		if err != nil {
			return "", err
		}
		return meta.Version, nil
	}
	if a.handoffPath == "" {
		return "", os.ErrNotExist
	}
	link, err := os.Readlink(filepath.Join(a.handoffPath, profile, name, "current"))
	if err != nil {
		return "", err
	}
	if filepath.Dir(link) != "releases" || !publishedReleasePattern.MatchString(filepath.Base(link)) {
		return "", errors.New("ungültiger Release-Link")
	}
	return filepath.Base(link), nil
}
func (a *App) distributionArtifact(profile, name, filename, version string) ([]byte, error) {
	if !acmeIDPattern.MatchString(profile) || !acmeIDPattern.MatchString(name) {
		return nil, os.ErrNotExist
	}
	if profile == "manual" {
		b, _, err := a.manualRead(name, version, filename)
		return b, err
	}
	if !distributableFiles[filename] || a.handoffPath == "" {
		return nil, os.ErrNotExist
	}
	if version == "" {
		var err error
		version, err = a.currentRelease(profile, name)
		if err != nil {
			return nil, err
		}
	}
	if !publishedReleasePattern.MatchString(version) {
		return nil, os.ErrNotExist
	}
	base := filepath.Join(a.handoffPath, profile, name)
	resolvedBase, err := filepath.EvalSymlinks(base)
	if err != nil {
		return nil, err
	}
	path, err := filepath.EvalSymlinks(filepath.Join(base, "releases", version, filename))
	if err != nil {
		return nil, err
	}
	rel, err := filepath.Rel(resolvedBase, path)
	if err != nil || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || rel == ".." || filepath.IsAbs(rel) || !strings.HasPrefix(rel, "releases"+string(os.PathSeparator)) {
		return nil, errors.New("Zertifikatspfad verlässt das Ausgabeverzeichnis")
	}
	stat, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !stat.Mode().IsRegular() || stat.Size() > 1<<20 || stat.Size() == 0 {
		return nil, errors.New("Ungültige Dateigröße oder Dateityp")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if err != nil || len(data) > 1<<20 {
		return nil, errors.New("Zertifikat zu groß")
	}
	if !validArtifactPEM(filename, data) {
		return nil, errors.New("Ungültiges PEM-Artefakt")
	}
	return data, nil
}
func validArtifactPEM(filename string, data []byte) bool {
	if filename == "privkey.pem" {
		block, rest := pem.Decode(data)
		if block == nil || len(strings.TrimSpace(string(rest))) != 0 {
			return false
		}
		switch block.Type {
		case "PRIVATE KEY":
			_, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			return err == nil
		case "RSA PRIVATE KEY":
			_, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			return err == nil
		case "EC PRIVATE KEY":
			_, err := x509.ParseECPrivateKey(block.Bytes)
			return err == nil
		}
		return false
	}
	count := 0
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" {
			return false
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return false
		}
		count++
		data = []byte(strings.TrimSpace(string(rest)))
	}
	return count > 0
}

func (a *App) apiDistributionManifest(w http.ResponseWriter, r *http.Request) {
	profile, name := r.PathValue("profile"), r.PathValue("name")
	if !a.authorizeDistribution(r, profile, name, false) {
		denyDistribution(w)
		return
	}
	version, err := a.currentRelease(profile, name)
	if err != nil {
		http.Error(w, "Kein veröffentlichtes Zertifikat vorhanden", 404)
		return
	}
	full, err := a.distributionArtifact(profile, name, "fullchain.pem", version)
	if err != nil {
		http.Error(w, "Kein veröffentlichtes Zertifikat vorhanden", 404)
		return
	}
	block, _ := pem.Decode(full)
	if block == nil {
		http.Error(w, "Ungültige Zertifikatskette", 500)
		return
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		http.Error(w, "Ungültige Zertifikatskette", 500)
		return
	}
	hash := sha256.Sum256(full)
	files := []string{"cert.pem", "chain.pem", "fullchain.pem"}
	details := []artifact{}
	if profile == "manual" {
		meta, err := a.manualVault.load(name, version)
		if err != nil {
			http.Error(w, "Manuelle Version nicht verfügbar", 404)
			return
		}
		files = nil
		for _, file := range meta.Artifacts {
			if manualIsPrivate(file) && !a.authorizeDistribution(r, profile, name, true) {
				continue
			}
			files = append(files, file.Name)
			details = append(details, file)
		}
	} else if a.authorizeDistribution(r, profile, name, true) {
		files = append(files, "privkey.pem")
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"profile": profile, "certificate": name, "version": version, "version_sha256": hex.EncodeToString(hash[:]),
		"not_after": leaf.NotAfter.UTC().Format(time.RFC3339), "dns_names": leaf.DNSNames,
		"artifacts": files, "artifact_details": details, "source": map[bool]string{true: "manual", false: "acme"}[profile == "manual"],
	})
}
func (a *App) apiDistributionArtifact(w http.ResponseWriter, r *http.Request) {
	profile, name, file := r.PathValue("profile"), r.PathValue("name"), r.PathValue("file")
	if !acmeIDPattern.MatchString(profile) || !acmeIDPattern.MatchString(name) || !manualSafeName(file) || (profile != "manual" && !distributableFiles[file]) {
		http.NotFound(w, r)
		return
	}
	// Deny unauthenticated requests before looking up manual metadata.
	if !a.authorizeDistribution(r, profile, name, false) {
		denyDistribution(w)
		return
	}
	isPrivate := file == "privkey.pem"
	if profile == "manual" {
		_, metaFile, err := a.manualArtifactMeta(name, r.PathValue("version"), file)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		isPrivate = manualIsPrivate(metaFile)
	}
	if !a.authorizeDistribution(r, profile, name, isPrivate) {
		denyDistribution(w)
		return
	}
	data, err := a.distributionArtifact(profile, name, file, r.PathValue("version"))
	if err != nil {
		http.Error(w, fmt.Sprintf("Artefakt nicht verfügbar: %s", file), 404)
		return
	}
	hash := sha256.Sum256(data)
	etag := `"` + hex.EncodeToString(hash[:]) + `"`
	w.Header().Set("ETag", etag)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	ctype := "application/x-pem-file"
	if profile == "manual" {
		ctype = "application/octet-stream"
		if strings.HasSuffix(file, ".pem") || strings.HasSuffix(file, ".crt") {
			ctype = "application/x-pem-file"
		}
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", `attachment; filename="`+file+`"`)
	w.Header().Set("X-CertWatch-Artifact", file)
	_, _ = w.Write(data)
}
