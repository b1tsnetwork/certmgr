package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"time"
)

// Browser downloads are intentionally independent of API bearer tokens.
// A valid interactive session (including the viewer role) grants access to
// all published artifacts, including private keys and PFX passwords.
// Run the WebUI behind HTTPS with appropriately restricted accounts.
type DownloadEntry struct {
	Profile string
	Name    string
	Label   string
	Source  string
	Ready   bool
	Error   string
}

type DownloadDetail struct {
	Entry      DownloadEntry
	Version    string
	NotAfter   time.Time
	DNSNames   []string
	Public     []artifact
	Private    []artifact
	ConvertErr string
}

func (a *App) availableDownloadEntries() []DownloadEntry {
	st := a.snapshot()
	entries := []DownloadEntry{}
	for _, c := range st.ManualCertificates {
		if a.manualVault == nil {
			continue
		}
		entries = append(entries, DownloadEntry{Profile: "manual", Name: c.Name, Label: c.Label, Source: "Manuell"})
	}
	if a.handoffPath != "" {
		for _, c := range st.ACMECerts {
			if c.Enabled {
				entries = append(entries, DownloadEntry{Profile: c.Profile, Name: c.Name, Label: c.Label, Source: "ACME"})
			}
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Label == entries[j].Label {
			return entries[i].Profile+"/"+entries[i].Name < entries[j].Profile+"/"+entries[j].Name
		}
		return entries[i].Label < entries[j].Label
	})
	return entries
}

// Conversion cache is kept in a separate namespace under the encrypted
// vault and is not registered in the manual inventory.
func acmeCacheName(profile, name string) string {
	h := sha256.Sum256([]byte(profile + "/" + name))
	return "acme-cache-" + hex.EncodeToString(h[:16])
}

func (a *App) acmeFormatVault() *vault {
	if a.manualVault == nil {
		return nil
	}
	// The leading underscore cannot be a valid manually imported ID.
	return &vault{dir: a.manualVault.dir + "/_acme-converted", gcm: a.manualVault.gcm}
}

// Generating the full ACME format set is lazy and encrypted under the same
// vault key as manual uploads, once per immutable Certbot release. A single
// mutex avoids simultaneous conversions with differing PFX passwords.
func (a *App) convertedACME(profile, name, version string) (certMeta, error) {
	if a.manualVault == nil {
		return certMeta{}, errors.New("Für PFX/DER/PKCS#7/PKCS#8 bitte CERTWATCH_VAULT_KEY konfigurieren")
	}
	if !publishedReleasePattern.MatchString(version) {
		return certMeta{}, os.ErrNotExist
	}
	cacheName := acmeCacheName(profile, name)
	v := a.acmeFormatVault()
	a.conversionMu.Lock()
	defer a.conversionMu.Unlock()
	if meta, err := v.load(cacheName, version); err == nil {
		// A changed vault key must never produce unusable links to sealed data.
		if _, checkErr := v.read(cacheName, version, "pfx-password.txt"); checkErr == nil {
			return meta, nil
		}
		return certMeta{}, errors.New("Verschlüsselter ACME-Cache nicht entschlüsselbar; Vault-Schlüssel prüfen")
	}
	cert, err := a.distributionArtifact(profile, name, "cert.pem", version)
	if err != nil {
		return certMeta{}, err
	}
	chain, err := a.distributionArtifact(profile, name, "chain.pem", version)
	if err != nil {
		return certMeta{}, err
	}
	key, err := a.distributionArtifact(profile, name, "privkey.pem", version)
	if err != nil {
		return certMeta{}, err
	}
	in, err := manualParseInput(cert, chain, key, nil)
	if err != nil {
		return certMeta{}, fmt.Errorf("ACME-Zertifikat kann nicht konvertiert werden: %w", err)
	}
	files, meta, err := manualConvert(os.TempDir(), cacheName, version, in)
	if err != nil {
		return certMeta{}, fmt.Errorf("Konvertierung fehlgeschlagen: %w", err)
	}
	if err = v.publish(cacheName, version, files, meta); err != nil {
		return certMeta{}, err
	}
	return v.load(cacheName, version)
}

func (a *App) browserArtifacts(profile, name, version string) ([]artifact, certMeta, string, error) {
	if profile == "manual" {
		if a.manualVault == nil {
			return nil, certMeta{}, "", os.ErrNotExist
		}
		meta, err := a.manualVault.load(name, version)
		return meta.Artifacts, meta, "", err
	}
	// ACME always has these four original PEM files if published.
	basic := []artifact{}
	for _, filename := range []string{"cert.pem", "chain.pem", "fullchain.pem", "privkey.pem"} {
		b, err := a.distributionArtifact(profile, name, filename, version)
		if err != nil {
			return nil, certMeta{}, "", err
		}
		basic = append(basic, artifact{Name: filename, Size: len(b), SHA256: manualHashHex(b), Private: filename == "privkey.pem"})
	}
	// Public certificate metadata is available even when conversion is disabled.
	var originalMeta certMeta
	if block, _ := pem.Decode(func() []byte {
		b, _ := a.distributionArtifact(profile, name, "cert.pem", version)
		return b
	}()); block != nil {
		if leaf, parseErr := x509.ParseCertificate(block.Bytes); parseErr == nil {
			originalMeta.NotAfter = leaf.NotAfter
			originalMeta.DNSNames = leaf.DNSNames
		}
	}
	meta, err := a.convertedACME(profile, name, version)
	if err != nil {
		// PEM remains available if no vault has been configured or conversion fails.
		return basic, originalMeta, err.Error(), nil
	}
	// The displayed checksums for the original four files must describe the
	// actual Certbot bytes, not normalized PEM generated by the converter.
	for i := range meta.Artifacts {
		for _, original := range basic {
			if meta.Artifacts[i].Name == original.Name {
				meta.Artifacts[i] = original
				break
			}
		}
	}
	return meta.Artifacts, meta, "", nil
}

func (a *App) downloadPage(w http.ResponseWriter, _ *http.Request, s session) {
	d := pageData("Zertifikate herunterladen", "downloads", s, a.snapshot())
	d.DownloadEntries = a.availableDownloadEntries()
	render(w, "downloads", d)
}

func (a *App) downloadDetail(w http.ResponseWriter, r *http.Request, s session) {
	profile, name := r.PathValue("profile"), r.PathValue("name")
	if !a.allowedBrowserScope(profile, name) {
		http.NotFound(w, r)
		return
	}
	entry := DownloadEntry{Profile: profile, Name: name, Label: name, Source: "ACME"}
	for _, item := range a.availableDownloadEntries() {
		if item.Profile == profile && item.Name == name {
			entry = item
			break
		}
	}
	if profile == "manual" {
		entry.Source = "Manuell"
	}
	d := pageData("Zertifikat herunterladen", "downloads", s, a.snapshot())
	version, err := a.currentRelease(profile, name)
	if err != nil {
		d.Error = "Für dieses Zertifikat wurde noch keine Version veröffentlicht."
		d.DownloadSelection = &DownloadDetail{Entry: entry}
		render(w, "downloads", d)
		return
	}
	files, meta, conversionErr, err := a.browserArtifacts(profile, name, version)
	if err != nil {
		d.Error = "Zertifikatsdateien sind nicht verfügbar oder beschädigt."
		d.DownloadSelection = &DownloadDetail{Entry: entry}
		render(w, "downloads", d)
		return
	}
	selection := DownloadDetail{Entry: entry, Version: version, DNSNames: meta.DNSNames, NotAfter: meta.NotAfter, ConvertErr: conversionErr}
	for _, f := range files {
		if f.Private {
			selection.Private = append(selection.Private, f)
		} else {
			selection.Public = append(selection.Public, f)
		}
	}
	d.DownloadSelection = &selection
	render(w, "downloads", d)
}

func (a *App) allowedBrowserScope(profile, name string) bool {
	if !acmeIDPattern.MatchString(profile) || !acmeIDPattern.MatchString(name) {
		return false
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.certificateRegisteredLocked(profile, name) &&
		((profile == "manual" && a.manualVault != nil) || (profile != "manual" && a.handoffPath != ""))
}

// file access only through sessions; query tokens / Authorization headers are
// never used. Always fetch the immutable version displayed in the UI.
func (a *App) browserDownload(w http.ResponseWriter, r *http.Request, _ session) {
	profile, name, version, filename := r.PathValue("profile"), r.PathValue("name"), r.PathValue("version"), r.PathValue("file")
	if !a.allowedBrowserScope(profile, name) || !manualSafeName(filename) {
		http.NotFound(w, r)
		return
	}
	if profile == "manual" {
		if !manualSafeName(version) {
			http.NotFound(w, r)
			return
		}
	} else if !publishedReleasePattern.MatchString(version) {
		http.NotFound(w, r)
		return
	}
	files, _, _, err := a.browserArtifacts(profile, name, version)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	var expected *artifact
	for i := range files {
		if files[i].Name == filename {
			expected = &files[i]
			break
		}
	}
	if expected == nil {
		http.NotFound(w, r)
		return
	}
	var b []byte
	if profile == "manual" || !distributableFiles[filename] {
		storedName := name
		if profile != "manual" {
			storedName = acmeCacheName(profile, name)
		}
		if profile == "manual" {
			b, err = a.manualVault.read(storedName, version, filename)
		} else {
			b, err = a.acmeFormatVault().read(storedName, version, filename)
		}
	} else {
		b, err = a.distributionArtifact(profile, name, filename, version)
	}
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if len(b) > 8<<20 || manualHashHex(b) != expected.SHA256 {
		http.Error(w, "Prüfsumme stimmt nicht überein oder Datei zu groß", 500)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store, private")
	w.Header().Set("X-CertWatch-Version", version)
	_, _ = w.Write(b)
}
