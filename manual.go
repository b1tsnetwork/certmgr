package main

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// Manual import is deliberately separate from ACME. The ciphertext is stored
// in data/certificates; the master key is never stored in state.json.
type ManualDisplay struct {
	ManualCertificate
	Meta        certMeta
	Available   bool
	Status      string
	StatusLabel string
	Error       string
	Public      []artifact
	Private     []artifact
}

func (a *App) manualList() []ManualDisplay {
	st := a.snapshot()
	result := make([]ManualDisplay, 0, len(st.ManualCertificates))
	for _, c := range st.ManualCertificates {
		v := ManualDisplay{ManualCertificate: c}
		if a.manualVault == nil {
			v.Error = "Vault-Key fehlt"
		} else {
			meta, err := a.manualVault.load(c.Name, "")
			if err == nil {
				_, _, err = a.manualRead(c.Name, meta.Version, "cert.pem")
			}
			if err != nil {
				v.Error = "Importdaten nicht lesbar"
			} else {
				v.Meta = meta
				v.Available = true
				daysLeft := time.Until(meta.NotAfter).Hours() / 24
				switch {
				case daysLeft <= 14:
					v.Status = "red"
					v.StatusLabel = "Kritisch / abgelaufen"
				case daysLeft <= 30:
					v.Status = "yellow"
					v.StatusLabel = "Läuft bald ab"
				default:
					v.Status = "green"
					v.StatusLabel = "Gültig"
				}
				for _, f := range meta.Artifacts {
					if manualIsPrivate(f) {
						v.Private = append(v.Private, f)
					} else {
						v.Public = append(v.Public, f)
					}
				}
			}
		}
		result = append(result, v)
	}
	return result
}

func (a *App) manualPage(w http.ResponseWriter, r *http.Request, s session) {
	d := pageData("Manueller Zertifikatsimport", "manual", s, a.snapshot())
	d.ManualCertificates = a.manualList()
	d.ManualVaultEnabled = a.manualVault != nil
	if r.URL.Query().Get("saved") == "1" {
		d.Notice = "Zertifikat importiert und Ausgabeformate erstellt."
	}
	if r.URL.Query().Get("deleted") == "1" {
		d.Notice = "Zertifikat und zugehörige Zugriffstokens entfernt."
	}
	render(w, "manual", d)
}

func manualFile(r *http.Request, name string) ([]byte, error) {
	files := r.MultipartForm.File[name]
	if len(files) == 0 {
		return nil, nil
	}
	if len(files) != 1 || files[0].Size > 2<<20 {
		return nil, errors.New(name + ": maximal 2 MiB erlaubt")
	}
	f, err := files[0].Open()
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, (2<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > 2<<20 {
		return nil, errors.New(name + ": zu groß")
	}
	return b, nil
}

func (a *App) uploadManual(w http.ResponseWriter, r *http.Request, _ session) {
	if a.manualVault == nil {
		http.Error(w, "Verschlüsselungsschlüssel nicht konfiguriert", 503)
		return
	}
	name, label := strings.TrimSpace(r.FormValue("name")), strings.TrimSpace(r.FormValue("label"))
	if !manualSafeName(name) || name == "manual" || len(label) == 0 || len(label) > 120 {
		http.Error(w, "Zertifikats-ID oder Bezeichnung ungültig", 400)
		return
	}
	if err := r.ParseMultipartForm(2 << 20); err != nil {
		http.Error(w, "Upload konnte nicht gelesen werden", 400)
		return
	}
	defer r.MultipartForm.RemoveAll()
	var cert, chain, key, root, pfx []byte
	var err error
	for _, item := range []struct {
		name string
		dst  *[]byte
	}{{"cert", &cert}, {"chain", &chain}, {"key", &key}, {"root", &root}, {"pfx", &pfx}} {
		*item.dst, err = manualFile(r, item.name)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
	}
	if len(pfx) == 0 && (len(cert) == 0 || len(key) == 0) {
		http.Error(w, "Leaf-Zertifikat und privater Schlüssel oder eine PFX/P12-Datei erforderlich", 400)
		return
	}
	if len(pfx) > 0 && (len(cert) > 0 || len(key) > 0 || len(chain) > 0 || len(root) > 0) {
		http.Error(w, "Entweder PFX/P12 oder PEM-Dateien auswählen, nicht beides", 400)
		return
	}
	var input certInput
	if len(pfx) > 0 {
		input, err = manualParsePFX(pfx, r.FormValue("pfx_password"))
	} else {
		input, err = manualParseInput(cert, chain, key, root)
	}
	if err != nil {
		http.Error(w, "Zertifikat nicht akzeptiert: "+err.Error(), 400)
		return
	}
	now := time.Now().UTC()
	rnd := make([]byte, 9)
	if _, err = rand.Read(rnd); err != nil {
		http.Error(w, "Zufallsquelle nicht verfügbar", 500)
		return
	}
	version := now.Format("20060102150405") + "-" + base64.RawURLEncoding.EncodeToString(rnd)
	// Can be re-imported under the same ID, creating a new immutable version.
	files, meta, err := manualConvert(os.TempDir(), name, version, input)
	if err != nil {
		http.Error(w, "Format-Konvertierung fehlgeschlagen: "+err.Error(), 422)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	exists := false
	for _, c := range a.state.ManualCertificates {
		if c.Name == name {
			exists = true
			break
		}
	}
	if !exists && len(a.state.ManualCertificates) >= 200 {
		http.Error(w, "Maximale Anzahl manueller Zertifikate erreicht", 409)
		return
	}
	// Publish encrypted version before exposing the version to clients.
	if err := a.manualVault.publish(name, version, files, meta); err != nil {
		http.Error(w, "Verschlüsseltes Speichern fehlgeschlagen", 500)
		return
	}
	if !exists {
		a.state.ManualCertificates = append(a.state.ManualCertificates, ManualCertificate{Name: name, Label: label, AddedAt: now})
	} else {
		for i := range a.state.ManualCertificates {
			if a.state.ManualCertificates[i].Name == name {
				a.state.ManualCertificates[i].Label = label
			}
		}
	}
	if err = a.saveLocked(); err != nil {
		http.Error(w, "Metadaten konnten nicht gespeichert werden", 500)
		return
	}
	http.Redirect(w, r, "/manual?saved=1", http.StatusSeeOther)
}

func (a *App) deleteManual(w http.ResponseWriter, r *http.Request, _ session) {
	name := r.PathValue("name")
	if !manualSafeName(name) {
		http.NotFound(w, r)
		return
	}
	a.mu.Lock()
	known := false
	kept := a.state.ManualCertificates[:0]
	for _, c := range a.state.ManualCertificates {
		if c.Name == name {
			known = true
		} else {
			kept = append(kept, c)
		}
	}
	if !known {
		a.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	a.state.ManualCertificates = kept
	pruneCertificateAssignments(&a.state, "manual:"+name)
	a.revokeScopeLocked("manual", name)
	err := a.saveLocked()
	a.mu.Unlock()
	if err != nil {
		http.Error(w, "Datenbankfehler", 500)
		return
	}
	// Revoke before deleting encrypted historical versions. If cleanup fails,
	// revoked access is still enforced by the catalog.
	if a.manualVault != nil {
		if err := os.RemoveAll(a.manualVault.root(name)); err != nil {
			log.Printf("WARN: Vault-Bereinigung für %s: %v", name, err)
		}
	}
	http.Redirect(w, r, "/manual?deleted=1", http.StatusSeeOther)
}

func (a *App) manualRegisteredLocked(name string) bool {
	for _, c := range a.state.ManualCertificates {
		if c.Name == name {
			return true
		}
	}
	return false
}

func manualIsPrivate(f artifact) bool {
	n := strings.ToLower(f.Name)
	return f.Private || strings.Contains(n, "private") || strings.HasPrefix(n, "key-") || strings.Contains(n, "password") || strings.HasSuffix(n, ".pfx") || strings.HasSuffix(n, ".p12") || strings.Contains(n, "pkcs8") || n == "privkey.pem" || n == "sha256sums.txt"
}
func (a *App) manualArtifactMeta(name, version, file string) (certMeta, artifact, error) {
	if a.manualVault == nil || !manualSafeName(name) || !manualSafeName(file) {
		return certMeta{}, artifact{}, os.ErrNotExist
	}
	meta, err := a.manualVault.load(name, version)
	if err != nil {
		return meta, artifact{}, err
	}
	for _, f := range meta.Artifacts {
		if f.Name == file {
			return meta, f, nil
		}
	}
	return meta, artifact{}, os.ErrNotExist
}

func (a *App) manualRead(name, version, file string) ([]byte, artifact, error) {
	meta, f, err := a.manualArtifactMeta(name, version, file)
	if err != nil {
		return nil, f, err
	}
	b, err := a.manualVault.read(name, meta.Version, file)
	if err != nil {
		return nil, f, err
	}
	if manualHashHex(b) != f.SHA256 || len(b) != f.Size {
		return nil, f, errors.New("Vault-Artefaktintegrität verletzt")
	}
	return b, f, nil
}

// Manual imports always require a private key just like the original
// UCNG converter; public formats are generated without exposing that key.
func (a *App) manualScopeAvailable(name string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.manualVault != nil && a.manualRegisteredLocked(name)
}
