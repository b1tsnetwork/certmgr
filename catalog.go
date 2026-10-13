package main

// The catalog is the CMS part of the certificate manager: certificate lineages,
// expected SANs, service inventory and per-service artifact selections.
// It intentionally never stores private key contents or DNS provider credentials.
import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type certificateDefinition struct {
	Name     string   `json:"name"`
	Label    string   `json:"label"`
	Profile  string   `json:"profile,omitempty"`
	DNSNames []string `json:"expected_dns_names"`
	Enabled  bool     `json:"enabled"`
}
type serviceRecord struct {
	ID          string    `json:"id"`
	Certificate string    `json:"certificate"`
	Name        string    `json:"name"`
	Kind        string    `json:"kind"`
	Host        string    `json:"host"`
	Environment string    `json:"environment"`
	Notes       string    `json:"notes"`
	Files       []string  `json:"files"`
	Created     time.Time `json:"created"`
	Updated     time.Time `json:"updated"`
}
type catalogData struct {
	Certificates []certificateDefinition `json:"certificates"`
	Services     []serviceRecord         `json:"services"`
	Profiles     []acmeProfile           `json:"acme_profiles,omitempty"`
}
type catalog struct {
	mu   sync.RWMutex
	path string
	data catalogData
}

type formatOption struct {
	File, Title, Group string
	Private            bool
}

// One checkbox corresponds to exactly one artifact, not a loosely defined extension.
// A service can only fetch entries it explicitly selected, plus the PFX password
// when a selected protected export requires it.
var formatOptions = []formatOption{
	{"leaf.pem", "Leaf (PEM)", "Zertifikate", false},
	{"leaf.der", "Leaf (DER) / IIS-Prüfung", "Zertifikate", false},
	{"leaf.crt", "Leaf (.crt)", "Zertifikate", false},
	{"leaf.cer", "Leaf (.cer, DER)", "Zertifikate", false},
	{"leaf-base64.cer", "Leaf (.cer, PEM)", "Zertifikate", false},
	{"fullchain.pem", "Fullchain (PEM)", "Zertifikate", false},
	{"fullchain.crt", "Fullchain (.crt)", "Zertifikate", false},
	{"chain-intermediates.pem", "Intermediate Chain (PEM)", "Zertifikate", false},
	{"fullchain-with-root.pem", "Fullchain mit Root (PEM)", "Zertifikate", false},
	{"fullchain-with-root.crt", "Fullchain mit Root (.crt)", "Zertifikate", false},
	{"ca-bundle.pem", "CA-Bundle mit Root", "Zertifikate", false},
	{"root-ca.pem", "Root CA (PEM)", "Zertifikate", false},
	{"root-ca.der", "Root CA (DER)", "Zertifikate", false},
	{"public-key.pem", "Public Key (PEM)", "Zertifikate", false},
	{"public-key.der", "Public Key (DER)", "Zertifikate", false},
	{"public.key", "Public Key (.key)", "Zertifikate", false},
	{"leaf-chain.p7b", "PKCS#7 (P7B)", "PKCS#7", false},
	{"leaf-chain.p7c", "PKCS#7 (P7C)", "PKCS#7", false},
	{"leaf-chain.pkcs7.pem", "PKCS#7 (PEM)", "PKCS#7", false},
	{"leaf-fullchain-with-root.p7b", "PKCS#7 inkl. Root (P7B)", "PKCS#7", false},
	{"leaf-fullchain-with-root.p7c", "PKCS#7 inkl. Root (P7C)", "PKCS#7", false},
	{"leaf-fullchain-with-root.pkcs7.pem", "PKCS#7 inkl. Root (PEM)", "PKCS#7", false},
	{"private-key.pem", "Privater Schlüssel (PEM)", "Private Schlüssel", true},
	{"key-leaf.pem", "Key + Leaf (PEM)", "Private Schlüssel", true},
	{"key-fullchain.pem", "Key + Fullchain (PEM)", "Private Schlüssel", true},
	{"key-fullchain-with-root.pem", "Key + Fullchain + Root (PEM)", "Private Schlüssel", true},
	{"leaf-only.pfx", "PFX nur Leaf", "PKCS#12 / PFX", true},
	{"leaf-only.p12", "P12 nur Leaf", "PKCS#12 / PFX", true},
	{"leaf-chain.pfx", "PFX mit Chain (IIS)", "PKCS#12 / PFX", true},
	{"leaf-chain.p12", "P12 mit Chain", "PKCS#12 / PFX", true},
	{"leaf-fullchain-with-root.pfx", "PFX mit Root", "PKCS#12 / PFX", true},
	{"leaf-fullchain-with-root.p12", "P12 mit Root", "PKCS#12 / PFX", true},
	{"private-key-pkcs8-encrypted.pem", "PKCS#8 verschlüsselt (PEM)", "Private Schlüssel", true},
	{"private-key-pkcs8-encrypted.der", "PKCS#8 verschlüsselt (DER)", "Private Schlüssel", true},
	{"private-key-pkcs8-UNENCRYPTED.pem", "PKCS#8 unverschlüsselt (PEM)", "Private Schlüssel", true},
	{"private-key-pkcs8-UNENCRYPTED.der", "PKCS#8 unverschlüsselt (DER)", "Private Schlüssel", true},
	{"certificate-info.txt", "Zertifikatsinformationen", "Sonstiges", false},
	{"chain-verification.txt", "Kettenprüfung", "Sonstiges", false},
	{"SHA256SUMS.txt", "SHA256-Prüfsummen", "Sonstiges", true},
}
var extraIntermediate = regexp.MustCompile(`^intermediate-(0[1-9]|[1-9][0-9])\.(pem|der)$`)

func validServiceFile(file string) bool {
	if extraIntermediate.MatchString(file) {
		return true
	}
	for _, f := range formatOptions {
		if f.File == file {
			return true
		}
	}
	return false
}
func filePrivate(name string) bool {
	if name == "pfx-password.txt" || name == "SHA256SUMS.txt" {
		return true
	}
	for _, f := range formatOptions {
		if f.File == name {
			return f.Private
		}
	}
	return false
}
func needsPassword(files []string) bool {
	for _, f := range files {
		if strings.HasSuffix(f, ".pfx") || strings.HasSuffix(f, ".p12") || strings.HasPrefix(f, "private-key-pkcs8-encrypted.") {
			return true
		}
	}
	return false
}
func normalizeFiles(files []string) ([]string, error) {
	if len(files) == 0 || len(files) > 60 {
		return nil, errors.New("Mindestens ein, maximal 60 Formate auswählen")
	}
	out := make([]string, 0, len(files))
	seen := map[string]bool{}
	for _, f := range files {
		if !validServiceFile(f) {
			return nil, fmt.Errorf("Unbekanntes Ausgabeformat %q", f)
		}
		if seen[f] {
			continue
		}
		seen[f] = true
		out = append(out, f)
	}
	sort.Strings(out)
	return out, nil
}
func validCertDefinition(v certificateDefinition) error {
	if !safeName(v.Name) || (v.Profile != "" && !safeName(v.Profile)) || len(v.Label) > 100 || len(v.DNSNames) == 0 || len(v.DNSNames) > 50 {
		return errors.New("Name, Label oder SAN-Liste ungültig")
	}
	seen := map[string]bool{}
	for _, n := range v.DNSNames {
		if !validSAN(n) || seen[n] {
			return fmt.Errorf("Ungültiger/doppelter DNS-Name %q", n)
		}
		seen[n] = true
	}
	return nil
}
func validateService(v serviceRecord) error {
	if len(strings.TrimSpace(v.Name)) == 0 || len(v.Name) > 120 || len(v.Host) > 253 || len(v.Environment) > 60 || len(v.Notes) > 1000 {
		return errors.New("Dienstdaten ungültig")
	}
	switch v.Kind {
	case "IIS", "Apache", "Nginx", "HAProxy", "Tomcat", "Other":
	default:
		return errors.New("Unbekannter Diensttyp")
	}
	if _, e := normalizeFiles(v.Files); e != nil {
		return e
	}
	return nil
}
func newCatalog(path string, seeds []certificateDefinition) (*catalog, error) {
	c := &catalog{path: path, data: catalogData{Certificates: []certificateDefinition{}, Services: []serviceRecord{}}}
	b, e := os.ReadFile(path)
	if e == nil {
		if e = json.Unmarshal(b, &c.data); e != nil {
			return nil, fmt.Errorf("catalog.json ungültig: %w", e)
		}
		profiles := map[string]bool{}
		for _, profile := range c.data.Profiles {
			if err := validACMEProfile(profile); err != nil {
				return nil, err
			}
			if profiles[profile.ID] {
				return nil, errors.New("Doppeltes ACME-Profil")
			}
			profiles[profile.ID] = true
		}
		names := map[string]bool{}
		for _, cert := range c.data.Certificates {
			if e = validCertDefinition(cert); e != nil {
				return nil, e
			}
			if cert.Profile != "" && !profiles[cert.Profile] {
				return nil, fmt.Errorf("Zertifikat %s verweist auf unbekanntes ACME-Profil %s", cert.Name, cert.Profile)
			}
			if names[cert.Name] {
				return nil, errors.New("Doppeltes Zertifikat")
			}
			names[cert.Name] = true
		}
		ids := map[string]bool{}
		for _, sv := range c.data.Services {
			if !safeName(sv.ID) || !names[sv.Certificate] || ids[sv.ID] {
				return nil, errors.New("Ungültiger Diensteintrag im Catalog")
			}
			if e = validateService(sv); e != nil {
				return nil, e
			}
			ids[sv.ID] = true
		}
	} else if !os.IsNotExist(e) {
		return nil, e
	} else {
		seenSeeds := map[string]bool{}
		for _, s := range seeds {
			if seenSeeds[s.Name] {
				return nil, fmt.Errorf("Doppelte initiale Zertifikats-Lineage %q", s.Name)
			}
			seenSeeds[s.Name] = true
			if e = validCertDefinition(s); e != nil {
				return nil, e
			}
			c.data.Certificates = append(c.data.Certificates, s)
		}
		c.data.Profiles = []acmeProfile{
			{ID: "letsencrypt", Label: "Let's Encrypt (Produktion)", DirectoryURL: "https://acme-v02.api.letsencrypt.org/directory", Challenge: "cloudflare", CredentialsFile: "/run/secrets/cloudflare.ini"},
			{ID: "letsencrypt-staging", Label: "Let's Encrypt (Staging)", DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory", Challenge: "cloudflare", CredentialsFile: "/run/secrets/cloudflare.ini"},
		}
		if e = c.saveLocked(c.data); e != nil {
			return nil, e
		}
	}
	return c, nil
}
func (c *catalog) saveLocked(d catalogData) error {
	b, e := json.MarshalIndent(d, "", "  ")
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(c.path), ".catalog-")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(0600); e != nil {
		f.Close()
		return e
	}
	if _, e = f.Write(b); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	return os.Rename(f.Name(), c.path)
}
func (c *catalog) snapshot() catalogData {
	c.mu.RLock()
	defer c.mu.RUnlock()
	d := catalogData{Certificates: make([]certificateDefinition, len(c.data.Certificates)), Services: make([]serviceRecord, len(c.data.Services)), Profiles: append([]acmeProfile(nil), c.data.Profiles...)}
	copy(d.Certificates, c.data.Certificates)
	copy(d.Services, c.data.Services)
	for i := range d.Certificates {
		d.Certificates[i].DNSNames = append([]string(nil), d.Certificates[i].DNSNames...)
	}
	for i := range d.Services {
		d.Services[i].Files = append([]string(nil), d.Services[i].Files...)
	}
	sort.Slice(d.Certificates, func(i, j int) bool { return d.Certificates[i].Name < d.Certificates[j].Name })
	sort.Slice(d.Services, func(i, j int) bool {
		if d.Services[i].Certificate == d.Services[j].Certificate {
			return d.Services[i].Name < d.Services[j].Name
		}
		return d.Services[i].Certificate < d.Services[j].Certificate
	})
	return d
}
func (c *catalog) certificate(name string) (certificateDefinition, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, v := range c.data.Certificates {
		if v.Name == name {
			v.DNSNames = append([]string(nil), v.DNSNames...)
			return v, true
		}
	}
	return certificateDefinition{}, false
}
func (c *catalog) service(id string) (serviceRecord, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, v := range c.data.Services {
		if v.ID == id {
			v.Files = append([]string(nil), v.Files...)
			return v, true
		}
	}
	return serviceRecord{}, false
}
func (c *catalog) upsertCertificate(v certificateDefinition) error {
	if e := validCertDefinition(v); e != nil {
		return e
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	d := c.snapshotWithoutLock()
	index := -1
	for i, old := range d.Certificates {
		if old.Name == v.Name {
			index = i
			break
		}
	}
	if index < 0 {
		d.Certificates = append(d.Certificates, v)
	} else {
		d.Certificates[index] = v
	}
	if v.Profile != "" && !hasProfile(d.Profiles, v.Profile) {
		return errors.New("Unbekanntes ACME-Profil")
	}
	if e := c.saveLocked(d); e != nil {
		return e
	}
	c.data = d
	return nil
}
func (c *catalog) deleteCertificate(name string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	d := c.snapshotWithoutLock()
	out := make([]certificateDefinition, 0, len(d.Certificates))
	found := false
	for _, x := range d.Certificates {
		if x.Name == name {
			found = true
		} else {
			out = append(out, x)
		}
	}
	if !found {
		return errors.New("Zertifikat nicht gefunden")
	}
	services := make([]serviceRecord, 0, len(d.Services))
	for _, s := range d.Services {
		if s.Certificate != name {
			services = append(services, s)
		}
	}
	d.Certificates = out
	d.Services = services
	if e := c.saveLocked(d); e != nil {
		return e
	}
	c.data = d
	return nil
}
func (c *catalog) upsertService(v serviceRecord) (serviceRecord, error) {
	if e := validateService(v); e != nil {
		return v, e
	}
	files, _ := normalizeFiles(v.Files)
	v.Files = files
	c.mu.Lock()
	defer c.mu.Unlock()
	d := c.snapshotWithoutLock()
	foundCert := false
	for _, def := range d.Certificates {
		if def.Name == v.Certificate {
			foundCert = true
			break
		}
	}
	if !foundCert {
		return v, errors.New("Zertifikat nicht gefunden")
	}
	index := -1
	for i, old := range d.Services {
		if old.ID == v.ID {
			index = i
			break
		}
	}
	if index >= 0 {
		if d.Services[index].Certificate != v.Certificate {
			return v, errors.New("Zertifikat des Dienstes kann nicht geändert werden")
		}
		v.Created = d.Services[index].Created
	} else {
		if v.ID != "" {
			return v, errors.New("Unbekannte Dienst-ID")
		}
		raw, e := randomToken()
		if e != nil {
			return v, e
		}
		v.ID = raw[:18]
		v.Created = time.Now().UTC()
	}
	v.Updated = time.Now().UTC()
	if index < 0 {
		d.Services = append(d.Services, v)
	} else {
		d.Services[index] = v
	}
	if e := c.saveLocked(d); e != nil {
		return v, e
	}
	c.data = d
	return v, nil
}
func (c *catalog) deleteService(id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	d := c.snapshotWithoutLock()
	out := make([]serviceRecord, 0, len(d.Services))
	found := false
	for _, sv := range d.Services {
		if sv.ID == id {
			found = true
		} else {
			out = append(out, sv)
		}
	}
	if !found {
		return errors.New("Dienst nicht gefunden")
	}
	d.Services = out
	if e := c.saveLocked(d); e != nil {
		return e
	}
	c.data = d
	return nil
}
func (c *catalog) snapshotWithoutLock() catalogData {
	d := catalogData{Certificates: append([]certificateDefinition(nil), c.data.Certificates...), Services: append([]serviceRecord(nil), c.data.Services...), Profiles: append([]acmeProfile(nil), c.data.Profiles...)}
	return d
}
