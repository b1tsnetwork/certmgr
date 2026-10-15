package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type PasswordHash struct {
	Salt       string `json:"salt"`
	Hash       string `json:"hash"`
	Iterations int    `json:"iterations"`
}

type User struct {
	ID        string       `json:"id"`
	Username  string       `json:"username"`
	Role      string       `json:"role"` // admin, editor, viewer
	Password  PasswordHash `json:"password"`
	CreatedAt time.Time    `json:"created_at"`
}

type ACMEProfile struct {
	ID                    string `json:"id"`
	Label                 string `json:"label"`
	DirectoryURL          string `json:"directory_url"`
	Email                 string `json:"email"`
	Challenge             string `json:"challenge"` // cloudflare | manual-dns-hooks | rfc2136
	CredentialsFile       string `json:"credentials_file,omitempty"`
	DNSServer             string `json:"dns_server,omitempty"`              // RFC2136 authoritative DNS server IP
	DNSPort               int    `json:"dns_port,omitempty"`                // default 53
	DNSPropagationSeconds int    `json:"dns_propagation_seconds,omitempty"` // default 60
	AuthHook              string `json:"auth_hook,omitempty"`
	CleanupHook           string `json:"cleanup_hook,omitempty"`
	CABundleFile          string `json:"ca_bundle_file,omitempty"`
	EABKidEnv             string `json:"eab_kid_env,omitempty"`
	EABHMACEnv            string `json:"eab_hmac_env,omitempty"`
}
type ACMECertificate struct {
	Name     string   `json:"name"`
	Label    string   `json:"label"`
	Profile  string   `json:"profile"`
	DNSNames []string `json:"expected_dns_names"`
	Enabled  bool     `json:"enabled"`
}

type Settings struct {
	WarningDays    int  `json:"warning_days"`
	CriticalDays   int  `json:"critical_days"`
	UseSystemRoots bool `json:"use_system_roots"`
}

type RootCA struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	PEM         string    `json:"pem"`
	AddedAt     time.Time `json:"added_at"`
	Fingerprint string    `json:"fingerprint"`
}

type CertInfo struct {
	Role               string    `json:"role"`
	Source             string    `json:"source"`
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	SANs               []string  `json:"sans,omitempty"`
	Serial             string    `json:"serial"`
	Fingerprint        string    `json:"fingerprint"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	PublicKeyAlgorithm string    `json:"public_key_algorithm"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	DaysLeft           int       `json:"days_left"`
	TimeText           string    `json:"time_text"`
	Status             string    `json:"status"`
	StatusText         string    `json:"status_text"`
	IsCA               bool      `json:"is_ca"`
}

type CheckResult struct {
	CheckedAt       time.Time  `json:"checked_at"`
	Status          string     `json:"status"`
	StatusText      string     `json:"status_text"`
	Valid           bool       `json:"valid"`
	Message         string     `json:"message"`
	TLSVersion      string     `json:"tls_version,omitempty"`
	CipherSuite     string     `json:"cipher_suite,omitempty"`
	RemoteAddress   string     `json:"remote_address,omitempty"`
	DurationMS      int64      `json:"duration_ms"`
	Chain           []CertInfo `json:"chain,omitempty"`
	Extra           []CertInfo `json:"extra,omitempty"`
	FullChain       bool       `json:"full_chain"`
	AlternateChains int        `json:"alternate_chains"`
	PeerCount       int        `json:"peer_count"`
}

// System describes an application or host using one or more certificates.
// Assignments are stored separately so one certificate can be shared by many systems.
type System struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Kind             string `json:"kind"` // server or application
	IPAddress        string `json:"ip_address,omitempty"`
	DocumentationURL string `json:"documentation_url,omitempty"`
	Description      string `json:"description,omitempty"`
}
type SystemAssignment struct {
	SystemID       string `json:"system_id"`
	CertificateRef string `json:"certificate_ref"` // target:<id>, acme:<name>, manual:<name>
}

type Target struct {
	ID              string            `json:"id"`
	Revision        int               `json:"revision"`
	Name            string            `json:"name"`
	URL             string            `json:"url"`
	SNI             string            `json:"sni,omitempty"`
	RootPolicy      string            `json:"root_policy,omitempty"`
	RootIDs         []string          `json:"root_ids,omitempty"`
	TrustSystem     *bool             `json:"trust_system,omitempty"`
	Server          string            `json:"server,omitempty"`
	Formats         string            `json:"formats,omitempty"`
	Environment     string            `json:"environment,omitempty"`
	Owner           string            `json:"owner,omitempty"`
	Notes           string            `json:"notes,omitempty"`
	Metadata        map[string]string `json:"metadata,omitempty"`
	IntervalMinutes int               `json:"interval_minutes"`
	WarningDays     *int              `json:"warning_days,omitempty"`
	CriticalDays    *int              `json:"critical_days,omitempty"`
	LastCheck       *CheckResult      `json:"last_check,omitempty"`
	ACMECert        string            `json:"acme_certificate,omitempty"`
}

// DistributionToken is a scoped, expiring bearer credential. Only the SHA-256
// hash is persisted; raw tokens are displayed once on creation.
type ManualCertificate struct {
	Name    string    `json:"name"`
	Label   string    `json:"label"`
	AddedAt time.Time `json:"added_at"`
}

type CertificateScope struct {
	Profile     string `json:"profile"`
	Certificate string `json:"certificate"`
}

// Existing v2.3/v2.4 tokens retain their legacy Profile/Certificate fields.
// New credentials use Scopes, granting only the explicitly selected lineages.
type DistributionToken struct {
	Scopes      []CertificateScope `json:"scopes,omitempty"`
	ID          string             `json:"id"`
	Label       string             `json:"label"`
	Profile     string             `json:"profile"`
	Certificate string             `json:"certificate"`
	Hash        string             `json:"hash"`
	Private     bool               `json:"private"`
	CreatedAt   time.Time          `json:"created_at"`
	ExpiresAt   time.Time          `json:"expires_at"`
}

type State struct {
	Systems            []System            `json:"systems,omitempty"`
	Assignments        []SystemAssignment  `json:"system_assignments,omitempty"`
	Version            int                 `json:"version"`
	Admin              *PasswordHash       `json:"admin,omitempty"` // legacy v1 migration only
	Users              []User              `json:"users"`
	ACMEProfiles       []ACMEProfile       `json:"acme_profiles,omitempty"`
	ACMECerts          []ACMECertificate   `json:"acme_certificates,omitempty"`
	DistributionTokens []DistributionToken `json:"distribution_tokens,omitempty"`
	ManualCertificates []ManualCertificate `json:"manual_certificates,omitempty"`
	Settings           Settings            `json:"settings"`
	Roots              []RootCA            `json:"roots"`
	Targets            []Target            `json:"targets"`
}

type session struct {
	csrf    string
	userID  string
	expires time.Time
}

type App struct {
	mu                   sync.RWMutex
	state                State
	path                 string
	running              map[string]bool
	sessions             map[string]session
	loginAttempts        map[string][]time.Time
	sem                  chan struct{}
	acmeCatalogPath      string
	acmeEnabled          bool
	acmeStatusPath       string
	handoffPath          string
	privateExportEnabled bool
	manualVault          *vault
	conversionMu         sync.Mutex
}

func newID() (string, error) {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// PBKDF2-HMAC-SHA256 implemented with standard library primitives for Go 1.23.
// Password hashes are deliberately not reversible or stored in environment after bootstrap.
func derivePassword(password string, salt []byte, rounds int) []byte {
	mac := hmac.New(sha256.New, []byte(password))
	mac.Write(salt)
	mac.Write([]byte{0, 0, 0, 1})
	u := mac.Sum(nil)
	out := append([]byte(nil), u...)
	for i := 1; i < rounds; i++ {
		mac.Reset()
		mac.Write(u)
		u = mac.Sum(nil)
		for j := range out {
			out[j] ^= u[j]
		}
	}
	return out
}

func hashPassword(password string) (PasswordHash, error) {
	if len(password) < 12 {
		return PasswordHash{}, errors.New("das Passwort muss mindestens 12 Zeichen lang sein")
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return PasswordHash{}, err
	}
	const rounds = 210000
	return PasswordHash{Salt: base64.RawStdEncoding.EncodeToString(b), Hash: base64.RawStdEncoding.EncodeToString(derivePassword(password, b, rounds)), Iterations: rounds}, nil
}

func (h PasswordHash) matches(password string) bool {
	salt, e1 := base64.RawStdEncoding.DecodeString(h.Salt)
	want, e2 := base64.RawStdEncoding.DecodeString(h.Hash)
	if e1 != nil || e2 != nil || h.Iterations < 10000 || h.Iterations > 2000000 || len(want) != sha256.Size {
		return false
	}
	return hmac.Equal(derivePassword(password, salt, h.Iterations), want)
}

func newApp(path, bootstrapPassword string) (*App, error) {
	a := &App{path: path, running: map[string]bool{}, sessions: map[string]session{}, loginAttempts: map[string][]time.Time{}, sem: make(chan struct{}, 4)}
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := json.Unmarshal(data, &a.state); err != nil {
			return nil, fmt.Errorf("Datenbankdatei unlesbar: %w", err)
		}
		if a.state.Version == 1 {
			if a.state.Admin == nil {
				return nil, errors.New("v1-Datenbank ohne Admin-Hash")
			}
			id, err := newID()
			if err != nil {
				return nil, err
			}
			a.state.Users = []User{{ID: id, Username: "admin", Role: "admin", Password: *a.state.Admin, CreatedAt: time.Now()}}
			a.state.Admin = nil
			a.state.Version = 2
		}
		if a.state.Version == 2 {
			// Import legacy free-text server values into first-class systems.
			// Keep the original legacy field for downgrade/recovery, but all future edits use assignments.
			for _, target := range a.state.Targets {
				name := strings.TrimSpace(target.Server)
				if name == "" {
					continue
				}
				id := ""
				for _, sys := range a.state.Systems {
					if strings.EqualFold(sys.Name, name) && sys.Kind == "server" {
						id = sys.ID
						break
					}
				}
				if id == "" {
					var idErr error
					id, idErr = newID()
					if idErr != nil {
						return nil, idErr
					}
					a.state.Systems = append(a.state.Systems, System{ID: id, Name: name, Kind: "server"})
				}
				a.state.Assignments = append(a.state.Assignments, SystemAssignment{SystemID: id, CertificateRef: "target:" + target.ID})
			}
			a.state.Version = 3
			if err := a.saveLocked(); err != nil {
				return nil, fmt.Errorf("Inventarmigration fehlgeschlagen: %w", err)
			}
		} else if a.state.Version != 3 {
			return nil, fmt.Errorf("unbekannte Datenversion %d", a.state.Version)
		}
		if len(a.state.Users) == 0 {
			return nil, errors.New("keine Benutzer vorhanden")
		}
	case errors.Is(err, os.ErrNotExist):
		if bootstrapPassword == "" {
			return nil, errors.New("beim ersten Start ADMIN_PASSWORD (mindestens 12 Zeichen) setzen")
		}
		h, err := hashPassword(bootstrapPassword)
		if err != nil {
			return nil, err
		}
		id, err := newID()
		if err != nil {
			return nil, err
		}
		a.state = State{Version: 3, Users: []User{{ID: id, Username: "admin", Role: "admin", Password: h, CreatedAt: time.Now()}}, Settings: Settings{WarningDays: 30, CriticalDays: 14, UseSystemRoots: true}, Roots: []RootCA{}, Targets: []Target{}}
		if err := a.saveLocked(); err != nil {
			return nil, err
		}
	default:
		return nil, err
	}
	return a, nil
}

func (a *App) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(a.path), 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(a.state, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(a.path)
	f, err := os.CreateTemp(dir, ".certwatch-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if _, err = f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), a.path); err != nil {
		return err
	}
	return a.exportACMECatalogLocked()
}

func cloneState(s State) State {
	// Deep copy so template rendering and checks never race against writes.
	b, _ := json.Marshal(s)
	var out State
	_ = json.Unmarshal(b, &out)
	return out
}
func (a *App) snapshot() State {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return cloneState(a.state)
}
func findTarget(s *State, id string) *Target {
	for i := range s.Targets {
		if s.Targets[i].ID == id {
			return &s.Targets[i]
		}
	}
	return nil
}
func effectiveThresholds(t Target, s Settings) (warn, critical int) {
	warn, critical = s.WarningDays, s.CriticalDays
	if t.WarningDays != nil {
		warn = *t.WarningDays
	}
	if t.CriticalDays != nil {
		critical = *t.CriticalDays
	}
	return
}
func fingerprint(data []byte) string {
	b := sha256.Sum256(data)
	s := strings.ToUpper(hex.EncodeToString(b[:]))
	var parts []string
	for len(s) > 0 {
		parts = append(parts, s[:2])
		s = s[2:]
	}
	return strings.Join(parts, ":")
}
func readLimited(r io.Reader, n int64) ([]byte, error) { return io.ReadAll(io.LimitReader(r, n)) }

func effectiveSystemRoots(t Target, s Settings) bool {
	if t.TrustSystem != nil {
		return *t.TrustSystem
	}
	return s.UseSystemRoots
}

func selectRoots(t Target, roots []RootCA) []RootCA {
	if t.RootPolicy != "selected" {
		return roots
	}
	selected := make(map[string]bool, len(t.RootIDs))
	for _, id := range t.RootIDs {
		selected[id] = true
	}
	out := make([]RootCA, 0, len(roots))
	for _, root := range roots {
		if selected[root.ID] {
			out = append(out, root)
		}
	}
	return out
}
