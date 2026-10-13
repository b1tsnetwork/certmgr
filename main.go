package main

import (
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

//go:embed templates/*.html static/*
var assets embed.FS

type config struct {
	addr, dataDir, sourceDir, rootsDir, scratchDir, adminUser, adminPassword string
	cookieSecure                                                             bool
	masterKey                                                                []byte
	users                                                                    map[string]string
	names                                                                    []string
	expectedSAN                                                              map[string][]string
	interval                                                                 time.Duration
}

type server struct {
	cfg       config
	vault     *vault
	catalog   *catalog
	auth      *authState
	templates *template.Template
	mu        sync.RWMutex
	status    map[string]string
}

type viewData struct {
	Title           string
	CSRF            string
	Error           string
	Notice          string
	Token           string
	Certificates    []certificateView
	Certificate     certificateView
	Service         serviceView
	Tokens          []tokenView
	Services        []serviceView
	FormatOptions   []formatOption
	FormatGroups    []formatGroup
	AdminUser       string
	Profiles        []acmeProfile
	Profile         acmeProfile
	PublicArtifacts []artifact
}
type certificateView struct {
	Label               string
	Enabled             bool
	ExpectedSAN         string
	ServiceCount        int
	Name                string
	Profile             string
	Version             string
	Fingerprint         string
	NotBefore, NotAfter string
	DNSNames            string
	Updated             string
	Error               string
}
type tokenView struct{ ID, Label, Certificate, Access, Expires, Created string }
type serviceView struct {
	serviceRecord
	Selected  map[string]bool
	Private   bool
	Available []string
	Missing   []string
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}
	s, err := newServer(cfg)
	if err != nil {
		log.Fatal(err)
	}
	s.syncAll()
	go s.poll()
	httpServer := &http.Server{Addr: cfg.addr, Handler: s.routes(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 90 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	log.Printf("UCNG Certificate Manager auf %s – %d Zertifikat(e) konfiguriert", cfg.addr, len(s.catalog.snapshot().Certificates))
	log.Fatal(httpServer.ListenAndServe())
}

func loadConfig() (config, error) {
	c := config{addr: env("LISTEN_ADDR", "127.0.0.1:8080"), dataDir: env("DATA_DIR", "./data"), sourceDir: env("CERT_SOURCE_DIR", "./handoff"), rootsDir: env("ROOT_CA_DIR", "./roots"), scratchDir: env("SCRATCH_DIR", os.TempDir()), adminUser: env("ADMIN_USER", "admin"), adminPassword: os.Getenv("ADMIN_PASSWORD"), cookieSecure: os.Getenv("COOKIE_SECURE") == "true", interval: 5 * time.Minute}
	if pwFile := os.Getenv("ADMIN_PASSWORD_FILE"); pwFile != "" {
		b, err := os.ReadFile(pwFile)
		if err != nil {
			return c, fmt.Errorf("ADMIN_PASSWORD_FILE: %w", err)
		}
		c.adminPassword = strings.TrimRight(string(b), "\r\n")
	}
	// USERS_JSON is easiest for more than one operator. Legacy ADMIN_USER/PASSWORD
	// is still accepted for existing installations. No on-disk user database.
	if raw := os.Getenv("USERS_JSON"); raw != "" {
		if err := json.Unmarshal([]byte(raw), &c.users); err != nil {
			return c, fmt.Errorf("USERS_JSON ist kein gültiges JSON-Objekt: %w", err)
		}
	} else {
		c.users = map[string]string{c.adminUser: c.adminPassword}
	}
	if len(c.users) == 0 || len(c.users) > 100 {
		return c, errors.New("USERS_JSON muss 1 bis 100 Benutzer enthalten")
	}
	for name, pass := range c.users {
		if !safeName(name) || len(name) > 64 || len(pass) < 12 {
			return c, fmt.Errorf("Benutzer %q: ungültiger Name oder Passwort kürzer als 12 Zeichen", name)
		}
	}
	// One plain APP_SECRET in .env replaces a separate master-key file. The
	// KDF context prevents the app secret being used as raw AES material.
	// MASTER_KEY and MASTER_KEY_FILE remain for encrypted v2 data migration.
	if raw := os.Getenv("MASTER_KEY"); raw != "" {
		key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw))
		if err != nil || len(key) != 32 {
			return c, errors.New("MASTER_KEY muss ein base64-kodierter 32-Byte-Key sein")
		}
		c.masterKey = key
	} else if keyFile := os.Getenv("MASTER_KEY_FILE"); keyFile != "" {
		contents, err := os.ReadFile(keyFile)
		if err != nil {
			return c, fmt.Errorf("MASTER_KEY_FILE: %w", err)
		}
		key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(contents)))
		if err != nil || len(key) != 32 {
			return c, errors.New("MASTER_KEY_FILE ungültig")
		}
		c.masterKey = key
	} else {
		secret := os.Getenv("APP_SECRET")
		if len(secret) < 32 {
			return c, errors.New("APP_SECRET fehlt oder ist kürzer als 32 Zeichen (in .env setzen)")
		}
		h := sha256.Sum256([]byte("ucng-certmanager-v3/vault-key\x00" + secret))
		c.masterKey = h[:]
	}
	for _, n := range strings.Split(os.Getenv("CERT_NAMES"), ",") {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		if !safeName(n) {
			return c, fmt.Errorf("ungültiger CERT_NAMES-Eintrag %q", n)
		}
		c.names = append(c.names, n)
	}

	c.expectedSAN = map[string][]string{}
	for _, mapping := range strings.Split(os.Getenv("CERT_SAN_RULES"), ";") {
		mapping = strings.TrimSpace(mapping)
		if mapping == "" {
			continue
		}
		parts := strings.SplitN(mapping, ":", 2)
		if len(parts) != 2 || !safeName(parts[0]) || !containsName(c.names, parts[0]) || c.expectedSAN[parts[0]] != nil {
			return c, fmt.Errorf("ungültige oder doppelte CERT_SAN_RULES-Zuordnung %q", mapping)
		}
		for _, domain := range strings.Split(parts[1], ",") {
			domain = strings.TrimSpace(strings.ToLower(domain))
			if !validSAN(domain) {
				return c, fmt.Errorf("ungültiger SAN-Name %q", domain)
			}
			c.expectedSAN[parts[0]] = append(c.expectedSAN[parts[0]], domain)
		}
	}
	for _, n := range c.names {
		if len(c.expectedSAN[n]) == 0 {
			return c, fmt.Errorf("CERT_SAN_RULES: für %s müssen erwartete DNS-Namen konfiguriert werden", n)
		}
	}
	if raw := os.Getenv("POLL_INTERVAL"); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil || d < time.Minute {
			return c, errors.New("POLL_INTERVAL mindestens 1m")
		}
		c.interval = d
	}
	return c, nil
}
func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func safeName(n string) bool {
	if n == "" || len(n) > 128 || n == "." || n == ".." || strings.HasPrefix(n, ".") {
		return false
	}
	for _, r := range n {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}
func containsName(names []string, target string) bool {
	for _, n := range names {
		if n == target {
			return true
		}
	}
	return false
}
func validSAN(s string) bool {
	if len(s) < 3 || len(s) > 253 {
		return false
	}
	if strings.HasPrefix(s, "*.") {
		s = s[2:]
	}
	if strings.Contains(s, "*") {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-') {
				return false
			}
		}
	}
	return strings.Contains(s, ".")
}
func randomToken() (string, error) {
	var b [32]byte
	_, e := rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:]), e
}
func hashHex(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func newServer(cfg config) (*server, error) {
	if err := os.MkdirAll(cfg.dataDir, 0700); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cfg.scratchDir, 0700); err != nil {
		return nil, err
	}
	v, err := newVault(cfg.dataDir, cfg.masterKey)
	if err != nil {
		return nil, err
	}
	seeds := make([]certificateDefinition, 0, len(cfg.names))
	for _, n := range cfg.names {
		seeds = append(seeds, certificateDefinition{Name: n, DNSNames: cfg.expectedSAN[n], Enabled: true})
	}
	registry, err := newCatalog(filepath.Join(cfg.dataDir, "catalog.json"), seeds)
	if err != nil {
		return nil, err
	}
	users := cfg.users
	if len(users) == 0 {
		users = map[string]string{cfg.adminUser: cfg.adminPassword}
	}
	a, err := newAuthStateUsers(filepath.Join(cfg.dataDir, "tokens.json"), users, cfg.cookieSecure)
	if err != nil {
		return nil, err
	}
	tpl, err := template.New("pages").Funcs(template.FuncMap{"short": func(s string) string {
		if len(s) > 16 {
			return s[:16]
		}
		return s
	}}).ParseFS(assets, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &server{cfg: cfg, vault: v, catalog: registry, auth: a, templates: tpl, status: map[string]string{}}, nil
}
func (s *server) poll() {
	t := time.NewTicker(s.cfg.interval)
	defer t.Stop()
	for range t.C {
		s.syncAll()
	}
}
func (s *server) syncAll() {
	for _, def := range s.catalog.snapshot().Certificates {
		if !def.Enabled {
			continue
		}
		name := def.Name
		if err := s.importCertificate(name); err != nil {
			s.mu.Lock()
			s.status[name] = err.Error()
			s.mu.Unlock()
			log.Printf("Import %s: %v", name, err)
		} else {
			s.mu.Lock()
			delete(s.status, name)
			s.mu.Unlock()
		}
	}
}
func (s *server) importCertificate(name string) error {
	def, ok := s.catalog.certificate(name)
	if !ok || !def.Enabled {
		return errors.New("Zertifikat nicht registriert oder deaktiviert")
	}
	src := filepath.Join(s.cfg.sourceDir, name, "current")
	// Profile-separated handoff. Legacy flat handoff remains only for
	// certificates without an assigned ACME profile.
	if def.Profile != "" {
		src = filepath.Join(s.cfg.sourceDir, def.Profile, name, "current")
	}
	// Alternativ akzeptieren wir ein direktes Certbot-Live-Verzeichnis.
	if _, err := os.Stat(src); os.IsNotExist(err) {
		if def.Profile == "" {
			src = filepath.Join(s.cfg.sourceDir, name)
		}
	}
	// Bei atomar umgeschaltetem "current"-Symlink wird die Version nur einmal aufgelöst.
	// Damit können während einer Renewal keine Zertifikatsteile aus zwei Releases gemischt werden.
	resolved, err := filepath.EvalSymlinks(src)
	if err != nil {
		return fmt.Errorf("Zertifikatsquelle nicht erreichbar: %w", err)
	}
	src = resolved
	cert, err := os.ReadFile(filepath.Join(src, "cert.pem"))
	if err != nil {
		return fmt.Errorf("cert.pem nicht lesbar: %w", err)
	}
	chain, err := os.ReadFile(filepath.Join(src, "chain.pem"))
	if err != nil {
		return fmt.Errorf("chain.pem nicht lesbar: %w", err)
	}
	key, err := os.ReadFile(filepath.Join(src, "privkey.pem"))
	if err != nil {
		return fmt.Errorf("privkey.pem nicht lesbar: %w", err)
	}
	var root []byte
	if b, err := os.ReadFile(filepath.Join(s.cfg.rootsDir, name+".pem")); err == nil {
		root = b
	} else if !os.IsNotExist(err) {
		return err
	}
	inputs, err := parseInput(cert, chain, key, root)
	if err != nil {
		return err
	}
	for _, expected := range def.DNSNames {
		match := false
		for _, actual := range inputs.leaf.DNSNames {
			if strings.EqualFold(actual, expected) {
				match = true
				break
			}
		}
		if !match {
			return fmt.Errorf("Zertifikat %s hat nicht den erwarteten SAN %s", name, expected)
		}
	}
	id := hashHex(append(append(append(append([]byte{}, cert...), chain...), key...), root...))[:24]
	if s.vault.exists(name, id) {
		return nil
	}
	files, meta, err := convert(s.cfg.scratchDir, name, id, inputs)
	if err != nil {
		return err
	}
	if err := s.vault.publish(name, id, files, meta); err != nil {
		return err
	}
	log.Printf("Zertifikat %s aktualisiert: Version %s, gültig bis %s", name, id, meta.NotAfter.Format(time.RFC3339))
	return nil
}
func (s *server) configured(n string) bool { v, ok := s.catalog.certificate(n); return ok && v.Enabled }
func (s *server) template(w http.ResponseWriter, status int, name string, d viewData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := s.templates.ExecuteTemplate(w, name, d); err != nil {
		log.Printf("Template %s: %v", name, err)
	}
}
