package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type authSession struct {
	Username string
	CSRF     string
	Expires  time.Time
}
type rateLimit struct {
	Attempts int
	Until    time.Time
}
type tokenRecord struct {
	ID          string    `json:"id"`
	Label       string    `json:"label"`
	Hash        string    `json:"hash"`
	Certificate string    `json:"certificate"`
	ServiceID   string    `json:"service_id,omitempty"`
	Private     bool      `json:"private"`
	Created     time.Time `json:"created"`
	Expires     time.Time `json:"expires"`
}
type authState struct {
	mu           sync.Mutex
	path         string
	users        map[string][32]byte
	cookieSecure bool
	sessions     map[string]authSession
	attempts     map[string]rateLimit
	tokens       map[string]tokenRecord
}

func newAuthState(path, user, pass string, secure bool) (*authState, error) {
	return newAuthStateUsers(path, map[string]string{user: pass}, secure)
}
func newAuthStateUsers(path string, credentials map[string]string, secure bool) (*authState, error) {
	users := make(map[string][32]byte, len(credentials))
	for name, pass := range credentials {
		users[name] = sha256.Sum256([]byte(pass))
	}
	a := &authState{path: path, users: users, cookieSecure: secure, sessions: map[string]authSession{}, attempts: map[string]rateLimit{}, tokens: map[string]tokenRecord{}}
	b, e := os.ReadFile(path)
	if e == nil {
		var arr []tokenRecord
		if e = json.Unmarshal(b, &arr); e != nil {
			return nil, fmt.Errorf("Tokens-Datei ungültig: %w", e)
		}
		for _, t := range arr {
			a.tokens[t.ID] = t
		}
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	return a, nil
}
func (a *authState) persist() error {
	var list []tokenRecord
	for _, t := range a.tokens {
		list = append(list, t)
	}
	b, e := json.MarshalIndent(list, "", "  ")
	if e != nil {
		return e
	}
	file, e := os.CreateTemp(filepath.Dir(a.path), ".tokens-")
	if e != nil {
		return e
	}
	defer os.Remove(file.Name())
	if e = file.Chmod(0600); e != nil {
		file.Close()
		return e
	}
	if _, e = file.Write(b); e != nil {
		file.Close()
		return e
	}
	if e = file.Close(); e != nil {
		return e
	}
	return os.Rename(file.Name(), a.path)
}
func (a *authState) create(label, certificate string, priv bool, days int) (string, error) {
	if label == "" || len(label) > 100 || days < 1 || days > 365 {
		return "", errors.New("Ungültiger Name oder Gültigkeit")
	}
	raw, e := randomToken()
	if e != nil {
		return "", e
	}
	idRaw, e := randomToken()
	if e != nil {
		return "", e
	}
	now := time.Now().UTC()
	t := tokenRecord{ID: idRaw[:12], Label: label, Certificate: certificate, Hash: hashHex([]byte("ucng_" + raw)), Private: priv, Created: now, Expires: now.Add(time.Duration(days) * 24 * time.Hour)}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.tokens[t.ID] = t
	if e = a.persist(); e != nil {
		delete(a.tokens, t.ID)
		return "", e
	}
	return "ucng_" + raw, nil
}

// Service tokens are not certificate-wide tokens. Existing certificate tokens
// intentionally cannot use service endpoints (and vice versa).
func (a *authState) createService(label, serviceID, certificate string, priv bool, days int) (string, error) {
	if !safeName(serviceID) {
		return "", errors.New("Ungültiger Dienst")
	}
	if label == "" || len(label) > 100 || days < 1 || days > 365 {
		return "", errors.New("Ungültiger Name oder Gültigkeit")
	}
	raw, e := randomToken()
	if e != nil {
		return "", e
	}
	id, e := randomToken()
	if e != nil {
		return "", e
	}
	now := time.Now().UTC()
	t := tokenRecord{ID: id[:12], Label: label, Hash: hashHex([]byte("ucng_" + raw)), Certificate: certificate, ServiceID: serviceID, Private: priv, Created: now, Expires: now.Add(time.Duration(days) * 24 * time.Hour)}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.tokens[t.ID] = t
	if e = a.persist(); e != nil {
		delete(a.tokens, t.ID)
		return "", e
	}
	return "ucng_" + raw, nil
}
func (a *authState) bearerServiceAllowed(r *http.Request, serviceID, certificate string, private bool) bool {
	return a.bearerMatches(r, func(t tokenRecord) bool {
		return t.ServiceID == serviceID && t.Certificate == certificate && (!private || t.Private)
	})
}

// Revoke tokens before removing a service/certificate, to prevent old tokens from
// becoming effective if the same certificate lineage is later recreated.
func (a *authState) revokeScope(certName, serviceID string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	original := a.tokens
	next := make(map[string]tokenRecord, len(original))
	for id, t := range original {
		if serviceID != "" && t.ServiceID == serviceID {
			continue
		}
		if certName != "" && (t.Certificate == certName || (t.ServiceID != "" && t.Certificate == certName)) {
			continue
		}
		next[id] = t
	}
	a.tokens = next
	if e := a.persist(); e != nil {
		a.tokens = original
		return e
	}
	return nil
}
func (a *authState) revoke(id string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	old, ok := a.tokens[id]
	if !ok {
		return errors.New("Token nicht gefunden")
	}
	delete(a.tokens, id)
	if e := a.persist(); e != nil {
		a.tokens[id] = old
		return e
	}
	return nil
}
func (a *authState) list() []tokenRecord {
	a.mu.Lock()
	defer a.mu.Unlock()
	items := make([]tokenRecord, 0, len(a.tokens))
	for _, t := range a.tokens {
		items = append(items, t)
	}
	return items
}
func (a *authState) bearerAllowed(r *http.Request, certificate string, secret bool) bool {
	return a.bearerMatches(r, func(t tokenRecord) bool {
		return t.ServiceID == "" && (t.Certificate == certificate || t.Certificate == "*") && (!secret || t.Private)
	})
}
func (a *authState) bearerMatches(r *http.Request, permitted func(tokenRecord) bool) bool {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ucng_") || len(h) > 256 {
		return false
	}
	raw := strings.TrimPrefix(h, "Bearer ")
	if strings.ContainsAny(raw, " \t\n\r") {
		return false
	}
	digest := hashHex([]byte(raw))
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, t := range a.tokens {
		if !permitted(t) || time.Now().After(t.Expires) {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(t.Hash), []byte(digest)) == 1 {
			return true
		}
	}
	return false
}
func (a *authState) session(r *http.Request) (authSession, bool) {
	cookie, e := r.Cookie("ucngcert_session")
	if e != nil {
		return authSession{}, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.sessions[hashHex([]byte(cookie.Value))]
	return s, ok && time.Now().Before(s.Expires)
}
func (a *authState) setCookie(w http.ResponseWriter, r *http.Request, value string, age int) {
	http.SetCookie(w, &http.Cookie{Name: "ucngcert_session", Value: value, Path: "/admin", HttpOnly: true, Secure: a.cookieSecure || r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: age})
}
func (s *server) protected(next func(http.ResponseWriter, *http.Request, authSession)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ss, ok := s.auth.session(r)
		if !ok {
			http.Error(w, "Nicht angemeldet", 401)
			return
		}
		if r.Method == "POST" {
			if !checkOrigin(r) {
				http.Error(w, "Origin ungültig", 403)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
			if e := r.ParseForm(); e != nil {
				http.Error(w, "Formular ungültig", 400)
				return
			}
			if subtle.ConstantTimeCompare([]byte(r.PostForm.Get("csrf")), []byte(ss.CSRF)) != 1 {
				http.Error(w, "CSRF ungültig", 403)
				return
			}
		}
		next(w, r, ss)
	}
}
func clientIP(r *http.Request) string {
	h, _, e := net.SplitHostPort(r.RemoteAddr)
	if e != nil {
		return r.RemoteAddr
	}
	return h
}
func checkOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, e := url.Parse(origin)
	if e != nil || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && u.Scheme != "http") {
		return false
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	req, e := url.Parse(scheme + "://" + r.Host)
	if e != nil || req.Hostname() == "" {
		return false
	}
	uh := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	rh := strings.TrimSuffix(strings.ToLower(req.Hostname()), ".")
	sameHost := uh == rh || (isLoopback(uh) && isLoopback(rh))
	if sameHost && u.Scheme == scheme && port(u) == port(req) {
		return true
	}
	return r.TLS == nil && uh == rh && u.Scheme == "https" && port(u) == 443 && req.Port() == ""
}
func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
func port(u *url.URL) int {
	if u.Port() != "" {
		p, e := strconv.Atoi(u.Port())
		if e != nil || p < 1 || p > 65535 {
			return -1
		}
		return p
	}
	if u.Scheme == "https" {
		return 443
	}
	return 80
}
func (s *server) login(w http.ResponseWriter, r *http.Request) {
	if !checkOrigin(r) {
		http.Error(w, "Origin ungültig", 403)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	if e := r.ParseForm(); e != nil {
		http.Error(w, "Formular ungültig", 400)
		return
	}
	ip := clientIP(r)
	s.auth.mu.Lock()
	attempts := s.auth.attempts[ip]
	if time.Now().After(attempts.Until) {
		attempts = rateLimit{}
	}
	limited := attempts.Attempts >= 6
	s.auth.mu.Unlock()
	if limited {
		s.template(w, 429, "login.html", viewData{Title: "UCNG Cert Manager", AdminUser: s.cfg.adminUser, Error: "Zu viele Anmeldeversuche. Bitte 15 Minuten warten."})
		return
	}
	username := r.PostForm.Get("username")
	pwHash := sha256.Sum256([]byte(r.PostForm.Get("password")))
	// Work against the configured users; never return different login errors.
	expectedPW, found := s.auth.users[username]
	if !found || subtle.ConstantTimeCompare(pwHash[:], expectedPW[:]) != 1 {
		s.auth.mu.Lock()
		s.auth.attempts[ip] = rateLimit{Attempts: attempts.Attempts + 1, Until: time.Now().Add(15 * time.Minute)}
		s.auth.mu.Unlock()
		s.template(w, 401, "login.html", viewData{Title: "UCNG Cert Manager", AdminUser: s.cfg.adminUser, Error: "Login fehlgeschlagen."})
		return
	}
	raw, e := randomToken()
	if e != nil {
		http.Error(w, "Interner Fehler", 500)
		return
	}
	csrf, e := randomToken()
	if e != nil {
		http.Error(w, "Interner Fehler", 500)
		return
	}
	s.auth.mu.Lock()
	delete(s.auth.attempts, ip)
	s.auth.sessions[hashHex([]byte(raw))] = authSession{Username: username, CSRF: csrf, Expires: time.Now().Add(12 * time.Hour)}
	s.auth.mu.Unlock()
	s.auth.setCookie(w, r, raw, 12*60*60)
	http.Redirect(w, r, "/admin", 303)
}
func (s *server) logout(w http.ResponseWriter, r *http.Request, _ authSession) {
	c, e := r.Cookie("ucngcert_session")
	if e == nil {
		s.auth.mu.Lock()
		delete(s.auth.sessions, hashHex([]byte(c.Value)))
		s.auth.mu.Unlock()
	}
	s.auth.setCookie(w, r, "", -1)
	http.Redirect(w, r, "/admin/login", 303)
}
