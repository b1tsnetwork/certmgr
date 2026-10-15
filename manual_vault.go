// Derived from the user-provided UCNG Certificate Manager encrypted vault (AGPL-3.0).
// Original license and notices: third_party/ucng/.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type vault struct {
	dir string
	gcm cipher.AEAD
	mu  sync.RWMutex
}

func newVault(dir string, key []byte) (*vault, error) {
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	g, e := cipher.NewGCM(block)
	if e != nil {
		return nil, e
	}
	return &vault{dir: filepath.Join(dir, "certificates"), gcm: g}, os.MkdirAll(filepath.Join(dir, "certificates"), 0700)
}
func (v *vault) root(name string) string { return filepath.Join(v.dir, name) }
func (v *vault) exists(name, version string) bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	_, e := os.Stat(filepath.Join(v.root(name), version, "meta.json"))
	return e == nil
}
func (v *vault) publish(name, id string, files map[string][]byte, meta certMeta) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	dir := v.root(name)
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	if _, e := os.Stat(filepath.Join(dir, id, "meta.json")); e == nil {
		return nil
	}
	temp, e := os.MkdirTemp(dir, ".new-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(temp)
	_ = os.Chmod(temp, 0700)
	for fn, plain := range files {
		nonce := make([]byte, v.gcm.NonceSize())
		if _, e = rand.Read(nonce); e != nil {
			return e
		}
		aad := []byte(name + "/" + id + "/" + fn)
		encrypted := append(nonce, v.gcm.Seal(nil, nonce, plain, aad)...)
		if e = os.WriteFile(filepath.Join(temp, fn+".sealed"), encrypted, 0600); e != nil {
			return e
		}
	}
	b, e := json.MarshalIndent(meta, "", "  ")
	if e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(temp, "meta.json"), b, 0600); e != nil {
		return e
	}
	if e = os.Rename(temp, filepath.Join(dir, id)); e != nil {
		return e
	}
	ptr, e := os.CreateTemp(dir, ".latest-")
	if e != nil {
		return e
	}
	tempPtr := ptr.Name()
	defer os.Remove(tempPtr)
	if _, e = ptr.WriteString(id + "\n"); e != nil {
		ptr.Close()
		return e
	}
	if e = ptr.Chmod(0600); e != nil {
		ptr.Close()
		return e
	}
	if e = ptr.Close(); e != nil {
		return e
	}
	return os.Rename(tempPtr, filepath.Join(dir, "latest"))
}
func (v *vault) load(name, version string) (certMeta, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if version == "" {
		b, e := os.ReadFile(filepath.Join(v.root(name), "latest"))
		if e != nil {
			return certMeta{}, e
		}
		version = stringTrim(b)
	}
	if !manualSafeName(version) {
		return certMeta{}, errors.New("ungültige Version")
	}
	b, e := os.ReadFile(filepath.Join(v.root(name), version, "meta.json"))
	if e != nil {
		return certMeta{}, e
	}
	var m certMeta
	if e = json.Unmarshal(b, &m); e != nil {
		return certMeta{}, e
	}
	if m.Name != name || m.Version != version {
		return certMeta{}, errors.New("ungültige Metadaten")
	}
	return m, nil
}
func stringTrim(b []byte) string { return stringTrimSpace(string(b)) }
func stringTrimSpace(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r' || s[len(s)-1] == ' ') {
		s = s[:len(s)-1]
	}
	return s
}
func (v *vault) read(name, version, filename string) ([]byte, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if !manualSafeName(name) || !manualSafeName(version) || filename == "" || filepath.Base(filename) != filename {
		return nil, errors.New("ungültige Datei")
	}
	raw, e := os.ReadFile(filepath.Join(v.root(name), version, filename+".sealed"))
	if e != nil {
		return nil, e
	}
	if len(raw) < v.gcm.NonceSize() {
		return nil, errors.New("ungültiger Ciphertext")
	}
	nonce := raw[:v.gcm.NonceSize()]
	b, e := v.gcm.Open(nil, nonce, raw[v.gcm.NonceSize():], []byte(name+"/"+version+"/"+filename))
	if e != nil {
		return nil, fmt.Errorf("Datei konnte nicht entschlüsselt werden: %w", e)
	}
	return b, nil
}

func manualSafeName(s string) bool { return acmeIDPattern.MatchString(s) && s != "." && s != ".." }
