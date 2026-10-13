package main

import (
	"bytes"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
)

// Manual uploads are deliberately short-lived: the request body stays in memory,
// conversion uses the existing protected scratch directory, and the vault stores
// the resulting artifacts encrypted. Never log an uploaded private key.
const maxUploadRequest = 12 << 20
const maxUploadFile = 4 << 20

// The ordinary CSRF middleware only accepts 16 KiB URL-encoded forms. Keep an
// independent bound for multipart uploads, but require the identical admin
// session, Origin check and constant-time CSRF validation.
func (s *server) protectedUpload(next func(http.ResponseWriter, *http.Request, authSession)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ss, ok := s.auth.session(r)
		if !ok {
			http.Error(w, "Nicht angemeldet", http.StatusUnauthorized)
			return
		}
		if !checkOrigin(r) {
			http.Error(w, "Origin ungültig", http.StatusForbidden)
			return
		}
		if !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "multipart/form-data;") {
			http.Error(w, "multipart/form-data benötigt", http.StatusBadRequest)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxUploadRequest)
		// All supported uploads fit in memory; do not spill sensitive raw
		// private keys into the host's ordinary temporary-file directory.
		if err := r.ParseMultipartForm(maxUploadRequest); err != nil {
			if r.MultipartForm != nil {
				_ = r.MultipartForm.RemoveAll()
			}
			http.Error(w, "Upload ungültig oder zu groß (maximal 12 MiB)", http.StatusRequestEntityTooLarge)
			return
		}
		defer r.MultipartForm.RemoveAll()
		if subtle.ConstantTimeCompare([]byte(r.PostForm.Get("csrf")), []byte(ss.CSRF)) != 1 {
			http.Error(w, "CSRF ungültig", http.StatusForbidden)
			return
		}
		next(w, r, ss)
	}
}

func readUploadFile(header *multipart.FileHeader) ([]byte, error) {
	if header.Size == 0 || header.Size > maxUploadFile {
		return nil, errors.New("Datei leer oder größer als 4 MiB")
	}
	f, err := header.Open()
	if err != nil {
		return nil, errors.New("Datei konnte nicht geöffnet werden")
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxUploadFile+1))
	if err != nil || len(b) == 0 || len(b) > maxUploadFile {
		return nil, errors.New("Datei leer, beschädigt oder größer als 4 MiB")
	}
	return b, nil
}

func formFile(r *http.Request, field string, mandatory bool) ([]byte, error) {
	headers := r.MultipartForm.File[field]
	if len(headers) == 0 {
		if mandatory {
			return nil, fmt.Errorf("Datei %s fehlt", field)
		}
		return nil, nil
	}
	if len(headers) != 1 {
		return nil, fmt.Errorf("Nur eine Datei im Feld %s zulässig", field)
	}
	b, err := readUploadFile(headers[0])
	if err != nil {
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	return b, nil
}

// Cert files can be PEM (.pem/.crt) or DER (.der/.cer), including a PEM
// fullchain in the leaf field. Every returned value is a normalized PEM block.
func normalizeUploadedCertificates(b []byte) ([][]byte, error) {
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return nil, errors.New("leere Zertifikatsdatei")
	}
	if !bytes.HasPrefix(b, []byte("-----BEGIN")) {
		c, err := x509.ParseCertificate(b)
		if err != nil {
			return nil, errors.New("Zertifikat ist weder PEM noch DER")
		}
		return [][]byte{certPEM(c)}, nil
	}
	certs, err := decodeCerts(b)
	if err != nil || len(certs) == 0 {
		return nil, errors.New("Ungültige PEM-Zertifikatskette")
	}
	blocks := make([][]byte, 0, len(certs))
	for _, c := range certs {
		blocks = append(blocks, certPEM(c))
	}
	return blocks, nil
}

func certificateUploadInput(r *http.Request) (certInput, []byte, []byte, []byte, []byte, error) {
	var empty certInput
	leafFile, err := formFile(r, "leaf", true)
	if err != nil {
		return empty, nil, nil, nil, nil, err
	}
	key, err := formFile(r, "private_key", true)
	if err != nil {
		return empty, nil, nil, nil, nil, err
	}
	rootFile, err := formFile(r, "root", false)
	if err != nil {
		return empty, nil, nil, nil, nil, err
	}
	leafBlocks, err := normalizeUploadedCertificates(leafFile)
	if err != nil {
		return empty, nil, nil, nil, nil, fmt.Errorf("Leaf-Zertifikat: %w", err)
	}
	if len(leafBlocks) > 20 {
		return empty, nil, nil, nil, nil, errors.New("Zu viele Zertifikate im Leaf-Bundle")
	}
	leaf := leafBlocks[0]
	chainBlocks := append([][]byte{}, leafBlocks[1:]...)
	headers := r.MultipartForm.File["intermediates"]
	if len(headers) > 20 {
		return empty, nil, nil, nil, nil, errors.New("Maximal 20 Intermediate-Dateien")
	}
	for _, header := range headers {
		data, err := readUploadFile(header)
		if err != nil {
			return empty, nil, nil, nil, nil, fmt.Errorf("Intermediate: %w", err)
		}
		parts, err := normalizeUploadedCertificates(data)
		if err != nil {
			return empty, nil, nil, nil, nil, fmt.Errorf("Intermediate: %w", err)
		}
		chainBlocks = append(chainBlocks, parts...)
	}
	var root []byte
	if len(rootFile) > 0 {
		parts, err := normalizeUploadedCertificates(rootFile)
		if err != nil || len(parts) != 1 {
			return empty, nil, nil, nil, nil, errors.New("Root-CA muss genau ein PEM-/DER-Zertifikat enthalten")
		}
		root = parts[0]
	}
	if len(chainBlocks) > 20 {
		return empty, nil, nil, nil, nil, errors.New("Zertifikatskette zu lang")
	}
	// Prevent an accidentally duplicated intermediate or root from creating
	// an invalid chain. The original chain order is otherwise preserved.
	seen := map[string]bool{hashHex(leaf): true}
	var chain []byte
	for _, part := range chainBlocks {
		key := hashHex(part)
		if seen[key] || (len(root) != 0 && bytes.Equal(root, part)) {
			continue
		}
		seen[key] = true
		chain = append(chain, part...)
	}
	in, err := parseInput(leaf, chain, key, root)
	if err != nil {
		return empty, nil, nil, nil, nil, err
	}
	return in, leaf, chain, key, root, nil
}

func (s *server) uploadCertificate(w http.ResponseWriter, r *http.Request, ss authSession) {
	name := r.PathValue("name")
	def, ok := s.catalog.certificate(name)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if !def.Enabled {
		s.certificatePageStatus(w, r, ss, 400, "Das Zertifikat ist deaktiviert. Bitte zuerst aktivieren.")
		return
	}
	if def.Profile != "" {
		s.certificatePageStatus(w, r, ss, 400, "Für dieses Zertifikat ist ein ACME-Profil aktiv. Für einen manuellen Upload zuerst das Profil auf 'Manuell' ändern.")
		return
	}
	in, leaf, chain, key, root, err := certificateUploadInput(r)
	if err != nil {
		s.certificatePageStatus(w, r, ss, 400, err.Error())
		return
	}
	for _, expected := range def.DNSNames {
		matched := false
		for _, actual := range in.leaf.DNSNames {
			if strings.EqualFold(actual, expected) {
				matched = true
				break
			}
		}
		if !matched {
			s.certificatePageStatus(w, r, ss, 400, fmt.Sprintf("Das hochgeladene Zertifikat enthält den erwarteten SAN %s nicht.", expected))
			return
		}
	}
	id := hashHex(joinPEM(leaf, chain, key, root))[:24]
	s.importMu.Lock()
	defer s.importMu.Unlock()
	if !s.vault.exists(name, id) {
		files, meta, e := convert(s.cfg.scratchDir, name, id, in)
		if e != nil {
			s.certificatePageStatus(w, r, ss, 500, "Konvertierung fehlgeschlagen: "+e.Error())
			return
		}
		if e = s.vault.publish(name, id, files, meta); e != nil {
			s.certificatePageStatus(w, r, ss, 500, "Speicherung fehlgeschlagen")
			return
		}
	}
	// Protect the uploaded manual version from being overwritten by the
	// 5-minute importer still watching a historical legacy handoff directory.
	def.Source = "manual"
	if err := s.catalog.upsertCertificate(def); err != nil {
		s.certificatePageStatus(w, r, ss, 500, "Upload gespeichert, aber der Importmodus konnte nicht aktualisiert werden")
		return
	}
	s.mu.Lock()
	delete(s.status, name)
	s.mu.Unlock()
	http.Redirect(w, r, "/admin/certificates/"+name+"?uploaded=1", http.StatusSeeOther)
}
