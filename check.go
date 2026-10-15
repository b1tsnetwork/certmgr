package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"
)

func parseTargetURL(raw string) (normalized, hostname, address string, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", "", errors.New("URL fehlt")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", "", fmt.Errorf("URL nicht lesbar: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "tls" {
		return "", "", "", errors.New("nur https:// und tls:// werden unterstützt")
	}
	if u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return "", "", "", errors.New("URL benötigt einen Host ohne Benutzerinformationen oder Fragment")
	}
	if u.Port() != "" {
		// Validation ensures that ports such as 65536 never reach the dialer.
		p := u.Port()
		var port int
		if _, err := fmt.Sscanf(p, "%d", &port); err != nil || port < 1 || port > 65535 || fmt.Sprint(port) != p {
			return "", "", "", errors.New("Port muss zwischen 1 und 65535 liegen")
		}
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	if u.Scheme == "tls" && (u.Path != "" && u.Path != "/" || u.RawQuery != "") {
		return "", "", "", errors.New("tls:// darf keinen Pfad oder Query enthalten")
	}
	return u.String(), u.Hostname(), net.JoinHostPort(u.Hostname(), port), nil
}

func parseRootPEM(data string) ([]*x509.Certificate, error) {
	remaining := []byte(strings.TrimSpace(data))
	if len(remaining) == 0 {
		return nil, errors.New("PEM-Inhalt fehlt")
	}
	var certs []*x509.Certificate
	for len(remaining) != 0 {
		block, rest := pem.Decode(remaining)
		if block == nil {
			return nil, errors.New("ungültiger PEM-Block oder fremde Daten in der Datei")
		}
		if block.Type != "CERTIFICATE" {
			return nil, errors.New("nur PEM-Blöcke vom Typ CERTIFICATE zulässig, keine privaten Schlüssel")
		}
		if len(block.Headers) > 0 {
			return nil, errors.New("PEM-Header nicht zulässig")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("Zertifikat kann nicht gelesen werden: %w", err)
		}
		if !cert.IsCA || !cert.BasicConstraintsValid || cert.CheckSignatureFrom(cert) != nil || cert.Subject.String() != cert.Issuer.String() {
			return nil, fmt.Errorf("%q ist keine selbstsignierte Stamm-CA", cert.Subject.String())
		}
		certs = append(certs, cert)
		if len(certs) > 25 {
			return nil, errors.New("maximal 25 Stammzertifikate pro Upload")
		}
		remaining = []byte(strings.TrimSpace(string(rest)))
	}
	return certs, nil
}

func rootCertificates(roots []RootCA) []*x509.Certificate {
	var out []*x509.Certificate
	for _, root := range roots {
		certs, err := parseRootPEM(root.PEM)
		if err == nil {
			out = append(out, certs...)
		}
	}
	return out
}

func statusForCertificate(cert *x509.Certificate, now time.Time, warn, critical int) (status, label string, daysLeft int, remaining string) {
	until := cert.NotAfter.Sub(now)
	daysLeft = int(math.Floor(until.Hours() / 24))
	switch {
	case now.Before(cert.NotBefore):
		return "red", "Noch nicht gültig", daysLeft, "noch nicht gültig"
	case !now.Before(cert.NotAfter):
		return "red", "Abgelaufen", daysLeft, "abgelaufen"
	case until <= time.Duration(critical)*24*time.Hour:
		if until < 24*time.Hour {
			remaining = "weniger als 1 Tag"
		} else {
			remaining = fmt.Sprintf("%d Tage", daysLeft)
		}
		return "red", "Läuft kritisch bald ab", daysLeft, remaining
	case until <= time.Duration(warn)*24*time.Hour:
		if until < 24*time.Hour {
			remaining = "weniger als 1 Tag"
		} else {
			remaining = fmt.Sprintf("%d Tage", daysLeft)
		}
		return "yellow", "Läuft bald ab", daysLeft, remaining
	default:
		return "green", "Gültigkeitsdauer OK", daysLeft, fmt.Sprintf("%d Tage", daysLeft)
	}
}

func certName(cert *x509.Certificate) string {
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}
	return cert.Subject.String()
}

func getCertInfo(cert *x509.Certificate, role, source string, now time.Time, warn, critical int) CertInfo {
	s, label, days, remaining := statusForCertificate(cert, now, warn, critical)
	fp := sha256.Sum256(cert.Raw)
	sans := append([]string(nil), cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}
	return CertInfo{
		Role: role, Source: source, Subject: certName(cert), Issuer: cert.Issuer.String(),
		SANs: sans, Serial: strings.ToUpper(cert.SerialNumber.Text(16)),
		Fingerprint:        strings.ToUpper(hex.EncodeToString(fp[:])),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(), PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		NotBefore: cert.NotBefore, NotAfter: cert.NotAfter, DaysLeft: days, TimeText: remaining,
		Status: s, StatusText: label, IsCA: cert.IsCA,
	}
}

func hasCert(chain []*x509.Certificate, cert *x509.Certificate) bool {
	for _, v := range chain {
		if string(v.Raw) == string(cert.Raw) {
			return true
		}
	}
	return false
}

// If validation fails, construct the observable chain using actual certificate
// signatures. Never pretend that a missing intermediate or root was verified.
func observableChain(peer, localRoots []*x509.Certificate) []*x509.Certificate {
	if len(peer) == 0 {
		return nil
	}
	chain := []*x509.Certificate{peer[0]}
	for len(chain) < 20 {
		current := chain[len(chain)-1]
		if current.Subject.String() == current.Issuer.String() && current.CheckSignatureFrom(current) == nil {
			break
		}
		var next *x509.Certificate
		for _, candidate := range peer[1:] {
			if hasCert(chain, candidate) {
				continue
			}
			if current.Issuer.String() == candidate.Subject.String() && current.CheckSignatureFrom(candidate) == nil {
				next = candidate
				break
			}
		}
		if next == nil {
			for _, candidate := range localRoots {
				if hasCert(chain, candidate) {
					continue
				}
				if current.Issuer.String() == candidate.Subject.String() && current.CheckSignatureFrom(candidate) == nil {
					next = candidate
					break
				}
			}
		}
		if next == nil {
			break
		}
		chain = append(chain, next)
	}
	return chain
}

func readableVerifyError(err error) string {
	var unknown x509.UnknownAuthorityError
	var name x509.HostnameError
	var invalid x509.CertificateInvalidError
	var system x509.SystemRootsError
	switch {
	case errors.As(err, &unknown):
		return "Zertifikatskette nicht vertrauenswürdig: Stamm-CA unbekannt oder Intermediate fehlt. (" + err.Error() + ")"
	case errors.As(err, &name):
		return "Hostname passt nicht zum Serverzertifikat: " + err.Error()
	case errors.As(err, &invalid):
		return "Ungültiges Zertifikat in der Kette: " + err.Error()
	case errors.As(err, &system):
		return "System-Stammzertifikate können nicht geladen werden: " + err.Error()
	default:
		return "Zertifikatsvalidierung fehlgeschlagen: " + err.Error()
	}
}

func checkTarget(ctx context.Context, target Target, settings Settings, trustedRoots []RootCA) CheckResult {
	start := time.Now()
	result := CheckResult{CheckedAt: start.UTC(), Status: "red", StatusText: "Fehler", Message: "Prüfung konnte nicht durchgeführt werden"}
	normalized, host, addr, err := parseTargetURL(target.URL)
	_ = normalized
	if err != nil {
		result.Message = err.Error()
		return result
	}
	warn, critical := effectiveThresholds(target, settings)
	if warn < critical || critical < 0 {
		result.Message = "Schwellwerte sind ungültig"
		return result
	}
	sni := host
	if target.SNI != "" {
		sni = target.SNI
	}
	// The handshake only COLLECTS peer certificates, with validation performed
	// explicitly below using x509.Verify, including the requested trust store.
	// No HTTP request is ever sent to the endpoint.
	dialer := tls.Dialer{Config: &tls.Config{ServerName: sni, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, NetDialer: &net.Dialer{Timeout: 8 * time.Second}}
	deadlineCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	rawConn, err := dialer.DialContext(deadlineCtx, "tcp", addr)
	if err != nil {
		result.Message = "TLS-Verbindung fehlgeschlagen: " + err.Error()
		result.DurationMS = time.Since(start).Milliseconds()
		return result
	}
	conn, ok := rawConn.(*tls.Conn)
	if !ok {
		rawConn.Close()
		result.Message = "TLS-Verbindung nicht verfügbar"
		result.DurationMS = time.Since(start).Milliseconds()
		return result
	}
	state := conn.ConnectionState()
	result.RemoteAddress = conn.RemoteAddr().String()
	conn.Close()
	result.TLSVersion = tlsVersion(state.Version)
	result.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	result.PeerCount = len(state.PeerCertificates)
	if len(state.PeerCertificates) == 0 {
		result.Message = "Server hat keine Zertifikate übermittelt"
		result.DurationMS = time.Since(start).Milliseconds()
		return result
	}

	roots := x509.NewCertPool()
	if effectiveSystemRoots(target, settings) {
		roots, err = x509.SystemCertPool()
		if err != nil {
			result.Message = "System-Vertrauensspeicher nicht lesbar: " + err.Error()
			result.DurationMS = time.Since(start).Milliseconds()
			return result
		}
	}
	localRoots := rootCertificates(trustedRoots)
	for _, r := range localRoots {
		roots.AddCert(r)
	}
	intermediatePool := x509.NewCertPool()
	for _, r := range state.PeerCertificates[1:] {
		intermediatePool.AddCert(r)
	}
	chains, validationErr := state.PeerCertificates[0].Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediatePool, DNSName: sni, CurrentTime: start,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	var chain []*x509.Certificate
	if validationErr == nil {
		// Select a valid path with the healthiest expiration outlook, to avoid
		// false alarms if more than one independent valid trust path exists.
		sort.SliceStable(chains, func(i, j int) bool {
			return chainWorst(chains[i], start, warn, critical) > chainWorst(chains[j], start, warn, critical)
		})
		chain = chains[0]
		result.AlternateChains = len(chains) - 1
		result.Valid = true
		result.Status = "green"
		result.StatusText = "Gültig"
		result.Message = "TLS-Zertifikatskette und Hostname erfolgreich geprüft"
	} else {
		chain = observableChain(state.PeerCertificates, localRoots)
		result.Message = readableVerifyError(validationErr)
		result.StatusText = "Validierung fehlgeschlagen"
	}
	result.FullChain = len(chain) > 0 && chain[len(chain)-1].IsCA && chain[len(chain)-1].CheckSignatureFrom(chain[len(chain)-1]) == nil
	for i, c := range chain {
		role := "Intermediate"
		if i == 0 {
			role = "Serverzertifikat"
		} else if i == len(chain)-1 && (result.Valid || result.FullChain) {
			role = "Stammzertifikat"
		}
		source := "Vom Server gesendet"
		if !hasCert(state.PeerCertificates, c) {
			source = "Vertrauensspeicher"
		}
		ci := getCertInfo(c, role, source, start, warn, critical)
		result.Chain = append(result.Chain, ci)
		if result.Valid && ci.Status == "red" {
			result.Status, result.StatusText = "red", "Kritischer Ablauf"
			result.Message = "Vertrauenswürdige Kette, aber mindestens ein Zertifikat läuft kritisch bald ab"
		} else if result.Valid && ci.Status == "yellow" && result.Status == "green" {
			result.Status, result.StatusText = "yellow", "Ablaufwarnung"
			result.Message = "Vertrauenswürdige Kette, aber mindestens ein Zertifikat läuft bald ab"
		}
	}
	for _, c := range state.PeerCertificates {
		if !hasCert(chain, c) {
			result.Extra = append(result.Extra, getCertInfo(c, "Zusätzlich gesendet (nicht im geprüften Pfad)", "Vom Server gesendet", start, warn, critical))
		}
	}
	result.DurationMS = time.Since(start).Milliseconds()
	return result
}

func chainWorst(chain []*x509.Certificate, now time.Time, warn, critical int) int {
	worst := 2
	for _, cert := range chain {
		s, _, _, _ := statusForCertificate(cert, now, warn, critical)
		switch s {
		case "red":
			worst = 0
		case "yellow":
			if worst > 1 {
				worst = 1
			}
		}
	}
	return worst
}

func tlsVersion(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%x", v)
	}
}
